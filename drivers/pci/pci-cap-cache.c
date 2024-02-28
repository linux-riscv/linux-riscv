// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCI capability cache.
 *
 * Copyright (C) 2023-2024 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/sprintf.h>

#include "pci.h"

#define CAP_CACHE_NR_DEVICES 32

/*
 * Represents a single capability entry in the cache. Keyed by cap + pos,
 * i.e. the same capability may appear multiple times at different offsets (as
 * allowed by the PCIe spec). The key field is used to identify the element to
 * start looking at for resumed searches where the caller passes in a start
 * offset to the original find capability function.
 */
struct cap_cache_entry {
	struct cap_cache_entry *next;
	u32 cap;
	u16 pos;
	u16 key;
};

struct kmem_cache *cap_cache_entry_cache;

struct cap_cache {
	unsigned int routing_id;
	struct cap_cache_entry *caps;
	struct cap_cache_entry *ext_caps;
};

static struct cap_cache cap_cache[CAP_CACHE_NR_DEVICES];
static unsigned int cap_cache_size;

static int cap_cache_param_set(const char *val, const struct kernel_param *kp)
{
	struct cap_cache *cc = (struct cap_cache *)kp->arg;
	unsigned int seg, bus, slot, func;
	int ret;

	ret = sscanf(val, "%x:%x:%x.%x", &seg, &bus, &slot, &func);
	if (ret < 0)
		return ret;

	cc->routing_id = seg << 16 | PCI_DEVID(bus, PCI_DEVFN(slot, func));
	return 0;
}

static int cap_cache_param_get(char *buffer, const struct kernel_param *kp)
{
	struct cap_cache *cc = (struct cap_cache *)kp->arg;
	unsigned int seg = cc->routing_id >> 16;
	unsigned int bus = PCI_BUS_NUM(cc->routing_id);
	unsigned int slot = PCI_SLOT(cc->routing_id);
	unsigned int func = PCI_FUNC(cc->routing_id);

	return sprintf(buffer, "%04x:%02x:%02x.%x\n", seg, bus, slot, func);
}

static const struct kernel_param_ops cap_cache_kparam_ops = {
	.set = cap_cache_param_set,
	.get = cap_cache_param_get,
};

static struct kparam_array cap_cache_kparam_array = {
	.max = ARRAY_SIZE(cap_cache),
	.elemsize = sizeof(cap_cache[0]),
	.num = &cap_cache_size,
	.ops = &cap_cache_kparam_ops,
	.elem = cap_cache,
};
module_param_cb(devices, &param_array_ops, &cap_cache_kparam_array, 0400);

static void cap_cache_entry_free(struct cap_cache_entry **ptr)
{
	for (struct cap_cache_entry *e = *ptr; e;) {
		struct cap_cache_entry *next = e->next;

		kmem_cache_free(cap_cache_entry_cache, e);
		e = next;
	}
	*ptr = NULL;
}

static struct cap_cache_entry *
cap_cache_entry_append(struct cap_cache *cc, struct cap_cache_entry **ptr)
{
	*ptr = kmem_cache_zalloc(cap_cache_entry_cache, GFP_KERNEL);
	if (!*ptr) {
		pr_warn("Failed to allocate cache entry, disabling PCI capability cache for device %#x",
			cc->routing_id);
		cap_cache_entry_free(&cc->caps);
		cap_cache_entry_free(&cc->ext_caps);
		/* Disable the entry by invalidating the routing ID. */
		cc->routing_id = ~0;
	}
	return *ptr;
}

static struct cap_cache *cap_cache_find(unsigned int routing_id)
{
	for (int i = 0; i < cap_cache_size; ++i) {
		if (cap_cache[i].routing_id == routing_id)
			return &cap_cache[i];
	}

	return NULL;
}

static bool cap_cache_read_caps(struct cap_cache *cc, struct pci_bus *bus,
				unsigned int devfn)
{
	struct cap_cache_entry *cur;
	int ttl = PCI_FIND_CAP_TTL;
	int count = 0;
	u8 hdr_type;
	u16 status;
	u16 ent;
	u8 tmp;
	u8 id;

	if (cc->caps)
		return true;

	cur = cap_cache_entry_append(cc, &cc->caps);
	if (!cur)
		return false;

	pci_bus_read_config_byte(bus, devfn, PCI_HEADER_TYPE, &hdr_type);
	pci_bus_read_config_word(bus, devfn, PCI_STATUS, &status);
	if (!(status & PCI_STATUS_CAP_LIST))
		return false;

	switch (hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
		cur->key = PCI_CAPABILITY_LIST;
		break;
	case PCI_HEADER_TYPE_CARDBUS:
		cur->key = PCI_CB_CAPABILITY_LIST;
		break;
	}

	if (!cur->key)
		return false;

	pci_bus_read_config_byte(bus, devfn, cur->key, &tmp);
	cur->pos = tmp;

	while (ttl--) {
		if (cur->pos < 0x40)
			break;
		cur->pos &= ~3;
		pci_bus_read_config_word(bus, devfn, cur->pos, &ent);

		id = ent & 0xff;
		if (id == 0xff)
			break;
		cur->cap = id;
		++count;

		struct cap_cache_entry *next =
			cap_cache_entry_append(cc, &cur->next);
		if (!next)
			return false;

		next->key = cur->pos + PCI_CAP_LIST_NEXT;
		next->pos = (ent >> 8);
		cur = next;
	}

	pr_info("%04x:%02x:%02x.%x Cached %u PCI capabilities", bus->domain_nr,
		bus->number, PCI_SLOT(devfn), PCI_FUNC(devfn), count);

	return true;
}

static bool cap_cache_read_ext_caps(struct cap_cache *cc, struct pci_dev *dev)
{
	int ttl = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) / 8;
	u16 pos = PCI_CFG_SPACE_SIZE;
	struct cap_cache_entry *cur;
	u32 header = 0;
	int count = 0;

	if (cc->ext_caps)
		return true;

	cur = cap_cache_entry_append(cc, &cc->ext_caps);
	if (!cur)
		return false;

	pci_read_config_dword(dev, pos, &header);
	cur->pos = pos;
	cur->cap = PCI_EXT_CAP_ID(header);
	++count;

	while (ttl--) {
		pos = PCI_EXT_CAP_NEXT(header);
		if (pos < PCI_CFG_SPACE_SIZE)
			break;

		if (pci_read_config_dword(dev, pos, &header) !=
		    PCIBIOS_SUCCESSFUL)
			break;

		struct cap_cache_entry *next =
			cap_cache_entry_append(cc, &cur->next);
		if (!next)
			return false;

		next->pos = pos;
		next->cap = PCI_EXT_CAP_ID(header);
		next->key = cur->pos;
		cur = next;
		++count;
	}

	pr_info("%04x:%02x:%02x.%x Cached %u PCI extended capabilities",
		dev->bus->domain_nr, dev->bus->number, PCI_SLOT(dev->devfn),
		PCI_FUNC(dev->devfn), count);

	return true;
}

struct cap_cache_entry *cap_cache_lookup(struct cap_cache_entry *entry, u16 key,
					 u32 cap)
{
	while (entry && entry->key != key)
		entry = entry->next;

	while (entry && entry->cap != cap)
		entry = entry->next;

	return entry;
}

bool pci_cap_cache_lookup_cap(struct pci_bus *bus, unsigned int devfn, u8 start,
			      int cap, u8 *pos)
{
	struct cap_cache_entry *entry;
	struct cap_cache *cc;

	cc = cap_cache_find(bus->domain_nr << 16 |
			    PCI_DEVID(bus->number, devfn));
	if (!cc)
		return false;

	if (!cap_cache_read_caps(cc, bus, devfn))
		return false;

	entry = cap_cache_lookup(cc->caps, start ? start : cc->caps->key, cap);
	*pos = entry ? entry->pos : 0;

	return true;
}

bool pci_cap_cache_lookup_ext_cap(struct pci_dev *dev, u16 start, int cap,
				  u16 *pos)
{
	struct cap_cache_entry *entry;
	struct cap_cache *cc;

	cc = cap_cache_find(dev->bus->domain_nr << 16 |
			    PCI_DEVID(dev->bus->number, dev->devfn));
	if (!cc)
		return false;

	if (!cap_cache_read_ext_caps(cc, dev))
		return false;

	entry = cap_cache_lookup(cc->ext_caps, start, cap);
	*pos = entry ? entry->pos : 0;

	return true;
}

static int __init pci_cap_cache_init(void)
{
	cap_cache_entry_cache = KMEM_CACHE(cap_cache_entry, SLAB_PANIC);
	return 0;
}
pure_initcall(pci_cap_cache_init);
