// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include <linux/init.h>
#include <linux/libfdt.h>

#include "pi.h"

u64 get_kaslr_seed(uintptr_t dtb_pa)
{
	int node, len;
	fdt64_t *prop;
	u64 ret;

	node = fdt_path_offset((void *)dtb_pa, "/chosen");
	if (node < 0)
		return 0;

	prop = fdt_getprop_w((void *)dtb_pa, node, "kaslr-seed", &len);
	if (!prop || len != sizeof(u64))
		return 0;

	ret = fdt64_to_cpu(*prop);
	*prop = 0;
	return ret;
}

/* Based off of fdt_stringlist_contains */
static int isa_string_contains(const char *strlist, int listlen, const char *str)
{
	int len = strlen(str);
	const char *p;

	while (listlen >= len) {
		if (strncasecmp(str, strlist, len) == 0)
			return 1;
		p = memchr(strlist, '_', listlen);
		if (!p)
			p = memchr(strlist, '\0', listlen);
		if (!p)
			return 0; /* malformed strlist.. */
		listlen -= (p - strlist) + 1;
		strlist = p + 1;
	}

	return 0;
}

/* Based off of fdt_nodename_eq_ */
static int fdt_node_name_eq(const void *fdt, int offset,
			    const char *s)
{
	int olen;
	int len = strlen(s);
	const char *p = fdt_get_name(fdt, offset, &olen);

	if (!p || olen < len)
		/* short match */
		return 0;

	if (memcmp(p, s, len) != 0)
		return 0;

	if (p[len] == '\0')
		return 1;
	else if (!memchr(s, '@', len) && (p[len] == '@'))
		return 1;
	else
		return 0;
}

/*
 * Returns true if the extension is in the isa string
 * Returns false if the extension is not found
 */
static bool get_ext_named(const void *fdt, int node, const char *name)
{
	const void *prop;
	int len;

	prop = fdt_getprop(fdt, node, "riscv,isa-base", &len);
	if (prop && isa_string_contains(prop, len, name))
		return true;

	prop = fdt_getprop(fdt, node, "riscv,isa-extensions", &len);
	if (prop && isa_string_contains(prop, len, name))
		return true;

	prop = fdt_getprop(fdt, node, "riscv,isa", &len);
	if (prop && isa_string_contains(prop, len, name))
		return true;

	return false;
}

/*
 * Returns true if the extension is in the isa string on all cpus
 * Returns false if the extension is not found
 */
bool early_isa_str(const void *fdt, const char *ext_name)
{
	int node, parent;
	bool ret = false;

	parent = fdt_path_offset(fdt, "/cpus");
	if (parent < 0)
		return false;

	fdt_for_each_subnode(node, fdt, parent) {
		if (!fdt_node_name_eq(fdt, node, "cpu"))
			continue;

		if (!get_ext_named(fdt, node, ext_name))
			return false;

		ret = true;
	}

	return ret;
}
