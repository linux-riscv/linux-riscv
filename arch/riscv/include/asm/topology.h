/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_TOPOLOGY_H
#define _ASM_RISCV_TOPOLOGY_H

#include <linux/cpumask.h>

#if defined(CONFIG_PCI) && defined(CONFIG_NUMA)

struct pci_bus;
int pcibus_to_node(struct pci_bus *bus);
#define cpumask_of_pcibus(bus)	(pcibus_to_node(bus) == -1 ?		\
				 cpu_all_mask :				\
				 cpumask_of_node(pcibus_to_node(bus)))

#endif /* defined(CONFIG_PCI) && defined(CONFIG_NUMA) */

#include <linux/arch_topology.h>

/* Replace task scheduler's default frequency-invariant accounting */
#define arch_scale_freq_tick		topology_scale_freq_tick
#define arch_set_freq_scale		topology_set_freq_scale
#define arch_scale_freq_capacity	topology_get_freq_scale
#define arch_scale_freq_invariant	topology_scale_freq_invariant

/* Replace task scheduler's default cpu-invariant accounting */
#define arch_scale_cpu_capacity	topology_get_cpu_scale

/* Enable topology flag updates */
#define arch_update_cpu_topology	topology_update_cpu_topology

#include <asm-generic/topology.h>

#endif /* _ASM_RISCV_TOPOLOGY_H */
