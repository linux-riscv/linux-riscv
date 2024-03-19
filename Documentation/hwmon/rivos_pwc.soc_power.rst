.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.soc_power
===================================

Supported chips:

  * Rivos PWC SoC power DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC SoC power DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

======================= =======	================================================
File			Perm	Description
======================= =======	================================================
curr1_max		RO	SoC ICC max
curr1_label		RO	String "soc_icc"

power1_crit		RO	SoC maximum value
power1_max		RO	SoC TDP
power1_min		RO	SoC minimum power
power1_cap_max		RO	Maximum value that can be set by the user as
				long power limit (maps to power1_min)
power1_cap_min		RO	Minimum value that can be set by the user as
				long power limit (maps to power1_max)
power1_cap		RW 	Long power limit that can be set by the user.
power1_short_cap_min	RO	Minimum short limit value that can be set
				(mapped to power1_max ie == TDP)
power1_short_cap_max	RO	Maximum short limit value that can be set
				(mapped to power1_crit)
power1_short_cap	RW	Short power limit that can be set by user
power1_label		RO	String "soc_power"

energy1_input		RO	SoC energy consumption 
energy1_label		RO	String "soc_energy"
======================= =======	================================================
