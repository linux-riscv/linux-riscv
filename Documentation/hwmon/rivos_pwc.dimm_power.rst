.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.dimm_power
===================================

Supported chips:

  * Rivos PWC DIMM power DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC DIMM power DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

======================= =======	================================================
File			Perm	Description
======================= =======	================================================
power1_max		RO	DIMM TDP 
power1_label		RO	String "dimm_max"
energy[1-3]_input	RO	DIMM slots energy consumption 
energy[1-3]_label	RO	Strings "dimm0", "dimm1", "dimm2"
======================= =======	================================================
