.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.dpa_power
===================================

Supported chips:

  * Rivos PWC DPA power DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC DPA power DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

=============== =======	========================================================
File		Perm	Description
=============== =======	========================================================
temp1_input	RO	DPA energy consumption  
temp1_label	RO	String "dpa" 
=============== =======	========================================================
