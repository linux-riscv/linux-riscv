.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.chiplet_power
===================================

Supported chips:

  * Rivos PWC Chiplet power DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC Chiplet power DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

=============== =======	========================================================
File		Perm	Description
=============== =======	========================================================
temp1_input	RO	Chiplet energy consumption  
temp1_label	RO	String "chiplet" 

temp[2-9]_input	RO	Clusters energy consumption  
temp[2-9]_label	RO	String "cluster0" -> “cluster7" 
=============== =======	========================================================
