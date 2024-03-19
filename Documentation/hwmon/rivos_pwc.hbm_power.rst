.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.hbm_power
===================================

Supported chips:

  * Rivos PWC HBM power DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC HBM power DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

=============== =======	========================================================
File		Perm	Description
=============== =======	========================================================
temp1_input	RO	HBM energy consumption  
temp1_label	RO	String "dpa" 
=============== =======	========================================================
