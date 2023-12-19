.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.hbm_thermal
===================================

Supported chips:

  * Rivos PWC HBM thermal DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC HBM thermal DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

=============================== =======	========================================
File				Perm	Description
=============================== =======	========================================
temp1_input			RO	HBM maximum absolute temperature
temp1_max			RW	Limit set as Thresold 1 Up value
temp1_max_hyst			RW	Limit set as T1 down threshold delta,
					should be set in millidegree absolute
					value. Delta is computed by driver.
temp1_max_alarm			RO	Report the status of the T1 alarm, ie
					stays set while temp reached T1 Up
					threshold and clears when temp falls
					below T1 down delta value
temp1_crit			RW	Limit set as Thresold 2 Up value
temp1_crit_hyst			RW	Limit set as T2 down threshold delta,
					should be set in millidegree absolute
					value. Delta is computed by driver.
temp1_crit_alarm 		RO	Report the status of the T2 alarm, ie
					stays set while temp reached T2 Up
					threshold and clears when temp falls
					below T2 down delta value
temp1_label			RO	String "hbm_max"
temp1_hi_status			RO	Bit T_HI_S content
temp1_ultra_hi_status		RO	Bit T_U_HI_S content
temp1_hi_status_log		RW	Sticky bit T_HI_L content, can be
					cleared by writing 0
temp1_ultra_hi_status_log       RW	Sticky bit T_U_HI_L content, can be
					cleared by writing 0
=============================== =======	========================================
