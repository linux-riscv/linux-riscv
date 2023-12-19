.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.dimm_thermal
===================================

Supported chips:

  * Rivos PWC DIMM thermal DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC DIMM thermal DVSEC is exposed by the Rivos PWC PCI Device.
Depending on the populated DIMM slots, some files might not be displayed.

Sysfs entries
-------------

The following attributes are supported:

======================= =======	================================================
File			Perm	Description
======================= =======	================================================

temp1_input		RO	DIMM maximum temperature of all slots
temp1_max		RW	Limit set as Thresold 1 Up value
temp1_max_hyst		RW	Limit set as T1 down threshold delta, should be
				set in millidegree absolute value. Delta is
				computed by driver.
temp1_max_alarm		RO	Report the status of the T1 alarm, ie stays set
				while temp reached T1 Up threshold and clears
				when temp falls below T1 down delta value
temp1_crit		RW	Limit set as Thresold 2 Up value
temp1_crit_hyst		RW	Limit set as T2 down threshold delta, should be
				set in millidegree absolute value. Delta is
				computed by driver.
temp1_crit_alarm 	RO	Report the status of the T2 alarm, ie stays set
				while temp reached T2 Up threshold and clears
				when temp falls below T2 down delta value
temp1_label		RO 	String "dimm_max"
temp1_dimm_max_slot_id	RO	Slot ID that was associated to the max
				temperature read, latched on temp1_input
				reading.

temp[2-4-6]_input	RO	DIMM Slot temperature (including PMIC/SPD)
temp[2-4-6]_label	RO	Strings "dimm0", dimm1, "dimm2"

temp[3-5-7]_input	RO	DIMM DRAM device Slot temperature (excluding
				PMIC/SPD)
temp[3-5-7]_label	RO	Strings "dimm_dram0", "dimm_dram1", "dimm_dram2"
======================= =======	================================================
