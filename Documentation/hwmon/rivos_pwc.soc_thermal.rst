.. SPDX-License-Identifier: GPL-2.0

Kernel driver rivos_pwc.soc_thermal
===================================

Supported chips:

  * Rivos PWC SoC thermal DVSEC

Author: Clément Léger <cleger@rivosinc.com>

Description
-----------

The Rivos PWC SoC thermal DVSEC is exposed by the Rivos PWC PCI Device.

Sysfs entries
-------------

The following attributes are supported:

======================= =======	================================================
File			Perm	Description
======================= =======	================================================
temp1_input     	RO	SoC max absolute temperature
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
temp1_emergency		RO	SoC Max Tj
temp1_emergency_alarm	RO	PH_S bit which reflect the fact the SoC was
				above Tjmax for a sustained period of time.
temp1_shutdown		RO	SoC shutdown temperature (t_sd)
temp1_label		RO	String "soc_max"
======================= =======	================================================
