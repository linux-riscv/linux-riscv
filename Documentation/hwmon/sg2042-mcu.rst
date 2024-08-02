.. SPDX-License-Identifier: GPL-2.0

Kernel driver sg2042-mcu
=====================

Supported chips:

  * Onboard MCU for sg2042

    Addresses scanned: -

    Prefix: 'sg2042-mcu'

Authors:

  - Inochi Amaoto <inochiama@outlook.com>

Description
-----------

This driver supprts hardware monitoring for onboard MCU with
i2c interface.

Usage Notes
-----------

This driver does not auto-detect devices. You will have to instantiate
the devices explicitly.
Please see Documentation/i2c/instantiating-devices.rst for details.

Sysfs Attributes
----------------

================= =============================================
temp1_input       Measured temperature of SoC
temp1_crit        Critical high temperature
temp1_crit_hyst   hysteresis temperature restore from Critical
temp2_input       Measured temperature of the base board
================= =============================================
