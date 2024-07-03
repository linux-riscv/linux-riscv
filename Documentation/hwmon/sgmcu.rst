.. SPDX-License-Identifier: GPL-2.0

Kernel driver sgmcu
=====================

Supported chips:

  * Onboard MCU for sg2042

    Addresses scanned: -

    Prefix: 'sgmcu'

Authors:

  - Inochi Amaoto <inochiama@outlook.com>

Description
-----------

This driver supprts hardware monitoring for onboard MCU with
PMBus interface.

Usage Notes
-----------

This driver does not auto-detect devices. You will have to instantiate
the devices explicitly.
Please see Documentation/i2c/instantiating-devices.rst for details.

Platform data support
---------------------

The driver supports standard PMBus driver platform data.

Sysfs Attributes
----------------

================= =============================================
temp1_input       Measured temperature of SoC
temp1_crit        Critical high temperature
temp1_crit_hyst   hysteresis temperature restore from Critical
temp2_input       Measured temperature of the base board
================= =============================================
