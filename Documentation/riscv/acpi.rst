.. SPDX-License-Identifier: GPL-2.0

==============
ACPI on RISC-V
==============

The ISA string parsing rules for ACPI are defined by `Version ASCIIDOC
Conversion, 12/2022 of the RISC-V specifications, as defined by tag
"riscv-isa-release-1239329-2023-05-23" (commit 1239329
) <https://github.com/riscv/riscv-isa-manual/releases/tag/riscv-isa-release-1239329-2023-05-23>`_

Interrupt Controller Drivers
=======

ACPI drivers for RISC-V interrupt controllers use software node framework to
create the fwnode for the interrupt controllers. Below properties are
additionally required for some firmware nodes apart from the properties
defined by the device tree bindings for these interrupt controllers. The
properties are created using the data in MADT table.

1) RISC-V Interrupt Controller (INTC)
-----------
``hartid`` - Hart ID of the hart this interrupt controller belongs to.

``riscv,imsic-addr`` - Physical base address of the Incoming MSI Controller
(IMSIC) MMIO region of this hart.

``riscv,imsic-size`` - Size in bytes of the IMSIC MMIO region of this hart.

``riscv,ext-intc-id`` - The unique ID of the external interrupts connected
to this hart.

2) RISC-V Advanced Platform Level Interrupt Controller (APLIC)
-----------

``riscv,gsi-base`` - The global system interrupt number where this APLIC’s
interrupt inputs start.

3) RISC-V Platform Level Interrupt Controller (PLIC)
-----------

``riscv,gsi-base`` - The global system interrupt number where this PLIC’s
interrupt inputs start.
