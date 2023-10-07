/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Rivos Inc.
 */

.text
.global test_uleb
test_uleb:
	ld	a0, second
	addi	a0, a0, -127
	ret
.data
first:
	.rept 127
	.byte 0
	.endr
second:
	.reloc second, R_RISCV_SET_ULEB128, second
	.reloc second, R_RISCV_SUB_ULEB128, first
	.dword 0
