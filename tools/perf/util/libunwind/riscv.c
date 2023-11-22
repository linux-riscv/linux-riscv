// SPDX-License-Identifier: GPL-2.0
/*
 * This file setups defines to compile arch specific binary from the
 * generic one.
 *
 * The function 'LIBUNWIND__ARCH_REG_ID' name is set according to arch
 * name and the definition of this function is included directly from
 * 'arch/riscv/util/unwind-libunwind.c', to make sure that this function
 * is defined no matter what arch the host is.
 *
 * Finally, the arch specific unwind methods are exported which will
 * be assigned to each riscv thread.
 */

#define REMOTE_UNWIND_LIBUNWIND

/* Define arch specific functions & regs for libunwind, should be
 * defined before including "unwind.h"
 */
#define LIBUNWIND__ARCH_REG_ID(regnum) libunwind__riscv_reg_id(regnum)

#include "unwind.h"
#include "libunwind-riscv.h"
#define perf_event_riscv_regs perf_event_riscv64_regs
#include <../../../arch/riscv/include/uapi/asm/perf_regs.h>
#undef perf_event_riscv_regs
#include "../../arch/riscv/util/unwind-libunwind.c"

/* NO_LIBUNWIND_DEBUG_FRAME is a feature flag for local libunwind,
 * assign NO_LIBUNWIND_DEBUG_FRAME_RISCV64 to it for compiling riscv
 * unwind methods.
 */
#undef NO_LIBUNWIND_DEBUG_FRAME
#ifdef NO_LIBUNWIND_DEBUG_FRAME_RISCV
#define NO_LIBUNWIND_DEBUG_FRAME
#endif
#include "util/unwind-libunwind-local.c"

struct unwind_libunwind_ops *
riscv_unwind_libunwind_ops = &_unwind_libunwind_ops;
