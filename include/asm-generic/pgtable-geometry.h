/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_GENERIC_PGTABLE_GEOMETRY_H
#define ASM_GENERIC_PGTABLE_GEOMETRY_H

#if   defined(PAGE_SHIFT_MAX) && defined(PAGE_SIZE_MAX) && defined(PAGE_MASK_MAX) && \
      defined(PAGE_SHIFT_MIN) && defined(PAGE_SIZE_MIN) && defined(PAGE_MASK_MIN)
/* Arch supports boot-time page size selection. */
#elif defined(PAGE_SHIFT_MAX) || defined(PAGE_SIZE_MAX) || defined(PAGE_MASK_MAX) || \
      defined(PAGE_SHIFT_MIN) || defined(PAGE_SIZE_MIN) || defined(PAGE_MASK_MIN)
#error Arch must define all or none of the boot-time page size macros
#else
/* Arch does not support boot-time page size selection. */
#define PAGE_SHIFT_MIN	PAGE_SHIFT
#define PAGE_SIZE_MIN	PAGE_SIZE
#define PAGE_MASK_MIN	PAGE_MASK
#define PAGE_SHIFT_MAX	PAGE_SHIFT
#define PAGE_SIZE_MAX	PAGE_SIZE
#define PAGE_MASK_MAX	PAGE_MASK
#endif

/*
 * Define a global variable (scalar or struct), whose value is derived from
 * PAGE_SIZE and friends. When PAGE_SIZE is a compile-time constant, the global
 * variable is simply defined with the static value. When PAGE_SIZE is
 * determined at boot-time, a pure initcall is registered and run during boot to
 * initialize the variable.
 *
 * @type: Unqualified type. Do not include "const"; implied by macro variant.
 * @name: Variable name.
 * @...:  Initialization value. May be scalar or initializer.
 *
 * "static" is declared by placing "static" before the macro.
 *
 * Example:
 *
 * struct my_struct {
 *         int a;
 *         char b;
 * };
 *
 * static DEFINE_GLOBAL_PAGE_SIZE_VAR(struct my_struct, my_variable, {
 *         .a = 10,
 *         .b = 'e',
 * });
 */
#if PAGE_SIZE_MIN != PAGE_SIZE_MAX
#define __DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, attrib, ...)		\
	type name attrib;						\
	static int __init __attribute__((constructor)) __##name##_init(void)	\
	{								\
		name = (type)__VA_ARGS__;				\
		return 0;						\
	}

#define DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, ...)			\
	__DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, , __VA_ARGS__)

#define DEFINE_GLOBAL_PAGE_SIZE_VAR_CONST(type, name, ...)		\
	__DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, __ro_after_init, __VA_ARGS__)
#else /* PAGE_SIZE_MIN == PAGE_SIZE_MAX */
#define __DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, attrib, ...)		\
	type name attrib = __VA_ARGS__;					\

#define DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, ...)			\
	__DEFINE_GLOBAL_PAGE_SIZE_VAR(type, name, , __VA_ARGS__)

#define DEFINE_GLOBAL_PAGE_SIZE_VAR_CONST(type, name, ...)		\
	__DEFINE_GLOBAL_PAGE_SIZE_VAR(const type, name, , __VA_ARGS__)
#endif

#endif /* ASM_GENERIC_PGTABLE_GEOMETRY_H */
