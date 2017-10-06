#ifndef _KSYM_H_
#define _KSYM_H_

#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <linux/kallsyms.h>

#define KSYM_TY(S)           __ksym_ ## S ## _t
#define KSYM_SYM(S)          __ksym ## S

#define KSYM_DECLARE_TYPE(S) typedef typeof(S) KSYM_TY(S)

#ifdef KSYM_TABLE
#define KSYM_DECLARE_FUNC(S) KSYM_TY(S)* KSYM_SYM(S)
#else
#define KSYM_DECLARE_FUNC(S) extern KSYM_TY(S)* KSYM_SYM(S)
#endif

#define KSYM_IMPORT(S) ((KSYM_TY(S)*) ksym_import(#S, (void**)(&KSYM_SYM(S))))
#define KSYM_INIT(S)   ksym_init(#S, (void**)(&KSYM_SYM(S)))

void* ksym_import(const char* name, void **sym);
void* ksym_init(const char* name, void **sym);

/* Supported functions. */
KSYM_DECLARE_TYPE(do_mmap_pgoff);
KSYM_DECLARE_FUNC(do_mmap_pgoff);

KSYM_DECLARE_TYPE(walk_page_range);
KSYM_DECLARE_FUNC(walk_page_range);

KSYM_DECLARE_TYPE(handle_mm_fault);
KSYM_DECLARE_FUNC(handle_mm_fault);

KSYM_DECLARE_TYPE(__get_locked_pte);
KSYM_DECLARE_FUNC(__get_locked_pte);

KSYM_DECLARE_TYPE(page_remove_rmap);
KSYM_DECLARE_FUNC(page_remove_rmap);

KSYM_DECLARE_TYPE(vm_normal_page);
KSYM_DECLARE_FUNC(vm_normal_page);

KSYM_DECLARE_TYPE(ptep_clear_flush);
KSYM_DECLARE_FUNC(ptep_clear_flush);

KSYM_DECLARE_TYPE(free_swap_and_cache);
KSYM_DECLARE_FUNC(free_swap_and_cache);

KSYM_DECLARE_TYPE(flush_tlb_current_task);
KSYM_DECLARE_FUNC(flush_tlb_current_task);

#endif /* _KSYM_H_ */
