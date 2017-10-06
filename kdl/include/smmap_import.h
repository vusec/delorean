#ifndef _SMMAP_IMPORT_H_
#define _SMMAP_IMPORT_H_

#include <linux/compiler.h>
#include <linux/mm.h>

#ifndef USE_SPLIT_PTLOCKS
#define USE_SPLIT_PTLOCKS 0
#endif

#if USE_SPLIT_PTLOCKS
#define smmap_pte_lockptr(mm, pte)    ({(void)(mm); __pte_lockptr(pte_page(*pte))})
#else
#define smmap_pte_lockptr(mm, pte)    ({(void)(pte); &(mm)->page_table_lock;})
#endif

#define smmap_do_mmap_pgoff       KSYM_IMPORT(do_mmap_pgoff)
#define smmap_ptep_clear_flush    KSYM_IMPORT(ptep_clear_flush)
#define smmap_vm_normal_page      KSYM_IMPORT(vm_normal_page)
#define smmap_page_remove_rmap    KSYM_IMPORT(page_remove_rmap)
#define smmap_free_swap_and_cache KSYM_IMPORT(free_swap_and_cache)
#define smmap_walk_page_range     KSYM_IMPORT(walk_page_range)
#define smmap_flush_tlb_current_task KSYM_IMPORT(flush_tlb_current_task)

#define smmap_get_locked_pte(P,M,A,S) do { \
    P = NULL; \
    __cond_lock(*(S), P = KSYM_IMPORT(__get_locked_pte)(M, A, S)); \
} while(0)

#define smmap_import_init() do { \
    KSYM_INIT(do_mmap_pgoff); \
    KSYM_INIT(ptep_clear_flush); \
    KSYM_INIT(vm_normal_page); \
    KSYM_INIT(page_remove_rmap); \
    KSYM_INIT(free_swap_and_cache); \
    KSYM_INIT(walk_page_range); \
    KSYM_INIT(__get_locked_pte); \
    KSYM_INIT(flush_tlb_current_task); \
} while(0)

#endif /* _SMMAP_IMPORT_H_ */
