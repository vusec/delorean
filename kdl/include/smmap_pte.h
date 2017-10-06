#ifndef _SMMAP_PTE_H_
#define _SMMAP_PTE_H_

#include <asm-generic/pgtable.h>

#define smmap_ptep_unset_bit(mm, addr, ptep, B) do { \
    clear_bit(B, (unsigned long *)&ptep->pte); \
    pte_update(mm, addr, ptep); \
} while(0)

#define smmap_ptep_dirty(P) pte_dirty(*(P))
#define smmap_ptep_unset_dirty(mm, addr, ptep) \
    smmap_ptep_unset_bit(mm, addr, ptep, _PAGE_DIRTY)

#define smmap_ptep_accessed(P) pte_young(*(P))
#define smmap_ptep_unset_accessed(mm, addr, ptep) \
    smmap_ptep_unset_bit(mm, addr, ptep, _PAGE_ACCESSED)

#define smmap_ptep_file(P) pte_file(*(P))

#endif /* _SMMAP_PTE_H_ */

