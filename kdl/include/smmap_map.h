#ifndef _SMMAP_MAP_H_
#define _SMMAP_MAP_H_

#include <smmap_defs.h>

#include <linux/mm.h>

struct smmap_proc_s;

typedef struct smmap_map_s {
    unsigned char active;
    unsigned long addr;
    unsigned long shadow_addr;
    size_t size;
    struct smmap_proc_s *owner;
} smmap_map_t;

#define SMMAP_VMA_PRINT(M) printk("VMA={ range=[0x%08lx;0x%08lx), cow=%d }", \
    (M)->vm_start, (M)->vm_end, is_cow_mapping((M)->vm_flags))

#define SMMAP_MAP_PRINT(M) do {\
    if (SMMAP_CONF(shadow != 0)) { \
        printk("MAP={ active=%d, size=%zd range=[0x%08lx;0x%08lx), " \
               "srange=[0x%08lx;0x%08lx) }", \
               (M)->active, (M)->size, (M)->addr, (M)->addr+(M)->size, \
               (M)->shadow_addr, (M)->shadow_addr+(M)->size); \
    } else { \
        printk("MAP={ active=%d, size=%zd range=[0x%08lx;0x%08lx) }", \
               (M)->active, (M)->size, (M)->addr, (M)->addr+(M)->size); \
    } \
} while(0)

#define SMMAP_MAP_ITER(P, M, B) do { \
    int __i, __num_maps = (P)->num_maps; \
    for (__i=0; __i<max_maps && __num_maps>0; __i++) { \
        if ((P)->maps[__i].active) { \
            M = &(P)->maps[__i]; \
            __num_maps--; \
            { B } \
        } \
    } \
} while(0)

#define SMMAP_RANGE_CONTAINS(A, S, E) ((E) >= (A) && (E) < (A)+(S))

#define SMMAP_MAP_CONTAINS_ADDR(M, A) \
    ((A) && SMMAP_RANGE_CONTAINS((M)->addr, (M)->size, *(A)))

#define SMMAP_MAP_CONTAINS_SHD_ADDR(M, SA) \
    ((SA) && SMMAP_RANGE_CONTAINS((M)->shadow_addr, (M)->size, *(SA)))

#define SMMAP_MAP_CONTAINS(M, A, SA) \
    (SMMAP_MAP_CONTAINS_ADDR(M, A) || \
     (SMMAP_CONF(shadow) != 0 && SMMAP_MAP_CONTAINS_SHD_ADDR(M, SA)))

#define SMMAP_MAP_OVERLAPS(M, SA, A) \
    SMMAP_CONF(shadow) != 0 && \
    (SMMAP_MAP_CONTAINS_ADDR(M, SA) || SMMAP_MAP_CONTAINS_SHD_ADDR(M, A))

#define SMMAP_MAP_VMAS_ITER(M, V, B) do { \
    SMMAP_MAP_GEN_VMAS_ITER(M, (M)->addr, V, B); \
} while(0)

#define SMMAP_MAP_SHD_VMAS_ITER(M, V, B) do { \
    SMMAP_MAP_GEN_VMAS_ITER(M, (M)->shadow_addr, V, B); \
} while(0)

#define SMMAP_MAP_GEN_VMAS_ITER(M, A, V, B) do { \
    V = find_vma((M)->owner->mm, A); \
    for (; (V) && (V)->vm_start <= (A)+(M)->size-1; V = (V)->vm_next) { \
        { B } \
    } \
} while(0)

#define SMMAP_MAP_ADDR_END(M)       ((M)->addr + (M)->size)
#define SMMAP_MAP_SHD_END(M)        ((M)->shadow_addr + (M)->size)
#define SMMAP_MAP_ADDR_TO_SHD(M, A) (((A) - (M)->addr) + (M)->shadow_addr)
#define SMMAP_MAP_SHD_TO_ADDR(M, A) (((A) - (M)->shadow_addr) + (M)->addr)

void smmap_map_vma_print_all(smmap_map_t *map);
void smmap_map_print_all(struct smmap_proc_s *proc);
smmap_map_t* smmap_map_lookup(struct smmap_proc_s *proc, unsigned long *addr,
    unsigned long *shadow_addr);
smmap_map_t* smmap_map_lookup2(struct smmap_proc_s *proc, smmap_map_t *data);
int smmap_map_create(struct smmap_proc_s *proc, smmap_map_t *data,
    smmap_map_t **map_ptr);
void smmap_map_destroy_all(struct smmap_proc_s *proc);
void smmap_map_destroy(smmap_map_t *map);
int smmap_map_valid(smmap_map_t *map);
int smmap_map_mmap(smmap_map_t *map);
int smmap_map_fixup_page(smmap_map_t *map, unsigned long addr,
    int *needs_tlb_flush, int should_copy, unsigned long *crc);
int smmap_map_default_page(smmap_map_t *map, unsigned long addr,
    int *needs_tlb_flush);
int smmap_map_fixup_page_list(struct smmap_proc_s *proc, const char* event);
int smmap_map_default_page_list(struct smmap_proc_s *proc,const char* event);
int smmap_map_restore(struct smmap_proc_s *proc, const char* event);
int smmap_map_rollback(struct smmap_proc_s *proc, int cpid, const char* event);
int smmap_map_rollback_ondemand(smmap_proc_t *proc,
    smmap_ctl_rollback_ondemand_t *rbdata, const char* event);
int smmap_map_mkclean(smmap_map_t *map, unsigned long *hits);
int smmap_map_mkclean_all(struct smmap_proc_s *proc, unsigned long *hits);

/* pagan */
void smmap_pagan_destroy_cb(void *priv);

#endif /* _SMMAP_MAP_H_ */

