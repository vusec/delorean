#include <smmap_defs.h>

#include <asm/tlbflush.h>
#include <asm-generic/pgtable.h>

#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <common/pagan/pagan.h>

#define smmap_wrprotect_page(ptep) \
    do { \
        pte_t pte; \
        vma = find_vma(mm, addr); \
        BUG_ON(!vma); \
        pte = smmap_ptep_clear_flush(vma, addr, ptep); \
        pte = pte_mkclean(pte_wrprotect(pte)); \
        set_pte_at(mm, addr, ptep, pte); \
    } while (0)

#define GET_PAGE_ALIGNED(A) \
    PAGE_ALIGNED((A)) ? (A) : PAGE_ALIGN((A)) - PAGE_SIZE;

void smmap_map_vma_print_all(smmap_map_t *map)
{
    struct vm_area_struct *vma;

#ifdef ENABLE_DEBUG
    if (SMMAP_CONF(debug_verbosity) < DEBUG_L2) return;
#endif

    printk("--- MAP VMAS:\n");
    SMMAP_MAP_VMAS_ITER(map, vma,
        SMMAP_VMA_PRINT(vma); printk("\n");
    );
    if (SMMAP_CONF(shadow) != 0) {
        printk("--- MAP SHADOW VMAS:\n");
        SMMAP_MAP_SHD_VMAS_ITER(map, vma,
            SMMAP_VMA_PRINT(vma); printk("\n");
        );
    }
}

void smmap_map_print_all(smmap_proc_t *proc)
{
    smmap_map_t *map;

#ifdef ENABLE_DEBUG
    if (SMMAP_CONF(debug_verbosity) < DEBUG_L2) return;
#endif

    printk("--- MAPS (%d):\n", proc->num_maps);
    SMMAP_MAP_ITER(proc, map,
        SMMAP_MAP_PRINT(map); printk("\n");
        smmap_map_vma_print_all(map);
    );
}

smmap_map_t* smmap_map_lookup(smmap_proc_t *proc, unsigned long *addr,
    unsigned long *shadow_addr)
{
    smmap_map_t *map;

    SMMAP_MAP_ITER(proc, map,
        if (SMMAP_MAP_CONTAINS(map, addr, shadow_addr)) {
            return map;
        }
    );

    return NULL;
}

smmap_map_t* smmap_map_lookup2(smmap_proc_t *proc, smmap_map_t *data)
{
    int i;
    unsigned long addrs[4];
    size_t max_addrs;

    if (SMMAP_CONF(shadow) != 0) {
        addrs[0] = data->addr;
        addrs[1] = data->shadow_addr;
        addrs[2] = data->addr ? data->addr + data->size - 1 : 0;
        addrs[3] = data->shadow_addr ? data->shadow_addr + data->size - 1 : 0;
        max_addrs = 4;
    } else {
        addrs[0] = data->addr;
        addrs[1] = data->addr ? data->addr + data->size - 1 : 0;
        addrs[2] = 0;
        addrs[3] = 0;
        max_addrs = 2;
    }

    for (i=0; i<max_addrs; i++) {
        smmap_map_t *map = smmap_map_lookup(proc, &addrs[i], &addrs[i]);
        if (map) {
            return map;
        }
    }

    return NULL;
}

int smmap_map_create(smmap_proc_t *proc, smmap_map_t *data,
    smmap_map_t **map_ptr)
{
    smmap_map_t *map;
    int i, ret;

    /* Check validity. */
    if (!smmap_map_valid(data)) {
        return -EINVAL;
    }

    /* Disallow overlapping ranges of any sort. */
    if (smmap_map_lookup2(proc, data))
        return -EEXIST;

    i = 0;
    while (i < max_maps && proc->maps[i].active) i++;
    if (i >= max_maps)
        return -ENOMEM;

    map = &proc->maps[i];
    memcpy(map, data, sizeof(smmap_map_t));
    map->active = 1;
    map->owner = proc;
    map->owner->num_maps++;
    SMMAP_STAT_INC(num_maps);
    if (map_ptr) {
        *map_ptr = map;
    }

    /* Create the necessary mappings. */
    ret = smmap_map_mmap(map);
    if (ret != 0) {
        smmap_map_destroy(map);
        return ret;
    }

    return 0;
}

void smmap_map_destroy_all(smmap_proc_t *proc)
{
    smmap_map_t *map;

    SMMAP_MAP_ITER(proc, map,
        smmap_map_destroy(map);
    );
}

void smmap_map_destroy(smmap_map_t *map)
{
    if (map == NULL) return;

    map->active = 0;
    map->owner->num_maps--;
    SMMAP_STAT_DEC(num_maps);

    if (map->owner->num_maps == 0) {
        smmap_proc_destroy(map->owner);
    }
}

int smmap_map_valid(smmap_map_t *map)
{
    if (SMMAP_MAP_OVERLAPS(map, &map->shadow_addr, &map->addr)) {
        DEBUG(DEBUG_L1, "invalid map (0x%p - 0x%p): overlaping addresses",
            (void *) map->shadow_addr, (void *) map->addr);
        return 0;
    }
    if (!PAGE_ALIGNED(map->addr)) {
        DEBUG(DEBUG_L1, "invalid address (0x%p): address not aligned",
            (void *) map->addr);
        return 0;
    }
    if (SMMAP_CONF(shadow) != 0 && !PAGE_ALIGNED(map->shadow_addr)) {
        DEBUG(DEBUG_L1, "invalid address (0x%p): shadow address not aligned",
            (void *) map->shadow_addr);
        return 0;
    }
    if (!PAGE_ALIGNED(map->size)) {
        DEBUG(DEBUG_L1, "invalid size (%lu): map size not aligned", map->size);
        return 0;
    }

    return 1;
}

static int smmap_shd_mmap(unsigned long addr, unsigned long size)
{
    unsigned long ret;
    /* XXX: can't we use vm_mmap here, as it is exported? */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
    ret = smmap_do_mmap_pgoff(NULL, addr, size,
        PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0);
#else
    unsigned long populate=0;
    ret = smmap_do_mmap_pgoff(NULL, addr, size,
        PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0, &populate);
#endif
    if (IS_ERR_VALUE(ret)) {
        return ret;
    }
    BUG_ON(ret != addr);

    return 0;
}

static void smmap_zap_pte(struct mm_struct *mm, struct vm_area_struct *vma,
                        unsigned long addr, pte_t *ptep, int flush_tlb,
                        int keep_page)
{
    pte_t pte = *ptep;

    if (pte_present(pte)) {
        struct page *page;

        flush_cache_page(vma, addr, pte_pfn(pte));
        pte = (!flush_tlb) ? ptep_get_and_clear(mm, addr, ptep) :
            smmap_ptep_clear_flush(vma, addr, ptep);

        page = smmap_vm_normal_page(vma, addr, pte);
        /* When zapping the page, if we want to keep the page but not have it
           mapped in the process, we need to increase get_page */
        if (page) {
            smmap_page_remove_rmap(page);
            dec_mm_counter(mm, PageAnon(page) ? MM_ANONPAGES : MM_FILEPAGES);
            update_hiwater_rss(mm);
            if (pte_dirty(pte)) set_page_dirty(page);
            if (!keep_page) page_cache_release(page);
        }
    } else {
        if (!pte_file(pte))
            smmap_free_swap_and_cache(pte_to_swp_entry(pte));
        pte_clear_not_present_full(mm, addr, ptep, 0);
    }
}

static void smmap_set_pte(struct mm_struct *mm, struct vm_area_struct *vma,
    pte_t *ptep, struct page *page, bool wrprotect, bool inc_count)
{
    pte_t pte;
    pgprot_t prot;

    pte = *ptep;
    if (pte_none(pte)) {
        /* required for present pages that are kept to be later restored */
        if (inc_count) get_page(page);

        page_dup_rmap(page);
        prot = vma->vm_page_prot;
        if (wrprotect) pte_wrprotect(pte);
        else pte_mkwrite(pte);
        set_pte(ptep, mk_pte(page, prot));
        inc_mm_counter(mm, PageAnon(page) ? MM_ANONPAGES : MM_FILEPAGES);
        update_hiwater_rss(mm);
    }
}

static int smmap_remove_shd_page(struct vm_area_struct *vma,
    struct mm_struct *mm, unsigned long addr)
{
    pte_t *pte;
    spinlock_t *ptl;

    if (!vma) {
        vma = find_vma(mm, addr);
        BUG_ON(!vma);
    }

    smmap_get_locked_pte(pte, mm, addr, &ptl);
    if (!pte)
        return -ENOMEM;
    if (!pte_none(*pte)) {
        smmap_zap_pte(mm, vma, addr, pte, 1, 0);
    }
    pte_unmap_unlock(pte, ptl);

    return 0;
}

static int smmap_insert_shd_page(struct vm_area_struct *vma,
    struct mm_struct *mm, unsigned long addr, struct page *page)
{
    pte_t *pte;
    spinlock_t *ptl;
    pgprot_t prot;

    if (!vma) {
        vma = find_vma(mm, addr);
        BUG_ON(!vma);
    }
    prot = vma->vm_page_prot;

    if(!page_count(page))
        return -EINVAL;
    flush_dcache_page(page);
    smmap_get_locked_pte(pte, mm, addr, &ptl);
    if (!pte)
        return -ENOMEM;
    if (!pte_none(*pte)) {
        smmap_zap_pte(mm, vma, addr, pte, 1, 0);
    }

    /* Ok, finally just insert the thing.. */
    get_page(page);
    add_mm_counter(mm, PageAnon(page) ? MM_ANONPAGES : MM_FILEPAGES, 1);
    page_dup_rmap(page);
    set_pte_at(mm, addr, pte, mk_pte(page, prot));

    pte_unmap_unlock(pte, ptl);
    return 0;
}

static inline int smmap_map_fixup_pte(smmap_map_t *map, pte_t *ptep,
    unsigned long addr, spinlock_t *ptl, int *needs_tlb_flush,
    int should_copy, unsigned long *crc)
{
    struct mm_struct *mm = map->owner->mm;
    int ret;
    unsigned long shadow_addr=0;
    struct page* page = NULL;
    struct vm_area_struct *vma = NULL;
    int tlb_flush_pending = 0;

    if (SMMAP_CONF(shadow)) {
        shadow_addr = SMMAP_MAP_ADDR_TO_SHD(map, addr);
        DEBUG(DEBUG_L1, "shadowing addr=0x%p shadow_addr=0x%p",
            (void *) addr, (void *) shadow_addr);
    }

    /* XXX: TO-DO: Hanlde pte_none() and pte_present() pages properly. */
    if (!pte_present(*ptep)) {
        if (!SMMAP_CONF(shadow)) {
            goto done;
        }
        spin_unlock(ptl);
        pte_unmap(ptep);
        DEBUG(DEBUG_L1, "pte not present, removing shadow mapping");
        return smmap_remove_shd_page(NULL, mm, shadow_addr);
    }

    if (should_copy) {
        smmap_page_t *spp;
        struct page *pagep = pte_page(*ptep);
        if (!pagep) BUG();

        spp = smmap_page_alloc();
        spp->addr = addr;
        spp->proc = map->owner;
        /* copy the page */
        if ((ret = smmap_page_copy_page(spp, pagep, crc, false)) < 0) {
            printk(KERN_ALERT "Error while copying the page (err %d).\n", ret);
            BUG();
        }
        smmap_flag_set(spp, SMMAP_PAGE_FLAG_SPECULATED);
        smmap_plist_add(&map->owner->checkpoint, spp, "pagan");

        /* the page was speculated */
        SMMAP_STAT_INC(num_spec_pages);

    } else {
        smmap_wrprotect_page(ptep);
        tlb_flush_pending = 1;
        DEBUG(DEBUG_L2, "write protected page @0x%p", (void *) addr);
    }

    if (tlb_flush_pending) {
        if (!SMMAP_CONF(tlb_batch_flush)) __flush_tlb_one(addr);
        else *needs_tlb_flush = 1;
    }

    if (!SMMAP_CONF(shadow)) goto done;
    if (!page) {
        if (SMMAP_CONF(shadow_zero_pages)) {
            page = pte_page(*ptep);
        } else {
            vma = find_vma(mm, addr);
            BUG_ON(!vma);
            page = smmap_vm_normal_page(vma, addr, *ptep);
            if (!page) goto done;
        }
    }

    /* We should use nested spinlocks for the 2 PTEs here (see copy_pte_range),
     * but the kernel API is not too pretty. We get page refcnt before and
     * drop it after, instead.
     */
    get_page(page);
    spin_unlock(ptl);
    pte_unmap(ptep);
    ret = smmap_insert_shd_page(NULL, mm, shadow_addr, page);
    put_page(page);

    return ret;
done:
    spin_unlock(ptl);
    pte_unmap(ptep);
    return 0;
}

static int smmap_map_mmap_mm_walk_cb(pte_t *pte, unsigned long addr,
    unsigned long end, struct mm_walk *walk)
{
    smmap_page_t *spp;
    smmap_proc_t *proc = (smmap_proc_t *) walk->private;

    if (pte_none(*pte)) return 0;

    spp = smmap_page_alloc();
    spp->addr = addr;
    spp->proc = proc;
    smmap_plist_add(&proc->checkpoint, spp, "smmap");

    return 0;
}

int smmap_map_mmap(smmap_map_t *map)
{
    struct vm_area_struct *vma;
    unsigned long addr, size;
    int ret = 0;
    struct mm_walk smmap_map_mmap_mm_walk = {
            .pte_entry = smmap_map_mmap_mm_walk_cb,
            .mm = map->owner->mm,
            .private = (void *) map->owner,
    };

    if (SMMAP_CONF(shadow) != 0) {
        ret = smmap_shd_mmap(map->shadow_addr, map->size);
        if (ret != 0) {
            return ret;
        }
        vma = find_vma(map->owner->mm, map->shadow_addr);
        BUG_ON(!vma);
        vma->vm_flags |= VM_DONTDUMP;
    }

    SMMAP_MAP_VMAS_ITER(map, vma,
        if (!is_cow_mapping(vma->vm_flags)) {
             continue;
        }
        addr = max(vma->vm_start, map->addr);
        size = min(vma->vm_end, SMMAP_MAP_ADDR_END(map)) - addr;

        ret = smmap_walk_page_range(addr, addr+size, &smmap_map_mmap_mm_walk);
        if (ret != 0) {
            return ret;
        }
    );

    return smmap_map_fixup_page_list(map->owner, "smmap");
}

int smmap_map_fixup_page(smmap_map_t *map, unsigned long addr,
    int *needs_tlb_flush, int should_save, unsigned long *crc)
{
    struct mm_struct *mm = map->owner->mm;
    pte_t *pte;
    spinlock_t *ptl;
    int ret;

    smmap_get_locked_pte(pte, mm, addr, &ptl);
    if (!pte) {
        printk("%s: cannot smmap_get_locked_pte failed\n", __func__ );
        return -ENOMEM;
    }
    ret = smmap_map_fixup_pte(map, pte, addr, ptl, needs_tlb_flush,
        should_save, crc);

    return ret;
}

int smmap_map_default_page(smmap_map_t *map, unsigned long addr,
    int *needs_tlb_flush)
{
    struct vm_area_struct *vma;
    struct mm_struct *mm = map->owner->mm;
    pte_t *pte;
    spinlock_t *ptl;

    vma = find_vma(mm, addr);
    if (!vma) {
        return 0;
    }

    smmap_get_locked_pte(pte, mm, addr, &ptl);
    if (!pte) return -ENOMEM;
    if (!pte_none(*pte)) {
        int flush_tlb;
        if (SMMAP_CONF(tlb_batch_flush)) {
            *needs_tlb_flush = 1;
            flush_tlb = 0;
        } else {
            flush_tlb = 1;
        }
        smmap_zap_pte(mm, vma, addr, pte, flush_tlb, 0);
    }
    pte_unmap_unlock(pte, ptl);

    return 0;
}

static int __smmap_map_save_page(smmap_plist_t *presentlist, unsigned long addr,
    pte_t *ptep, const char *event)
{
    smmap_page_t *spp;

    /* prepare the smmap page */
    spp = smmap_page_alloc();
    spp->addr = addr;
    if (pte_write(*ptep))
        smmap_flag_set(spp, SMMAP_PAGE_FLAG_IS_WRITE);
    smmap_page_set_ppage(spp, pte_page(*ptep));
    /* add the smmap page to the list */
    smmap_plist_add(presentlist, spp, event);

    DEBUG(DEBUG_L1, "(%s) saved addr=0x%p", event, (void *) addr);

    return 0;
}

static int __smmap_map_rollback_page(smmap_page_t *oldp, pte_t *ptep,
    struct vm_area_struct *vma, struct mm_struct *mm, int *needs_tlb_flush,
    const char *event)
{
    int flush_tlb;

    if (!pte_none(*ptep)) {
        if (SMMAP_CONF(tlb_batch_flush)) *needs_tlb_flush = !(flush_tlb = 0);
        else flush_tlb = 1;

        /* If an entry in the rollback lists does not contain a page,
           something unexpected happend, that was not suppose to happen. */
        if (!smmap_page_has_page(oldp)) BUG();

        /* Zap the current page, but keep it around. We only get here when a
           restore was previously issued, hence we always keep the page. */
        smmap_zap_pte(mm, vma, oldp->addr, ptep, flush_tlb, 1);
        /* Switch to the checkpointed page */
        if (!smmap_page_has_page(oldp)) BUG();
        smmap_set_pte(mm, vma, ptep, smmap_page_get_page(oldp), 1,
            !smmap_flag_is_set(oldp->cpage, SMMAP_PAGE_FLAG_COMPRESSED));
        DEBUG(DEBUG_L2, "(%s) rolledback addr=0x%p", event, (void *) oldp->addr);

    } else {
        /* XXX: might need to treat this part in a special way */
        DEBUG(DEBUG_L2, "(%s) unable to rolledback addr=0x%p", event,
            (void *) oldp->addr);
    }

    return 0;
}

int __smmap_map_save_and_rollback(smmap_map_t *map, smmap_page_t *sp,
    int *needs_tlb_flush, const char *event)
{
    smmap_proc_t *proc = map->owner;
    struct mm_struct *mm = proc->mm;
    struct vm_area_struct *vma;
    pte_t *ptep;
    spinlock_t *ptl;
    int ret;

    if (!(vma = find_vma(mm, sp->addr))) BUG();

    smmap_get_locked_pte(ptep, mm, sp->addr, &ptl);
    if (!ptep) return -ENOMEM;

    /* save the current page at the same address as the checkpointed page */
    ret = __smmap_map_save_page(&proc->present, sp->addr, ptep, event);
    if (ret != 0) goto unlock;

    /* rollback to the checkpointed page */
    ret = __smmap_map_rollback_page(sp, ptep, vma, mm, needs_tlb_flush, event);

unlock:
    pte_unmap_unlock(ptep, ptl);
    return ret;
}

#define SMMAP_PAGAN_COPY 1
#define SMMAP_PAGAN_DONT_COPY 0

/* page gets copied speculativly */
static void smmap_pagan_save_cb(void *addr, void *priv, unsigned long *crc)
{
    smmap_page_t *spp = (smmap_page_t *) priv;
    unsigned long a = (unsigned long) addr;
    smmap_map_t *map;

    /* pagan is not supposed to have a pointer to the pages since it does not
       use them */
    if (smmap_page_has_page(spp)) {
        printk("%s: pagan should not deal with pages.", __func__);
        BUG();
    }

    map = smmap_map_lookup(spp->proc, &a, NULL);
    if (!map) return;

    DEBUG(DEBUG_L2, "addr=%p", addr);
    smmap_map_fixup_page(map, (unsigned long) addr,
        &spp->proc->needs_tlb_flush, SMMAP_PAGAN_COPY, crc);
}


/* page gets discared from workingset so we have to protect it again */
static void smmap_pagan_discard_cb(void *addr, void *priv)
{
    smmap_page_t *spp = (smmap_page_t *) priv;
    unsigned long a = (unsigned long) addr;
    smmap_map_t *map;
    int *needs_tlb_flush;

    /* pagan is not supposed to have a pointer to the pages since it does not
       use them */
    if (smmap_page_has_page(spp)) {
        printk(KERN_ALERT "%s: pagan should not deal with pages.", __func__);
        BUG();
    }

    if (spp->proc == NULL) printk(KERN_ALERT "smmap_page->proc == NULL");

    map = smmap_map_lookup(spp->proc, &a, NULL);
    if (!map) return;

    DEBUG(DEBUG_L2, "addr=%p", addr);
    needs_tlb_flush = &spp->proc->needs_tlb_flush;
    smmap_map_fixup_page(map, (unsigned long) addr, needs_tlb_flush,
        SMMAP_PAGAN_DONT_COPY, NULL);
}

/* this guy is called when pagan forgets about the page */
void smmap_pagan_destroy_cb(void *priv)
{
    smmap_page_t *spp = (smmap_page_t *) priv;

    /* pagan is not supposed to have a pointer to the pages since it does not
       use them */
    if (smmap_page_has_page(spp)) {
        printk(KERN_ALERT "%s: pagan should not deal with pages.", __func__);
        BUG();
    }
    smmap_page_free(&spp);
}

static void smmap_pagan_handle_old_priv(void * old_priv)
{
    smmap_page_t *spp;

    if (old_priv) {
        spp = old_priv;
        if (smmap_page_has_page(spp)) {
            printk("%s: pagan should not deal with pages.", __func__);
            BUG();
        }
        smmap_page_free(&spp);
    }
}

static inline int smmap_map_shrink_page(smmap_page_t *spp)
{
    bool do_compress = SMMAP_CONF(compress) == COMPRESS_FIXUP;
    bool do_dedup = SMMAP_CONF(dedup_type) > DEDUP_TYPE_NONE &&
            SMMAP_CONF(dedup_location) == DEDUP_LOCATION_CP;
    int ret;

    if (!smmap_page_has_page(spp) || (!do_dedup && !do_compress))
        return 0;

    if (do_dedup && !do_compress) {
        smmap_dedup_add(spp, NULL, NULL, true, false);

    } else if (!do_dedup && do_compress) {
        /* if a CRC is required, at this point the crc should have been
           already computed, since the page was previously copied. */
        ret = smmap_compress_page(spp->cpage);
        if (ret < 0) return ret;

    } else if (do_dedup && do_compress) {
        /* first compress the node */
        ret = smmap_compress_page(spp->cpage);
        if (ret < 0) return ret;
        /* afterwards, try to add the node */
        smmap_dedup_add(spp, NULL, NULL, true, false);
    }

    return 0;
}

static int __smmap_map_fixup_page_list(smmap_proc_t *proc, const char* event)
{
    smmap_map_t *map;
    int ret = 0;
    smmap_plist_t iterable;
    smmap_page_t *spp, *pagan_spp;

    smmap_plist_clear_and_iter(&proc->checkpoint, &iterable);
    while (smmap_plist_iter_next(&iterable, &spp, event)) {
        bool was_added = false;
        void *old_priv;

        map = smmap_map_lookup(proc, &spp->addr, NULL);
        if (!map) continue;

        if (proc->use_pagan) {
            /* when pagan is requested, we must feed smmap-pages to pagan only
               if the page was not already previously speculated. If not, the
               speculation would be based on the wrong pages */
            if (!smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_SPECULATED)) {
                unsigned long proc_addr = (unsigned long) proc;

                pagan_spp = smmap_page_alloc();
                smmap_page_copy(pagan_spp, spp, false);

                /* pagan has to free the original page, if such a page exits */
                old_priv = pagan_page_add(proc_addr,
                    (void *) spp->addr, pagan_spp);
                smmap_pagan_handle_old_priv(old_priv);
            }

        } else {
            /* in the normal case, no speculation is involved so we can easily
               just apply fixup to the single page */
            ret = smmap_map_fixup_page(map, spp->addr,
                &proc->needs_tlb_flush, 0, NULL);
            if (ret < 0) goto exit_loop;
        }

        PRINT_SMMAP_PAGE(spp);
        if (smmap_page_has_page(spp)) {
            /* attempt to deduplicate and/or compress the page */
            if ((ret = smmap_map_shrink_page(spp)) < 0)
                goto exit_loop;
            /* Added to the journal db, if necessary */
            ret = smmap_journal_add(&proc->journal, spp);
            if (ret < 0) goto exit_loop;
            /* set the flag whether the page was added or not to the journal */
            was_added = ret;
        }

exit_loop:
        /* if the page was added to the journal, we cannot give it back
           since the ownership goes to the journal. If not, we can simply
           get read of the page. */
        if (!was_added) smmap_page_free(&spp);
        if (ret < 0) {
            /* in case of error, let just clear the list we were iterating on,
               to avoid leaking memory */
            smmap_plist_clear(&iterable);
            goto exit;
        }
    }

    if (proc->use_pagan) {
        /* if pagan was requested, at this point the speculation is triggered,
           and the process actually runs a round of speculation for the next
           checkpoint interval. */
        pagan_process((unsigned long) proc, smmap_pagan_save_cb,
            smmap_pagan_discard_cb, smmap_pagan_destroy_cb);
    }

exit:
    return (ret<0) ? ret : 0;
}

int smmap_map_fixup_page_list(smmap_proc_t *proc, const char* event)
{
    int ret;

    proc->needs_tlb_flush = 0;

    /* this is the point where a new checkpoint-interval starts. This
       entry-point is the same for both standard and pagan runs since they
       both share most of the logic. */
    ret = __smmap_map_fixup_page_list(proc, "fixup");
    DEBUG(DEBUG_L2, "completed fixup (return status: %d)", ret);

    if (proc->needs_tlb_flush) smmap_flush_tlb_current_task();

    return ret;
}

int smmap_map_default_page_list(smmap_proc_t *proc, const char* event)
{
    smmap_map_t *map;
    unsigned long addr;
    int ret;
    smmap_page_t *spp;
    smmap_plist_t iterable;
    int needs_tlb_flush = 0;

    smmap_plist_clone_and_iter(&proc->checkpoint, &iterable);
    while (smmap_plist_iter_next(&iterable, &spp, event)) {
        addr = spp->addr;
        map = smmap_map_lookup(proc, &addr, NULL);
        if (!map) continue;

        ret = smmap_map_default_page(map, addr, &needs_tlb_flush);
        if (ret != 0) return ret;

        /* done with the spp, give it back */
        smmap_page_free(&spp);
    }

    if (needs_tlb_flush) smmap_flush_tlb_current_task();

    return 0;
}

int smmap_map_zap_page_current_list(smmap_proc_t *proc, const char* event)
{
    smmap_map_t *map;
    unsigned long addr;
    int ret;
    smmap_page_t *spp;
    smmap_plist_t iterable;
    int needs_tlb_flush = 0;

    smmap_plist_clone_and_iter(&proc->present, &iterable);
    while (smmap_plist_iter_next(&iterable, &spp, event)) {
        addr = spp->addr;
        map = smmap_map_lookup(proc, &addr, NULL);
        if (!map) continue;

        if ((ret = smmap_map_default_page(map, addr, &needs_tlb_flush)) != 0)
            return ret;

        /* done with the spp, give it back */
        smmap_page_free(&spp);
    }

    if (needs_tlb_flush) smmap_flush_tlb_current_task();

    return 0;
}


/**
 * smmap_map_rollback - rolls back all the pages of a process to the checkpoint
 *                      specified.
 *
 * @proc: the smmap process descriptor
 * @id: the checkpoint ID to which we are rollbacking
 * @event: description of the event for debugging purposes
 *
 * Returns 0 on success or a negative value on failure
 */
int smmap_map_rollback(smmap_proc_t *proc, int id, const char* event)
{
    int ret;
    smmap_plist_t cpl;
    int needs_tlb_flush = 0;

    if (!proc || !smmap_journal_valid_id(&proc->journal, id)) return -EINVAL;

    smmap_plist_init(&cpl, "rb");

    /* To support rollback from a rollback state, we need to restore the
       present pages before proceeding with the rollback */
    if (!smmap_plist_empty(&proc->present, event))
        smmap_map_restore(proc, event);

    /* Retrieve list from the journal db */
    ret = smmap_journal_get_pages(&proc->journal, id, &cpl);
    if (ret < 0) return ret;

    /* Eagerly restore all the checkpoitned pages from the journal */
    if (!smmap_plist_empty(&cpl, event)) {
        unsigned long addr;
        smmap_map_t *map;
        smmap_plist_t iterable;
        smmap_page_t *spp;

        smmap_plist_clear_and_iter(&cpl, &iterable);
        while (smmap_plist_iter_next(&iterable, &spp, event)) {
            addr = spp->addr;
            if (!(map = smmap_map_lookup(proc, &addr, NULL))) continue;

            ret = __smmap_map_save_and_rollback(map, spp,
                &needs_tlb_flush, event);
            if (ret != 0) return ret;

            /* done with the spp, unset page */
            smmap_page_free(&spp);
        }
    }

    if (needs_tlb_flush) smmap_flush_tlb_current_task();

    return 0;
}

int smmap_map_rollback_ondemand(smmap_proc_t *proc,
    smmap_ctl_rollback_ondemand_t *data, const char* event)
{
    int i, ret = 0, needs_tlb_flush = 0, id;
    smmap_map_t *map;

    if (!proc || !data || data->slots < 0 ||
        !smmap_journal_valid_id(&proc->journal, data->checkpoint)) {

        return -EINVAL;
    }

    /* To support rollback from a rollback state, we need to restore the
       present pages before proceeding with the rollback */
    if (!smmap_plist_empty(&proc->present, event))
        smmap_map_restore(proc, event);

    /* Rollback the set of pages */
    id = data->checkpoint;
    for (i=0; i<data->slots; ++i) {
        unsigned long startp, endp;
        int j, n;

        /* Determine the number of contiguous pages starting from the variable
           that need to be rolledback. The endp indicates the last position
           occupied by the variable. Hence, for a one-byte element, startp and
           endp point to the same position. */
        startp = GET_PAGE_ALIGNED(data->vars[i].addr);
        endp = GET_PAGE_ALIGNED(data->vars[i].addr + data->vars[i].size - 1);
        n = ((endp - startp) / PAGE_SIZE) + 1;

        for (j = 0; j < n; j++) {
            smmap_page_t sp;
            unsigned long addr = startp + (PAGE_SIZE * j);

            /* check if the page was already rollbacked, if so, no need to
               search and rollback it again. */
            if (smmap_plist_contains(&proc->present, NULL, addr, event))
                continue;

            smmap_page_reset(&sp);
            ret = smmap_journal_get_page(&proc->journal, id, addr, &sp);

            if (ret < 0) {
                goto exit;
            } else if (ret == 1) {
                /* rollback the page */
                if (!(map = smmap_map_lookup(proc, &addr, NULL))) continue;
                ret = __smmap_map_save_and_rollback(map, &sp,
                    &needs_tlb_flush, event);
                /* unset the page */
                smmap_page_unset_page(&sp);

                /* in case of error, stop the rollback */
                if (ret != 0) goto exit;

                DEBUG(DEBUG_L2, "rollbakced page @addr=0x%p", (void *) addr);

            } else {
                /* no page found, skip */
                continue;
            }
        }
    }

exit:
    if (needs_tlb_flush) smmap_flush_tlb_current_task();
    return ret;
}

static int __smmap_map_restore_page(struct vm_area_struct *vma,
    struct mm_struct *mm, smmap_page_t *spp, int *needs_tlb_flush,
    const char *event)
{
    pte_t *ptep;
    spinlock_t *ptl;
    int flush_tlb;

    /* restore the page in process memory area */
    smmap_get_locked_pte(ptep, mm, spp->addr, &ptl);
    if (!ptep) return -ENOMEM;

    if (!pte_none(*ptep)) {
        if (SMMAP_CONF(tlb_batch_flush)) *needs_tlb_flush = !(flush_tlb = 0);
        else flush_tlb = 1;

        /* zap the rollbacked page. We do not keep it around since we already
           have control over it */
        smmap_zap_pte(mm, vma, spp->addr, ptep, flush_tlb, 0);
        /* Switch to the present page */
        smmap_set_pte(mm, vma, ptep, smmap_page_get_ppage(spp),
            !smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_IS_WRITE), 0);
    }
    pte_unmap_unlock(ptep, ptl);

    DEBUG(DEBUG_L2, "(%s) restored addr=0x%p", event, (void *) spp->addr);

    return 0;
}

int smmap_map_restore(struct smmap_proc_s *proc, const char* event) {
    smmap_plist_t iterable;
    smmap_page_t *spp;
    struct mm_struct *mm = proc->mm;
    struct vm_area_struct *vma;
    int needs_tlb_flush = 0;
    int ret;

    /* nothing to do if there are no present pages */
    if (smmap_plist_empty(&proc->present, event)) return 0;

    DEBUG(DEBUG_L1, "(%s) restore 'present' pages", event);

    /* eagerly restore all the rollbacked pages */
    smmap_plist_clear_and_iter(&proc->present, &iterable);
    while (smmap_plist_iter_next(&iterable, &spp, event)) {
        /* in this situation a vma should always be found */
        if (!(vma = find_vma(mm, spp->addr))) BUG();

        DEBUG(DEBUG_L2, "(%s) attempting to restore page addr=0x%p",
            event, (void *) spp->addr);

        /* restore the page in place */
        ret = __smmap_map_restore_page(vma, mm, spp, &needs_tlb_flush, event);
        if (ret != 0) return ret;

        DEBUG(DEBUG_L2, "(%s) restored page addr=0x%p", event,
            (void *) spp->addr);

        /* done with the smmap page container, unset page */
        smmap_page_free(&spp);
    }

    if (needs_tlb_flush) smmap_flush_tlb_current_task();

    return 0;
}

static int smmap_map_mkclean_mm_walk_cb(pte_t *pte, unsigned long addr,
    unsigned long end, struct mm_walk *walk)
{
    unsigned long *hits;

    if (pte_none(*pte) || !pte_present(*pte) || !pte_dirty(*pte)) {
        return 0;
    }

    hits = (unsigned long*) walk->private;
    (*hits)++;
    pte_mkclean(*pte);
    __flush_tlb_one(addr);

    return 0;
}

int smmap_map_mkclean_all(smmap_proc_t *proc, unsigned long *hits)
{
    smmap_map_t *map;
    int ret = 0;

    SMMAP_MAP_ITER(proc, map,
        ret = smmap_map_mkclean(map, hits);
        if (ret) {
            return ret;
        }
    );

    return ret;
}

int smmap_map_mkclean(smmap_map_t *map, unsigned long *hits)
{
    struct vm_area_struct *vma;
    unsigned long addr, size;
    int ret;
    struct mm_walk smmap_map_mkclean_mm_walk = {
            .pte_entry = smmap_map_mkclean_mm_walk_cb,
            .mm = map->owner->mm,
            .private = hits
    };

    SMMAP_MAP_VMAS_ITER(map, vma,
        if (!is_cow_mapping(vma->vm_flags)) {
             continue;
        }
        addr = max(vma->vm_start, map->addr);
        size = min(vma->vm_end, SMMAP_MAP_ADDR_END(map)) - addr;

        ret = smmap_walk_page_range(addr, addr+size,
            &smmap_map_mkclean_mm_walk);
        if (ret) {
            return ret;
        }
    );

    return 0;
}

