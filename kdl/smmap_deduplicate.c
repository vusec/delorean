#include <smmap_defs.h>

typedef struct search_result_s {
    /* relates to searches performed on the deduplication tree */
    smmap_dedup_node_t *tnodep;
    struct rb_node *parentp;
    struct rb_node **newp;
    struct rb_node *bkp;
    /* relates to searches perfromed on per-node lists */
    smmap_dedup_crc_node_t *lnodep;
    /* when removing orphans in-line, if this flag is set the parent node
       will be replaced rather than removed. */
    bool replace;
} search_result_t;

typedef long long (* cmp_node_t)(smmap_dedup_node_t *node, smmap_page_t *spp,
    struct page *pagep);
typedef void (* set_node_t)(smmap_dedup_node_t *node, smmap_page_t *spp);

#define page_is_orphan(__cp) \
    atomic_read(&(__cp)->count) == 1

#define do_copy_page(__spp, __pagep, __crcp) \
    do { \
        smmap_cpage_t *__cpp, *__outcpp; \
        if (__spp->cpage) BUG(); \
        __cpp = smmap_cpage_alloc(); \
        __outcpp = __do_copy_page(__cpp, __pagep, __crcp); \
        if (IS_ERR(__outcpp)) { \
            printk(KERN_ALERT "smmap: %s: error while copying page " \
                "(err: %ld)", __func__, PTR_ERR(__outcpp)); \
            smmap_cpage_free(&__cpp); \
            BUG(); \
        } \
        smmap_page_set_cpage(__spp, __cpp); \
    } while (0)

/* the macro below is used only to provide statistics located in
   /proc/sys/smmap/info/ */
#define update_num_zeroed(__node, __frequency) \
    do { \
        if ((__node)->cpage->kpage) { \
            char *__mem; \
            __mem = kmap_atomic((__node)->cpage->kpage); \
            if (page_zero_filled(__mem)) \
                smmap_page_freq.num_zeroed = __frequency; \
            kunmap_atomic(__mem); \
        } \
    } while (0)

/* A node found means we are going to increase its frequency if
   requested since a new user is going to be added. */
#define update_page_frequency(__tnode) \
    do { \
        if (unlikely(SMMAP_CONF(page_freq))) \
            (__tnode)->frequency += 1; \
    } while (0)

int smmap_dedup_cpcounter = 0;

/* frequency statistics information */
smmap_page_freq_t smmap_page_freq = {
    .frequencies = NULL, .size = 0, .i = 0, .num_zeroed = 0 };

static struct kmem_cache *smmap_node_cache;
static struct kmem_cache *smmap_crc_node_cache;
/* The page and crc trees */
static smmap_dedup_tree_t page_tree;

static inline smmap_dedup_node_t *alloc_node(void);
static inline void free_node(smmap_dedup_node_t *node);
static inline smmap_dedup_crc_node_t *alloc_crc_node(void);
static inline void free_crc_node(smmap_dedup_crc_node_t *node);
static inline void __rm_all_nodes(struct rb_root *root);

static inline void __page_freq_clear(void);
static inline int __page_freq_prepare(void);

static inline smmap_cpage_t *__do_copy_page(smmap_cpage_t *cpp,
    struct page *pagep, unsigned long *crcp);
static void __deduplicate_page_at_fixup(smmap_page_t *spp);
static void __deduplicate_page_at_cpy(smmap_page_t *spp,
    struct page *pagep, unsigned long *crcp, bool early_copy);
static void __deduplicate_crc_at_fixup(smmap_page_t *spp);
static void __deduplicate_crc_at_cpy(smmap_page_t *spp, struct page *pagep,
    bool early_copy);
static inline void __rm_orphans(void);
static long long __cmp_page(smmap_dedup_node_t *node, smmap_page_t *spp,
    struct page *pagep);
static long long __cmp_crc(smmap_dedup_node_t *node, smmap_page_t *spp,
    struct page *pagep);
static void __set_page(smmap_dedup_node_t *node, smmap_page_t *spp);
static void __set_crc(smmap_dedup_node_t *node, smmap_page_t *spp);
static inline int __search_tree_node(smmap_page_t *spp, struct page *pagep,
    cmp_node_t cmp_cb, search_result_t *sretp);
static inline int __search_list_node(smmap_page_t *spp, search_result_t *sretp,
    struct page *pagep);
static inline int __insert_tree_node(smmap_page_t *spp, set_node_t set_node_cb,
    search_result_t *sretp);
static inline int __insert_list_node(smmap_page_t *spp, search_result_t *sretp);
static inline int __rm_tree_orphans_inline(smmap_dedup_node_t *tnodep,
    search_result_t *sretp);
static inline int __rm_list_orphans_inline(smmap_dedup_crc_node_t *lnodep);
static inline void __try_rm_tree_orphan(smmap_dedup_node_t *tnode,
    search_result_t *sretp);
static inline void __try_rm_list_orphans(smmap_dedup_node_t *tnode);
static inline void __try_rm_list_orphan(smmap_dedup_crc_node_t *lnodep);


/**
 * smmap_dedup_dointvec - takes action when the deduplication configuration
 *                        is set. This will clean up the tree.
 */
int smmap_dedup_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos)
{
    int ret = 0;

    ret = proc_dointvec(table, write, buffer, lenp, p_pos);
    if (write) {
        /* the configuration was changed, so let's clean-up the tree */
        smmap_dedup_clear();
        /* check for compatibility with the compression code path */
        check_dedup_and_compress();
    }
    return ret;
}

/**
 * smmap_dedup_sysctl_pstats - dumps information from the deduplicated pages.
 *
 * NB: This function is meant to be called multiple times, each time printing
 *     a chunk of the deduplication tree. However, it cannot guarantee
 *     a consistent view of the deduplication tree among calls. Make sure that
 *     while interacting with this function, there is no access to the
 *     deduplication tree.
 */
int smmap_dedup_page_freq_sysctl(ctl_table *ctl, int write, void __user *buffer,
    size_t *lenp, loff_t *ppos)
{
    int pos = 0, ret, i;
    char *string;

    if (SMMAP_CONF(page_freq) && !smmap_page_freq.frequencies)
        __page_freq_prepare();

    if (!*lenp || (*ppos && !write) || !smmap_page_freq.frequencies) {
        smmap_page_freq.string[0] = '[';
        smmap_page_freq.string[1] = ']';
        smmap_page_freq.string[2] = '\0';

        goto exit;
    }

    /* make sure the string array is emtpy */
    string = smmap_page_freq.string;
    memset(string, 0, PAGE_STATS_SIZE);

    /* open array */
    pos += ret = scnprintf(string, PAGE_STATS_SIZE - pos, "[");
    if (!ret) goto error;

    if (smmap_page_freq.i >= smmap_page_freq.size) {
        /* When the stream has compeleted, lets just clean up the memory */
        if (smmap_page_freq.frequencies) kfree(smmap_page_freq.frequencies);
        smmap_page_freq.i = smmap_page_freq.size = 0;
        smmap_page_freq.frequencies = NULL;

    } else {
        /* iterate over the values, making sure that the string is
           not overflowed */
        i = smmap_page_freq.i;
        for (; i < smmap_page_freq.size; ++i) {
            pos += ret = scnprintf(string + pos, PAGE_STATS_SIZE - pos,
                "%d, ", smmap_page_freq.frequencies[i]);
            if (!ret) goto error;

            if ((PAGE_STATS_SIZE - pos) < 15)
                break;
        }
        smmap_page_freq.i = i;
    }

    /* close array */
    pos += ret = scnprintf(string + pos, PAGE_STATS_SIZE - pos, "]");
    if (!ret) goto error;

    goto exit;

error:
    pr_info("smmap: (%s) info buffer too small\n", __func__);

exit:
    return proc_dostring(ctl, write, buffer, lenp, ppos);
}

static inline int __page_freq_prepare(void)
{
    int size = 0, i = 0, ret = 0;
    unsigned long flags;
    struct rb_node *next;
    smmap_dedup_node_t *tnode;

    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_CRC ||
        SMMAP_CONF(dedup_type) == DEDUP_TYPE_NONE) {

        __rm_all_nodes(&page_tree.root);
        return 0;
    }

    spin_lock_irqsave(&page_tree.lock, flags);

    /* determine the number of elements in the deduplication tree */
    next = rb_first(&page_tree.root);
    while (next) {
        size++;
        next = rb_next(next);
    }
    if (size == 0) goto exit;

    /* prepare the shared datastructure with accounting and integer array */
    smmap_page_freq.size = size;
    smmap_page_freq.frequencies = (int *) kmalloc(
        size * sizeof(int), GFP_ATOMIC);

    if (!smmap_page_freq.frequencies) {
        ret = -ENOMEM;
        goto exit;
    }
    memset(smmap_page_freq.frequencies, 0, size * sizeof(int));

    /* collect the ref-count values of all the pages stored in the
       deduplication tree.
       NB: This assumes a single process being registered. */
    next = rb_first(&page_tree.root);
    while (next) {
        BUG_ON(i >= size);

        tnode = rb_entry(next, smmap_dedup_node_t, node);
        smmap_page_freq.frequencies[i] = tnode->frequency + 1;
        if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_PAGE) {
            update_num_zeroed(tnode, smmap_page_freq.frequencies[i]);
        }

        next = rb_next(next);
        i += 1;
    }

    /* at this point, clear the deduplication tree */
    __rm_all_nodes(&page_tree.root);

exit:
    spin_unlock_irqrestore(&page_tree.lock, flags);

    return ret;
}

int smmap_dedup_init(void)
{
    smmap_node_cache = kmem_cache_create("smmap_node_cache",
        sizeof(smmap_dedup_node_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
    if (!smmap_node_cache) return -ENOMEM;

    smmap_crc_node_cache = kmem_cache_create("smmap_crc_node_cache",
        sizeof(smmap_dedup_crc_node_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
    if (!smmap_crc_node_cache) return -ENOMEM;

    /* Initialize the trees */
    page_tree.root = RB_ROOT;
    spin_lock_init(&page_tree.lock);

    return 0;
}

void smmap_dedup_clear_orphans(void)
{
    unsigned long flags;

    DEBUG(DEBUG_L1, "clearing orphans");

    spin_lock_irqsave(&page_tree.lock, flags);
    __rm_orphans();
    spin_unlock_irqrestore(&page_tree.lock, flags);
}

void smmap_dedup_clear(void)
{
    unsigned long flags;

    spin_lock_irqsave(&page_tree.lock, flags);
    /* remove all the elements from the page tree */
    __rm_all_nodes(&page_tree.root);
    spin_unlock_irqrestore(&page_tree.lock, flags);

    __page_freq_clear();
}

void smmap_dedup_close(void)
{
    smmap_dedup_clear();
    kmem_cache_destroy(smmap_node_cache);
}

void smmap_dedup_add(smmap_page_t *spp, struct page *pagep, unsigned long *crcp,
    bool is_fixup, bool is_cow)
{
    int location = SMMAP_CONF(dedup_location);

    if (!spp) BUG();

    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_NONE) {
        printk(KERN_ALERT "deduplicating while deduplication is disabled \n");
        BUG();

    } else if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_PAGE) {
        /* Page based deduplication */
        switch (location) {
            case DEDUP_LOCATION_CP:
                if (!is_fixup) do_copy_page(spp, pagep, crcp);
                else __deduplicate_page_at_fixup(spp);
                break;

            case DEDUP_LOCATION_COW_COPY:
                if (!is_fixup)
                    __deduplicate_page_at_cpy(spp, pagep, crcp, true);
                break;

            case DEDUP_LOCATION_COW_SEARCH:
                if (!is_fixup)
                    __deduplicate_page_at_cpy(spp, pagep, crcp, false);
                break;

            case DEDUP_LOCATION_SPEC:
                if (!is_fixup && !is_cow)
                    __deduplicate_page_at_cpy(spp, pagep, crcp, false);
                break;

            default:
                BUG();
        }

    } else if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_CRC) {
        /* Crc based deduplication */
        switch (location) {
            case DEDUP_LOCATION_CP:
                if (!is_fixup) {
                    do_copy_page(spp, pagep, &spp->crc);
                    if (crcp) *crcp = spp->crc;
                } else {
                    __deduplicate_crc_at_fixup(spp);
                }
                break;

            case DEDUP_LOCATION_COW_COPY:
                if (!is_fixup) {
                    __deduplicate_crc_at_cpy(spp, pagep, true);
                    if (crcp) *crcp = spp->crc;
                }
                break;

            case DEDUP_LOCATION_COW_SEARCH:
                if (!is_fixup) {
                    __deduplicate_crc_at_cpy(spp, pagep, false);
                    if (crcp) *crcp = spp->crc;
                }
                break;

            case DEDUP_LOCATION_SPEC:
                if (!is_fixup && !is_cow) {
                    __deduplicate_crc_at_cpy(spp, pagep, false);
                    if (crcp) *crcp = spp->crc;
                }
                break;

            default:
                BUG();
        }
    }
}

static inline void __page_freq_clear(void)
{
    if (!smmap_page_freq.frequencies) {
        kfree(smmap_page_freq.frequencies);
        memset(&smmap_page_freq, 0, sizeof(smmap_page_freq_t));
    }
}

static inline smmap_cpage_t *__do_copy_page(smmap_cpage_t *cpp,
    struct page *pagep, unsigned long *crcp)
{
    struct page *npagep = NULL;

    if (!cpp || !pagep)
        return ERR_PTR(-EINVAL);

    npagep = smmap_copy_page(pagep, crcp);
    if (IS_ERR(pagep))
        return (void *) pagep;

    smmap_cpage_set_page(cpp, npagep);
    return cpp;
}

static void __deduplicate_page_at_fixup(smmap_page_t *spp)
{
    unsigned long flags;
    search_result_t sret;
    int found, ret;

    if (!spp->cpage) BUG();

    memset(&sret, 0, sizeof(search_result_t));

    spin_lock_irqsave(&page_tree.lock, flags);
    found = __search_tree_node(spp, NULL, __cmp_page, &sret);
    if (found < 0) {
        printk(KERN_ALERT "smmap: %s: error searching the deduplication tree "
            "(err: %d)\n", __func__, found);
        goto err;

    } else if (found) {
        /* If compression is enabled, when deduplicating the page size
           needs to be subtracted by the compression size statistics */
        if (SMMAP_CONF(compress) != COMPRESS_NONE)
            smmap_compress_size_sub(spp->cpage);

        /* swap the cpages on spp */
        smmap_page_set_cpage(spp, sret.tnodep->cpage);
        update_page_frequency(sret.tnodep);

    } else {
        /* add the element in the tree */
        ret = __insert_tree_node(spp, __set_page, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a new deduplication "
                "node (err: %d)\n", __func__, ret);
            goto err;
        }
        /* update statistics */
        SMMAP_STAT_INC(num_unique_pages);
    }
    goto exit;

err:
    spin_unlock_irqrestore(&page_tree.lock, flags);
    BUG();

exit:
    spin_unlock_irqrestore(&page_tree.lock, flags);
}

static void __deduplicate_page_at_cpy(smmap_page_t *spp, struct page *pagep,
    unsigned long *crcp, bool early_copy)
{
    unsigned long flags;
    search_result_t sret;
    struct page *in_pagep = NULL;
    int found, ret;

    if (early_copy) do_copy_page(spp, pagep, crcp);
    else in_pagep = pagep;

    memset(&sret, 0, sizeof(search_result_t));

    spin_lock_irqsave(&page_tree.lock, flags);
    found = __search_tree_node(spp, in_pagep, __cmp_page, &sret);
    if (found < 0) {
        printk(KERN_ALERT "smmap: %s: error searching the deduplication tree "
            "(err: %d)\n", __func__, found);
        goto err;

    } else if (found) {
        /* swap the cpages on spp */
        smmap_page_set_cpage(spp, sret.tnodep->cpage);
        update_page_frequency(sret.tnodep);

        /* when searching and later copying, we need to get the crc from the
           tree. NB: this *assumes* that the crc was computed and stored in
           the node when the copying happened. */
        if (!early_copy && crcp) *crcp = sret.tnodep->crc;

    } else {
        if (!early_copy) do_copy_page(spp, pagep, crcp);

        /* add the element in the tree */
        ret = __insert_tree_node(spp, __set_page, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a new deduplication "
                "node (err: %d)\n", __func__, ret);
            goto err;
        }
        /* store the CRC if required for pagan. This is recovered later when
           deduplication happens*/
        if (crcp) sret.tnodep->crc = *crcp;
        /* update statistics */
        SMMAP_STAT_INC(num_unique_pages);
    }
    goto exit;

err:
    if (smmap_page_has_page(spp)) smmap_cpage_unset(spp);
    spin_unlock_irqrestore(&page_tree.lock, flags);
    BUG();

exit:
    spin_unlock_irqrestore(&page_tree.lock, flags);
}

static void __deduplicate_crc_at_fixup(smmap_page_t *spp)
{
    unsigned long flags;
    search_result_t sret;
    int found, ret;

    if (!spp->cpage) BUG();

    memset(&sret, 0, sizeof(search_result_t));

    spin_lock_irqsave(&page_tree.lock, flags);
    found = __search_tree_node(spp, NULL, __cmp_crc, &sret);
    if (found < 0) {
        printk(KERN_ALERT "smmap: %s: error searching the deduplication tree "
            "(err: %d)\n", __func__, found);
        goto err;

    } else if (found) {
        /* search the page in the list */
        found = __search_list_node(spp, &sret, NULL);
        if (found < 0) {
            printk(KERN_ALERT "smmap: %s: error searching node list "
                "(err: %d)\n", __func__, found);
            goto err;

        } else if (found) {
            /* If compression is enabled, when deduplicating the page size
               needs to be subtracted by the compression size statistics */
            if (SMMAP_CONF(compress) != COMPRESS_NONE)
                smmap_compress_size_sub(spp->cpage);

            /* replace the found page in the smmap-page */
            smmap_page_set_cpage(spp, sret.lnodep->cpage);
            update_page_frequency(sret.tnodep);

        } else {
            /* add the list entry */
            ret = __insert_list_node(spp, &sret);
            if (ret < 0) {
                printk(KERN_ALERT "smmap: %s: error inserting a list node "
                    "(err: %d)\n", __func__, ret);
                goto err;
            }
            /* update statistics */
            if (!sret.replace) SMMAP_STAT_INC(num_unique_pages);
        }

    } else {
        /* add the element in the tree */
        ret = __insert_tree_node(spp, __set_crc, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a tree  node "
                "(err: %d)\n", __func__, ret);
            goto err;
        }
        /* add also the element in the list */
        ret = __insert_list_node(spp, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a list node "
                "(err: %d)\n", __func__, ret);
            goto err;
        }
        /* update statistics */
        SMMAP_STAT_INC(num_unique_pages);
        if (!sret.replace) SMMAP_STAT_INC(num_unique_crcs);
    }
    goto exit;

err:
    spin_unlock_irqrestore(&page_tree.lock, flags);
    BUG();

exit:
    spin_unlock_irqrestore(&page_tree.lock, flags);
}

static void __deduplicate_crc_at_cpy(smmap_page_t *spp, struct page *pagep,
    bool early_copy)
{
    unsigned long flags;
    search_result_t sret;
    struct page *in_pagep = NULL;
    int found, ret;

    if (early_copy) {
        do_copy_page(spp, pagep, &spp->crc);
    } else {
        in_pagep = pagep;
        get_highpage_crc(pagep, &spp->crc);
    }

    memset(&sret, 0, sizeof(search_result_t));

    spin_lock_irqsave(&page_tree.lock, flags);
    found = __search_tree_node(spp, in_pagep, __cmp_crc, &sret);
    if (found < 0) {
        printk(KERN_ALERT "smmap: %s: error searching the deduplication tree "
            "(err: %d)\n", __func__, found);
        goto err;

    } else if (found) {
        found = __search_list_node(spp, &sret, in_pagep);
        if (found < 0) {
            printk(KERN_ALERT "smmap: %s: error searching node list "
                "(err: %d)\n", __func__, found);
            goto err;

        } else if (found) {
            /* replace the found page in the smmap-page */
            smmap_page_set_cpage(spp, sret.lnodep->cpage);
            update_page_frequency(sret.tnodep);

        } else {
            if (!early_copy) do_copy_page(spp, pagep, &spp->crc);
            /* add the list entry */
            ret = __insert_list_node(spp, &sret);
            if (ret < 0) {
                printk(KERN_ALERT "smmap: %s: error inserting a list node "
                    "(err: %d)\n", __func__, ret);
                goto err;
            }
            /* update statistics */
            SMMAP_STAT_INC(num_unique_pages);
        }

    } else {
        if (!early_copy) do_copy_page(spp, pagep, &spp->crc);
        /* add the element in the tree */
        ret = __insert_tree_node(spp, __set_crc, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a tree  node "
                "(err: %d)\n", __func__, ret);
            goto err;
        }
        /* add also the element in the list */
        ret = __insert_list_node(spp, &sret);
        if (ret < 0) {
            printk(KERN_ALERT "smmap: %s: error inserting a list node "
                "(err: %d)\n", __func__, ret);
            goto err;
        }
        /* update statistics */
        SMMAP_STAT_INC(num_unique_pages);
        SMMAP_STAT_INC(num_unique_crcs);
    }
    goto exit;

err:
    if (smmap_page_has_page(spp)) smmap_cpage_unset(spp);
    spin_unlock_irqrestore(&page_tree.lock, flags);
    BUG();

exit:
    spin_unlock_irqrestore(&page_tree.lock, flags);
}

static inline int __search_tree_node(smmap_page_t *spp, struct page *pagep,
    cmp_node_t cmp_cb, search_result_t *sretp)
{
    smmap_dedup_node_t *this;
    long long cmp;
    int ret;

    if (!spp || !cmp_cb || !sretp)
        return -EINVAL;

    sretp->newp = &page_tree.root.rb_node;
    /* When dealing with in-line tree-node deletion, we might end-up deleting
       a node and trashing the newp pointer value (is a pointer to a pointer
       held by the parent node deleted. To account for this case, we used the
       backup pointer node. */
    while ((sretp->newp && *sretp->newp) || sretp->bkp) {
        if (sretp->newp) {
            sretp->parentp = *sretp->newp;
        } else {
            sretp->parentp = sretp->bkp;
            sretp->bkp = NULL;
        }

        this = rb_entry(sretp->parentp, smmap_dedup_node_t, node);
        cmp = cmp_cb(this, spp, pagep);

        if (cmp < 0) {
            sretp->newp = &(sretp->parentp)->rb_left;
        } else if (cmp > 0) {
            sretp->newp = &(sretp->parentp)->rb_right;
        } else {
            sretp->tnodep = this;
            return 1;
        }

        ret = __rm_tree_orphans_inline(this, sretp);
        if (ret < 0) return ret;
    }

    return 0;
}

static inline int __search_list_node(smmap_page_t *spp, search_result_t *sretp,
    struct page *pagep)
{
    struct list_head *cursor, *ctmp;
    smmap_dedup_crc_node_t *lnodep = NULL;
    int cmp, ret;

    if (!spp || !sretp || !sretp->tnodep)
        return -EINVAL;

    list_for_each_safe(cursor, ctmp, &sretp->tnodep->crc_pages.list) {
        lnodep = list_entry(cursor, smmap_dedup_crc_node_t, list);
        cmp = (pagep) ? memcmp_pages(lnodep->cpage->kpage, pagep) :
            smmap_cpage_compare(spp->cpage, lnodep->cpage);

        if (cmp == 0) {
            sretp->lnodep = lnodep;
            return 1;
        }

        ret = __rm_list_orphans_inline(lnodep);
        if (ret < 0) return ret;
    }

    return 0;
}

static inline int __rm_tree_orphans_inline(smmap_dedup_node_t *tnodep,
    search_result_t *sretp)
{
    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_NONE ||
        SMMAP_CONF(dedup_clear) != DEDUP_CLEAR_INLINE) {

        return 0;
    }

    if (!tnodep || !sretp) return -EINVAL;

    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_PAGE) {
        if (page_is_orphan(tnodep->cpage) && !(*sretp->newp)) {
            /* When dealing with inline orphan reclaming, we need to make sure
               that we do not drop a node that is going to be the parent of a
               new node. In such a case, we will simply replace the parent with
               the new node instead of doing insertion. This function signals
               the event setting the flag below. */
            sretp->replace = true;
            return 0;
        }

        /* if the node is not a parent, try to remove the node */
        __try_rm_tree_orphan(tnodep, sretp);

    } else if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_CRC) {
        /* attempt to clean orphaned pages in the list of the current node */
        __try_rm_list_orphans(tnodep);
        /* test for parent-orphand tree nodes */
        if (list_empty(&(tnodep)->crc_pages.list) && !(*sretp->newp)) {
            /* If the tree node is now an empty node but is the parent of the
               node we are about to add, we flag only the need to replace
               the node later at insertion time and signal it by setting the
               flag below. */
            sretp->replace = true;
            return 0;
        }
        /* if the node is now not needed, clean it up */
        __try_rm_tree_orphan(tnodep, sretp);
    }

    return 0;
}

static inline int __rm_list_orphans_inline(smmap_dedup_crc_node_t *lnodep)
{
    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_NONE ||
        SMMAP_CONF(dedup_clear) != DEDUP_CLEAR_INLINE) {

        return 0;
    }

    if (!lnodep) return -EINVAL;

    __try_rm_list_orphan(lnodep);

    return 0;
}

static inline int __insert_tree_node(smmap_page_t *spp, set_node_t set_node_cb,
    search_result_t *sretp)
{
   if (!spp || !set_node_cb || !sretp)
       return -EINVAL;

   /* alloc and prepare the node */
   sretp->tnodep = alloc_node();
   set_node_cb(sretp->tnodep, spp);

   /* add the node or replace the parent */
   if (sretp->replace) {
        smmap_dedup_node_t *entry = rb_entry(sretp->parentp,
            smmap_dedup_node_t, node);
        /* just replace the parent node with the new one */
        rb_replace_node(sretp->parentp, &sretp->tnodep->node, &page_tree.root);
        /* In case of CRC, we know already that this element had an empty list
           and is supposed to be removed, hence no need for a special case. */
        smmap_cpage_unset(entry);
        free_node(entry);

   } else {
        /* add node and rebalance tree */
        rb_link_node(&sretp->tnodep->node, sretp->parentp, sretp->newp);
        rb_insert_color(&sretp->tnodep->node, &page_tree.root);
   }

   return 0;
}

static inline int __insert_list_node(smmap_page_t *spp, search_result_t *sretp)
{
    smmap_dedup_crc_node_t *lnodep = NULL;

    if (!spp || !sretp || !sretp->tnodep) return -EINVAL;

    /* prepare the list node */
    lnodep = alloc_crc_node();
    if (!lnodep) return -ENOMEM;
    smmap_cpage_set(lnodep, spp->cpage);
    /* add the list-node to the tree-node list */
    list_add(&lnodep->list, &sretp->tnodep->crc_pages.list);

    return 0;
}

static inline smmap_dedup_node_t *alloc_node(void)
{
    smmap_dedup_node_t *node;

    node = kmem_cache_alloc(smmap_node_cache, GFP_ATOMIC);
    memset(node, 0, sizeof(smmap_dedup_node_t));
    INIT_LIST_HEAD(&node->crc_pages.list);
    return node;
}

static inline void free_node(smmap_dedup_node_t *node)
{
    kmem_cache_free(smmap_node_cache, node);
}

static inline smmap_dedup_crc_node_t *alloc_crc_node(void)
{
    smmap_dedup_crc_node_t *node;

    node = kmem_cache_alloc(smmap_crc_node_cache, GFP_ATOMIC);
    memset(node, 0, sizeof(smmap_dedup_crc_node_t));
    return node;
}

static inline void free_crc_node(smmap_dedup_crc_node_t *node)
{
    kmem_cache_free(smmap_crc_node_cache, node);
}

static inline void __rm_orphans(void)
{
    struct rb_root *root = &page_tree.root;
    struct rb_node *pos, *next = rb_first(root);
    smmap_dedup_node_t *node;

    if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_NONE) return;

    while (next) {
        pos = next;
        next = rb_next(pos);
        node = rb_entry(pos, smmap_dedup_node_t, node);

        if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_PAGE) {
            __try_rm_tree_orphan(node, NULL);

        } else if (SMMAP_CONF(dedup_type) == DEDUP_TYPE_CRC) {
            __try_rm_list_orphans(node);
            __try_rm_tree_orphan(node, NULL);
        }
    }
}

static inline void __rm_all_nodes(struct rb_root *root)
{
    struct rb_node *pos, *next = rb_first(root);
    smmap_dedup_node_t *node;
    smmap_dedup_crc_node_t *lnode;

    while (next) {
        pos = next;
        next = rb_next(pos);

        node = rb_entry(pos, smmap_dedup_node_t, node);
        rb_erase(&node->node, root);
        if (node->cpage) smmap_cpage_unset(node);

        /* in case of crc we need to drop the list as well */
        while (!list_empty(&node->crc_pages.list)) {
            lnode = list_first_entry(&node->crc_pages.list,
                smmap_dedup_crc_node_t, list);

            smmap_cpage_unset(lnode);
            list_del(&lnode->list);
            free_crc_node(lnode);
        }

        /* free the memory of the node */
        free_node(node);
    }
}

static inline void __try_rm_tree_orphan(smmap_dedup_node_t *tnodep,
    search_result_t *sretp)
{
    bool is_page_dedup = SMMAP_CONF(dedup_type) == DEDUP_TYPE_PAGE;
    bool is_crc_dedup = SMMAP_CONF(dedup_type) == DEDUP_TYPE_CRC;

    if (is_page_dedup && page_is_orphan(tnodep->cpage)) {
        DEBUG(DEBUG_L2, "Dropping page from deduplication tree (type: page) "
            "cpage addr=0x%p", tnodep->cpage);

        /* drop page */
        smmap_cpage_unset(tnodep);
        if (unlikely(tnodep->cpage)) BUG();

        /* save the backup pointer and remove the newp pointer if in
           in-line mode*/
        if (sretp && sretp->newp) {
            sretp->bkp = *sretp->newp;
            sretp->newp = NULL;
        }

        /* drop node */
        rb_erase(&tnodep->node, &page_tree.root);
        free_node(tnodep);

        /* update statistics */
        SMMAP_STAT_DEC(num_unique_pages);

    } else if (is_crc_dedup && list_empty(&tnodep->crc_pages.list)) {
        /* remove the node from the tree */
        DEBUG(DEBUG_L2, "Dropping node from deduplication tree "
            "(type: crc) CRC: %lu", tnodep->crc);

        /* remove the node from the tree */
        rb_erase(&tnodep->node, &page_tree.root);
        free_node(tnodep);

        /* update statistics */
        SMMAP_STAT_DEC(num_unique_crcs);
    }
}

static inline void __try_rm_list_orphans(smmap_dedup_node_t *tnodep)
{
    struct list_head *cursor, *tmp;
    smmap_dedup_crc_node_t *node;

    list_for_each_safe(cursor, tmp, &tnodep->crc_pages.list) {
        node = list_entry(cursor, smmap_dedup_crc_node_t, list);
        __try_rm_list_orphan(node);
    }
}

static inline void __try_rm_list_orphan(smmap_dedup_crc_node_t *lnodep)
{
    if (page_is_orphan(lnodep->cpage)) {
        DEBUG(DEBUG_L2, "Dropping orphan-page from CRC page-list (page: 0x%p)",
            lnodep->cpage);

        /* drop page */
        smmap_cpage_unset(lnodep);
        if (unlikely(lnodep->cpage)) BUG();

        /* drop list node */
        list_del(&lnodep->list);
        free_crc_node(lnodep);

        /* update statistics */
        SMMAP_STAT_DEC(num_unique_pages);
    }
}

static long long __cmp_page(smmap_dedup_node_t *node, smmap_page_t *spp,
    struct page *pagep)
{
    /* if a pointer to a page is provided, we take it as a higher priority
       request to compare directly to the page provided */
    return (pagep) ? memcmp_pages(node->cpage->kpage, pagep) :
        smmap_cpage_compare(spp->cpage, node->cpage);
}

static long long __cmp_crc(smmap_dedup_node_t *node, smmap_page_t *spp,
    struct page *pagep)
{
    return node->crc - spp->crc;
}

static void __set_page(smmap_dedup_node_t *nodep, smmap_page_t *spp)
{
    smmap_cpage_set(nodep, spp->cpage);
}

static void __set_crc(smmap_dedup_node_t *nodep, smmap_page_t *spp)
{
    nodep->crc = spp->crc;
}
