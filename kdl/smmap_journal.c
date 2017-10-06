#include <smmap_defs.h>

#define __journal_tree_insert(__tree, __key, __kmember, __type, \
    __alloc_cb, __node) \
    do { \
        struct rb_node **__new, *__parent = NULL; \
        long long __cmp; \
        bool __exists = false; \
        __new = &(__tree)->rb_node; \
        while (*__new) { \
            __node = rb_entry(*__new, __type, node); \
            __cmp = __key - __node->__kmember; \
            __parent = *__new; \
            if (__cmp < 0) __new = &(*__new)->rb_left; \
            else if (__cmp > 0) __new = &(*__new)->rb_right; \
            else { \
                __exists = true; \
                break; \
            } \
        } \
        if (!__exists) { \
            __node = __alloc_cb(); \
            (__node)->__kmember = __key; \
            rb_link_node(&(__node)->node, __parent, __new); \
            rb_insert_color(&(__node)->node, __tree); \
        } \
    } while(0)

#define __journal_tree_search_page(__tree, __id, __parent, __spp) \
    do { \
        struct rb_node **__new; \
        smmap_journal_page_t *__pagep; \
        __new = &__tree.rb_node; \
        while (*__new) { \
            long long __cmp; \
            __pagep = rb_entry(*__new, smmap_journal_page_t, node); \
            __cmp = __id - __pagep->checkpoint; \
            __parent = *__new; \
            if (__cmp < 0) __new = &(*__new)->rb_left; \
            else if (__cmp > 0) __new = &(*__new)->rb_right; \
            else { \
                __spp = __pagep->spp; \
                break; \
            } \
        } \
    } while (0)

#define __journal_page_eval(__spp, __parent) \
    do { \
        if (!__spp && __parent) { \
            smmap_journal_page_t *__pagep; \
            struct rb_node *__next = __parent; \
            if (__next) { \
                __pagep = rb_entry(__next, smmap_journal_page_t, node); \
                __spp = __pagep->spp; \
            } \
        } \
    } while (0)

static struct kmem_cache *smmap_addr_node_cache = NULL;
static struct kmem_cache *smmap_page_node_cache = NULL;

static inline smmap_plist_t *smmap_journal_itol(smmap_journal_t *journal,
    int index);
static inline int smmap_journal_ltoi(smmap_journal_t *journal,
    smmap_plist_t *list);
static inline int __journal_tree_get_pages(smmap_journal_t *journal, int id,
    smmap_plist_t *outl);
static inline int __journal_tree_get_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp);

/* memory management */
static inline smmap_journal_addr_t *alloc_addr_node(void);
static inline void free_addr_node(smmap_journal_addr_t *node);
static inline smmap_journal_page_t *alloc_page_node(void);
static inline void free_page_node(smmap_journal_page_t *node);

/**
 * smmap_journal_init - initialize a checkpoint journal
 * @journal: the pointer to the journal to be initialized
 */
void smmap_journal_init(smmap_journal_t *journal)
{
    int i;

    if (!journal) BUG();

    /* clear the content of the journal */
    memset(journal, 0, sizeof(smmap_journal_t));

    if (journal_size == 0) {
        journal->checkpoints = NULL;
        journal->inuse = NULL;
        journal->slots_used = 0;
    } else {
        journal->checkpoints = (smmap_plist_t *) vmalloc(
            sizeof(smmap_plist_t) * journal_size);
        BUG_ON(!journal->checkpoints);

        for (i=0; i<journal_size; ++i) {
            smmap_plist_init(&journal->checkpoints[i], "ith-journal");
            DEBUG(DEBUG_L1, "initialized journal list @%d", i);
        }
        journal->inuse = &journal->checkpoints[0];
        journal->slots_used = 0;
    }

    /* Initialize mem cache for the merge tree nodes */
    if (smmap_addr_node_cache == NULL) {
        smmap_addr_node_cache = kmem_cache_create("smmap_addr_node_cache",
            sizeof(smmap_journal_addr_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC,
            NULL);
    }
    if (!smmap_addr_node_cache) BUG();

    /* Initialize mem cache for the merge tree nodes */
    if (smmap_page_node_cache == NULL) {
        smmap_page_node_cache = kmem_cache_create("smmap_page_node_cache",
            sizeof(smmap_journal_page_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC,
            NULL);
    }
    if (!smmap_page_node_cache) BUG();
}

/**
 * smmap_journal_destroy - destroy a checkpoint journal
 * @journal: the pointer to the journal to be destroyed
 */
void smmap_journal_destroy(smmap_journal_t *journal)
{
    int i;

    if (!journal) BUG();

    /* remove all the elements */
    for (i=0; i<journal_size; ++i) {
        smmap_plist_clear(&journal->checkpoints[i]);
        DEBUG(DEBUG_L1, "closed journal list @%d", i);
    }
    vfree(journal->checkpoints);

    /* delete tree, if necessary*/
    smmap_journal_tree_destroy(journal);

    /* reset the entire journal struct */
    memset(journal, 0, sizeof(smmap_journal_t));

    /* Uninitialize mem cache for the merge tree nodes */
    if (smmap_addr_node_cache != NULL) {
        kmem_cache_destroy(smmap_addr_node_cache);
        smmap_addr_node_cache = NULL;
    }
}


/**
 * smmap_journal_set_next - request the journal to switch to the next db. This
 *                          function will also carry the pages from the
 *                          previous checkpoint list.
 *                          NB: this is called only at smmap requests and not
 *                              when smmap is initialized. This is required by
 *                              design.
 * @journal: the journal on which to apply the switch
 *
 * Return 0 on success, 1 on success if the number of checkpoints is greater
 * than the window, a negative value on failure.
 */
int smmap_journal_set_next(smmap_journal_t *journal)
{
    bool out_of_window;
    unsigned long index;

    if (!journal) return -EINVAL;

    DEBUG(DEBUG_L1, "Start new interval");

    /* if journal_size is set to 0, we are effectively downgrading the
       checkpointing system to no journal support. */
    if (journal_size == 0) return 1;

    /* select the pointer to the next current checkpoint db */
    index = smmap_journal_ltoi(journal, journal->inuse);
    if (journal->slots_used > 0)
        index = (index + 1) % journal_size;
    journal->inuse = &journal->checkpoints[index];

    /* set the counter that identifies the number of checkpoints currently
       indexed */
    journal->slots_used += 1;
    out_of_window = journal->slots_used > journal_size;
    journal->slots_used = (journal->slots_used <= journal_size) ?
        journal->slots_used : journal_size;

    /* clear the new journal for the next interval */
    /* if the list is going out-of-window, we are also cleaning the list, so
       we need to account for it */
    if (out_of_window) {
        size_t lenght = smmap_plist_size(journal->inuse, "checkpoint");
        SMMAP_STAT(num_total_pages) -= lenght;
    }

    smmap_plist_clear(journal->inuse);

    return out_of_window;
}

/**
 * smmap_journal_add - add a new smmap_page to the selected db in the journal
 * @journal: the journal from which the db is selected
 * @spp: pointer to the smmap_page that has to be added.
 *
 * Returns 0 if the page was not added, 1 if the page was added and a negative
 * value on failure.
 */
int smmap_journal_add(smmap_journal_t *journal, smmap_page_t *spp)
{
    const char *event = "journal add";

    if (!journal || !spp) return -EINVAL;

    if (journal->inuse == NULL) return 0;

    smmap_plist_add_or_replace(journal->inuse, spp, event);
    return 1;
}

/**
 * smmap_journal_get_pages - get a list of pages for the requested checkpoint
 * @journal: journal struct containing the dbs
 * @id: the checkpoint id related to the db
 *
 * Returns 0 on success, a negative value on failure.
 */
int smmap_journal_get_pages(smmap_journal_t *journal, int id,
    smmap_plist_t *outl)
{
    unsigned char *event = "journal get pages";

    if (!journal || id < 0 || !outl) return -EINVAL;

    if (!smmap_journal_valid_id(journal, id)) return -EINVAL;

    if (id == 0) {
        smmap_proc_t *proc = container_of(journal, smmap_proc_t, journal);

        /* Simply copy and return the current checkpoint list */
        if (!smmap_plist_empty(&proc->checkpoint, event))
            smmap_plist_copy(outl, &proc->checkpoint, event);

    } else if (!journal->merge.isinit) {
        /* search the pages associated to the requested checkpoint ID */
        int i;
        struct rb_node **new, *parent = NULL;
        struct rb_node *pos, *next;

        journal->merge.tree = RB_ROOT;
        /* From the furthest checkpoint registered, start adding smmap pages if
           the page is not present in the tree. */
        for (i=id; i>=0; i--) {
            smmap_plist_t *db;
            smmap_plist_t iterable;
            smmap_page_t *spp;

            /* Select the list */
            if (i > 0) {
                db = smmap_journal_itol(journal, i);
                if (IS_ERR(db)) return PTR_ERR(db);
            } else {
                smmap_proc_t *proc = container_of(journal,
                    smmap_proc_t, journal);
                db = &proc->checkpoint;
            }

            /* For every page in the list, try to add the page into the tree,
               if the assocaited address is not already in the tree */
            smmap_plist_clone_and_iter(db, &iterable);
            while (smmap_plist_iter_next(&iterable, &spp, event)) {
                bool exists = false;

                new = &journal->merge.tree.rb_node;
                while (*new) {
                    smmap_journal_addr_t *this = rb_entry(*new,
                        smmap_journal_addr_t, node);
                    long long cmp = this->addr - spp->addr;

                    parent = *new;
                    if (cmp < 0) {
                        new = &(*new)->rb_left;
                    } else if (cmp > 0) {
                        new = &(*new)->rb_right;
                    } else {
                        exists = true;
                        break;
                    }
                }

                /* Add a new node if the address was not found in the tree.
                   At the same time, add the smmap_page_t to the output list */
                if (!exists) {
                    smmap_journal_addr_t *newn;

                    /* Add tree node */
                    newn = alloc_addr_node();
                    newn->addr = spp->addr;
                    rb_link_node(&newn->node, parent, new);
                    rb_insert_color(&newn->node, &journal->merge.tree);

                    /* Add list node */
                    smmap_plist_add(outl, spp, event);
                } else {
                    smmap_page_free(&spp);
                }
            }
        }

        /* clear the temporary tree */
        next = rb_first(&journal->merge.tree);
        while (next) {
            smmap_journal_addr_t *this;

            pos = next;
            next = rb_next(pos);

            /* Drop the tree node */
            this = rb_entry(pos, smmap_journal_addr_t, node);
            rb_erase(&this->node, &journal->merge.tree);
            free_addr_node(this);
        }

    } else {
        int ret;

        ret = __journal_tree_get_pages(journal, id, outl);
        if (ret < 0) return ret;
    }

    return 0;
}

/**
 * smmap_journal_get_page - get the page at the specified address for the
 *                          requested checkpoint
 * @journal: journal pointer
 * @cpl: checkpoint list
 * @id: checkpoint id from which to obtain the address
 * @addr: page address to be retrieved
 * @outp: output smmap_page_t page. This page is allocated and needs to be
 *        freed by the caller of the function.
 *
 * Returns 0 on success, a negative value on error.
 */
int smmap_journal_get_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp)
{
    smmap_page_t *tmpp;
    const char *event = "journal get page";
    int i, ret;

    if (!journal || id < 0 || !outp) return -EINVAL;

    if (!journal->merge.isinit) {
        for (i=id; i>=0; i--) {
            smmap_plist_t *db;

            /* get the list */
            if (i > 0) {
                db = smmap_journal_itol(journal, i);
                if (IS_ERR(db)) return PTR_ERR(db);
            } else {
                smmap_proc_t *proc = container_of(journal, smmap_proc_t, journal);
                db = &proc->checkpoint;
            }

            /* Search the element, and if found give it to the caller
               and exit */
            if (!smmap_plist_empty(db, event)) {
                if ((ret = smmap_plist_rcontains(db, &tmpp, addr, event)) < 0) {
                    return ret;
                } else if (ret == 1) {
                    smmap_page_copy(outp, tmpp, true);
                    return 1;
                }
            }
        }
    } else {
        ret = __journal_tree_get_page(journal, id, addr, outp);
        return ret;
    }

    return 0;
}

int smmap_journal_has_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp)
{
    int ret = 0;
    smmap_plist_t *db;
    smmap_page_t *tmpp;
    const char *event = "journal access page";

    /* get the list */
    if (id > 0) {
        db = smmap_journal_itol(journal, id);
        if (IS_ERR(db)) return PTR_ERR(db);
    } else {
        smmap_proc_t *proc = container_of(journal, smmap_proc_t, journal);
        db = &proc->checkpoint;
    }

    /* Search the element, and if found give it to the caller
       and exit */
    if (!smmap_plist_empty(db, event)) {
        ret = smmap_plist_rcontains(db, &tmpp, addr, event);
        if (ret == 1) smmap_page_copy(outp, tmpp, true);
    }

    return ret;
}

/**
 * smmap_journal_valid_id -
 */
bool smmap_journal_valid_id(smmap_journal_t *journal, int id)
{
    if (!journal) return false;

    if (id <= journal->slots_used) return true;

    return false;
}

int smmap_journal_tree_populate(smmap_journal_t *journal)
{
    int i;
    const char *event = "journal tree populate";

    if (!journal) return -EINVAL;

    if (journal->merge.isinit) return 0;

    journal->merge.tree = RB_ROOT;
    for (i=0; i<=journal->slots_used; ++i) {
        smmap_plist_t *db;
        smmap_page_t *spp;
        smmap_plist_t iterable;

        /* Select the list */
        if (i > 0) {
            db = smmap_journal_itol(journal, i);
            if (IS_ERR(db)) return PTR_ERR(db);
        } else {
            smmap_proc_t *proc = container_of(journal, smmap_proc_t, journal);
            db = &proc->checkpoint;
        }

        smmap_plist_clone_and_iter(db, &iterable);
        while (smmap_plist_iter_next(&iterable, &spp, event)) {
            smmap_journal_addr_t *anodep = NULL;
            smmap_journal_page_t *pnodep = NULL;

            /* insert the address-based node */
            __journal_tree_insert(&journal->merge.tree, spp->addr, addr,
                smmap_journal_addr_t, alloc_addr_node, anodep);
            if (!anodep) BUG();

            /* insert the checkpoint-based node */
            __journal_tree_insert(&anodep->pages, i, checkpoint,
                smmap_journal_page_t, alloc_page_node, pnodep);
            if (!pnodep) BUG();

            /* update pointer to the page */
            pnodep->spp = spp;
        }
    }
    journal->merge.isinit = true;

    return 0;
}

int smmap_journal_tree_destroy(smmap_journal_t *journal)
{
    struct rb_node *apos, *anext, *ppos, *pnext;

    if (!journal) return -EINVAL;

    if (!journal->merge.isinit) return 0;

    anext = rb_first(&journal->merge.tree);
    while (anext) {
        smmap_journal_addr_t *athis;

        /* advance the counter */
        apos = anext;
        anext = rb_next(apos);
        /* retrieve the element */
        athis = rb_entry(apos, smmap_journal_addr_t, node);

        /* drop the elements in the page tree, if any */
        pnext = rb_first(&athis->pages);
        while (pnext) {
            smmap_journal_page_t *pthis;

            /* advance the counter */
            ppos = pnext;
            pnext = rb_next(ppos);
            /* retrieve the element */
            pthis = rb_entry(ppos, smmap_journal_page_t, node);
            /* delete the element */
            smmap_page_free(&pthis->spp);
            rb_erase(&pthis->node, &athis->pages);
            free_page_node(pthis);
        }

        /* delete the element */
        rb_erase(&athis->node, &journal->merge.tree);
        free_addr_node(athis);
    }

    journal->merge.isinit = false;
    return 0;
}

static inline smmap_plist_t *smmap_journal_itol(smmap_journal_t *journal,
    int id)
{
    unsigned long inuse_addr = (unsigned long) journal->inuse;
    unsigned long cp_addr = (unsigned long) journal->checkpoints;
    int idx;

    id -= 1;
    idx = (int)((inuse_addr-cp_addr) / sizeof(smmap_plist_t));
    if (idx < 0) return ERR_PTR(-ERANGE);

    idx = (idx - id) % journal_size;
    idx = (idx < 0) ? idx + journal_size: idx;

    return &journal->checkpoints[idx];
}

static inline int __journal_tree_get_pages(smmap_journal_t *journal, int id,
    smmap_plist_t *outl)
{
    struct rb_node *next, *parent = NULL;
    char *event = "journal get pages";

    if (!journal || !outl) return -EINVAL;

    /* Iterate over all the pages and find the suitable checkpointed version,
       if any */
    next = rb_first(&journal->merge.tree);
    while (next) {
        smmap_journal_addr_t *addrp;
        smmap_page_t *spp = NULL;

        addrp = rb_entry(next, smmap_journal_addr_t, node);
        __journal_tree_search_page(addrp->pages, id, parent, spp);
        __journal_page_eval(spp, parent);

        if (spp) {
            smmap_page_t *tmpp = smmap_page_alloc();
            smmap_page_copy(tmpp, spp, true);
            smmap_plist_add(outl, tmpp, event);
        }

        next = rb_next(next);
    }

    return 0;
}

static inline int __journal_tree_get_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp)
{
    struct rb_node **new, *pparent = NULL;
    smmap_page_t *spp = NULL;
    long long cmp;

    if (!journal || !outp) return -EINVAL;

    new = &journal->merge.tree.rb_node;
    while (*new) {
        smmap_journal_addr_t *addrp;

        addrp = rb_entry(*new, smmap_journal_addr_t, node);
        cmp = addr - addrp->addr;

        if (cmp < 0) new = &(*new)->rb_left;
        else if (cmp > 0) new = &(*new)->rb_right;
        else {
            /* found the address, lets search for the right versions */
            __journal_tree_search_page(addrp->pages, id, pparent, spp);
            break;
        }
    }

    __journal_page_eval(spp, pparent);

    if (spp) {
        smmap_page_copy(outp, spp, true);
        return 1;
    }

    return 0;
}

static inline int smmap_journal_ltoi(smmap_journal_t *journal,
    smmap_plist_t *list)
{
    unsigned long list_addr = (unsigned long) list;
    unsigned long cp_addr = (unsigned long) journal->checkpoints;
    int index;

    index = (list_addr-cp_addr) / sizeof(smmap_plist_t);
    if (index < 0) return -ERANGE;

    return index;
}

static inline smmap_journal_addr_t *alloc_addr_node(void)
{
    smmap_journal_addr_t *node;

    node = kmem_cache_alloc(smmap_addr_node_cache, GFP_KERNEL);
    memset(node, 0, sizeof(smmap_journal_addr_t));

    return node;
}

static inline void free_addr_node(smmap_journal_addr_t *node)
{
    kmem_cache_free(smmap_addr_node_cache, node);
}

static inline smmap_journal_page_t *alloc_page_node(void)
{
    smmap_journal_page_t *node;

    node = kmem_cache_alloc(smmap_page_node_cache, GFP_KERNEL);
    memset(node, 0, sizeof(smmap_journal_page_t));

    return node;
}

static inline void free_page_node(smmap_journal_page_t *node)
{
    kmem_cache_free(smmap_page_node_cache, node);
}
