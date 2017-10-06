#include <smmap_page_list.h>
#include <smmap_page.h>
#include <smmap_defs.h>

#include <linux/list.h>
#include <linux/slab.h>

static struct kmem_cache *smmap_plist_node_cachep = NULL;

void smmap_plist_node_init(void)
{
    smmap_plist_node_cachep = kmem_cache_create(
                  "smmap_page_list_meta",           /* Name */
                  sizeof(smmap_plist_node_t),       /* Object Size */
                  0,                                /* Alignment */
                  SLAB_HWCACHE_ALIGN|SLAB_PANIC,    /* Flags */
                  NULL);                            /* Constructor */
}

void smmap_plist_node_destroy(void)
{
    if (smmap_plist_node_cachep)
        kmem_cache_destroy(smmap_plist_node_cachep);
}

smmap_plist_node_t *smmap_plist_node_alloc(void)
{
    smmap_plist_node_t *nodep;

    nodep =  kmem_cache_alloc(smmap_plist_node_cachep, GFP_ATOMIC);
    memset(nodep, 0, sizeof(smmap_plist_node_t));
    return nodep;
}

void smmap_plist_node_free(smmap_plist_node_t **nodep)
{
    kmem_cache_free(smmap_plist_node_cachep, *nodep);
    *nodep = NULL;
}

void smmap_plist_init(smmap_plist_t *list, const char *label)
{
    INIT_LIST_HEAD(&list->head);
    spin_lock_init(&list->lock);
    list->length = 0;
    list->label = label;
}

size_t smmap_plist_size(smmap_plist_t *list, const char *event)
{
    unsigned long flags;
    size_t length;

    if (!list) return 0;

    spin_lock_irqsave(&list->lock, flags);
    length = list->length;
    spin_unlock_irqrestore(&list->lock, flags);

    return length;
}

void smmap_plist_add(smmap_plist_t *list, smmap_page_t *spp, const char *event)
{
    unsigned long flags;
    smmap_plist_node_t *nodep = smmap_plist_node_alloc();

    if (!list || !spp) return;

    nodep->spp = spp;

    spin_lock_irqsave(&list->lock, flags);
    list_add(&nodep->list, &list->head);
    list->length += 1;
    spin_unlock_irqrestore(&list->lock, flags);

    DEBUG(DEBUG_L1, "(%s-%s) addr=0x%p", event, list->label,
        (void *) nodep->spp->addr);
}


/**
 * smmap_plist_add_or_replace - adds a smmap_page to the list. If an smmap_page
 *                              associated to the same address is found in the
 *                              list, it is replaced with the new user-provided
 *                              page.
 * @list: destination list to which the page will be added
 * @smmap_page: new page container
 */
void smmap_plist_add_or_replace(smmap_plist_t *list, smmap_page_t *spp,
    const char *event)
{
    unsigned long flags;
    smmap_plist_node_t *old_nodep, *new_nodep;

    if (!list || !spp) return;

    new_nodep = smmap_plist_node_alloc();
    new_nodep->spp = spp;

    DEBUG(DEBUG_L1, "(%s-%s) addr=0x%p", event, list->label,
        (void *) new_nodep->spp->addr);

    /* Search for an element associated to the same address. If we find one,
       replace it, otherwise add the element to the list */
    spin_lock_irqsave(&list->lock, flags);
    list_for_each_entry(old_nodep, &list->head, list) {
        DEBUG(DEBUG_L2, "(%s-%s) comparing addr=0x%p and addr=0x%p", event,
            list->label, (void *) new_nodep->spp->addr,
            (void *) old_nodep->spp->addr);

        if (old_nodep->spp->addr == new_nodep->spp->addr) {
            DEBUG(DEBUG_L2, "(%s-%s) replace page with new checkpointed page "
                "addr=0x%p", event, list->label, (void *) new_nodep->spp->addr);
            list_replace(&old_nodep->list, &new_nodep->list);
            /* Return the page and return the old container */
            smmap_page_free(&old_nodep->spp);
            smmap_plist_node_free(&old_nodep);
            goto unlock;
        }
    }
    /* if the element was not replaced, the new page is added to the list */
    list_add(&new_nodep->list, &list->head);
    list->length += 1;
    DEBUG(DEBUG_L2, "(%s-%s) added page addr=0x%p", event, list->label,
        (void *) new_nodep->spp->addr);

unlock:
    spin_unlock_irqrestore(&list->lock, flags);
}

void smmap_plist_clear(smmap_plist_t *list)
{
    smmap_plist_t iterable;
    smmap_page_t *spp;

    smmap_plist_clear_and_iter(list, &iterable);
    while (smmap_plist_iter_next(&iterable, &spp, "clear"))
        smmap_page_free(&spp);

    DEBUG(DEBUG_L2, "(clear) cleared list");
}

/**
 * smmap_plist_copy - deep copy the content of one list into another list.
 *                    The smmap_page_t objects are duplicated while the
 *                    struct page elements are shared.
 * @dst: the list to where the pages will be copied. The function does not
 *       require this list to be empty. If the function already contains
 *       elements, it will be extended with the new ones.
 *       The list must be already initialized and during this operation is not
 *       locked, so make sure there is no contention on it.
 * @src: the list from where the copy is performed
 * @event: type of event for logging messages.
 *
 * Returns the number of elements copied or a negative value in case of error.
 */
int smmap_plist_copy(smmap_plist_t *dst, smmap_plist_t *src, const char *event)
{
    unsigned long flags;
    smmap_plist_node_t *src_node, *dst_node;

    if (!dst || !src) return -EINVAL;

    /* if none of the conditions above applied, copy the list */
    DEBUG(DEBUG_L1, "(%s)", event);

    spin_lock_irqsave(&src->lock, flags);
    list_for_each_entry_reverse(src_node, &src->head, list) {
        dst_node = smmap_plist_node_alloc();
        dst_node->spp = smmap_page_alloc();
        smmap_page_copy(dst_node->spp, src_node->spp, true);
        list_add(&dst_node->list, &dst->head);
        dst->length += 1;
    }
    spin_unlock_irqrestore(&src->lock, flags);

    return dst->length;
}


/**
 * smmap_plist_contains - check if the list contains the requested address
 *
 * @list: list in which to search fo the address
 * @sp: if not NULL, this will point to the found smmap_page
 * @addr: address to look for
 * @event: event description for debugging purpose
 * 
 * Returns 1 when the page was found, 0 if the page was not found, and a
 * negative value on error.
 */
int smmap_plist_contains(smmap_plist_t *list, smmap_page_t **sp,
        unsigned long addr, const char *event)
{
    smmap_plist_node_t *iter;
    unsigned long flags;
    int found = 0;

    if (!list) return -EINVAL;

    DEBUG(DEBUG_L2, "(%s - %s) addr=0x%p", event, list->label, (void *) addr);

    spin_lock_irqsave(&list->lock, flags);
    list_for_each_entry(iter, &list->head, list) {
        DEBUG(DEBUG_L2, "(%s - %s) comparing addr=0x%p and addr=0x%p", event,
            list->label, (void *) addr, (void *) iter->spp->addr);

        if (iter->spp->addr == addr) {
            if (sp != NULL) *sp = iter->spp;
            found = 1;
	        DEBUG(DEBUG_L1, "(%s - %s) found addr=0x%p", event, list->label,
                (void *) addr);
            break;
        }
    }
    spin_unlock_irqrestore(&list->lock, flags);

    return found;
}

int smmap_plist_rcontains(smmap_plist_t *list, smmap_page_t **sp,
        unsigned long addr, const char *event)
{
    smmap_plist_node_t *iter;
    unsigned long flags;
    int found = 0;

    if (!list) return -EINVAL;

    DEBUG(DEBUG_L2, "(%s - %s) addr=0x%p", event, list->label, (void *) addr);

    spin_lock_irqsave(&list->lock, flags);
    list_for_each_entry_reverse(iter, &list->head, list) {
        DEBUG(DEBUG_L2, "(%s - %s) comparing addr=0x%p and addr=0x%p", event,
            list->label, (void *) addr, (void *) iter->spp->addr);

        if (iter->spp->addr == addr) {
            if (sp != NULL) *sp = iter->spp;
            found = 1;
	        DEBUG(DEBUG_L1, "(%s - %s) found addr=0x%p", event, list->label,
                (void *) addr);
            break;
        }
    }
    spin_unlock_irqrestore(&list->lock, flags);

    return found;
}

int smmap_plist_empty(smmap_plist_t *list, const char *event)
{
    int res;
    unsigned long flags;

    if (!list) return -EINVAL;
    
    spin_lock_irqsave(&list->lock, flags);
    res = list_empty(&list->head);
    spin_unlock_irqrestore(&list->lock, flags);

    return res;
}

/**
 * smmap_plist_iter_next - retrive the next element in the list. The function
 *                         Drops the reference to the page when copying
 *                         the content of the smmap_page.
 *                         The function avoids locking the list so make sure
 *                         that the list is not subject of contention.
 *
 * @iter: the pointer to the single element list containing the next element
 * @event: label describing the context of the caller (debugging purposes only)
 *
 * Returns 1 when a new element is available, 0 when no new elements are
 * available
 */
int smmap_plist_iter_next(smmap_plist_t *iterable, smmap_page_t **outp,
    const char *event)
{
    smmap_plist_node_t *nodep;

    if (!iterable || !outp) return -EINVAL;

    if (list_empty(&iterable->head)) return 0;

    /* retrieve the first element from the list */
    nodep = list_first_entry(&iterable->head, smmap_plist_node_t, list);
    *outp = nodep->spp;
    /* Delete the odl object and free the node */
    list_del(&nodep->list);
    iterable->length -= 1;
    smmap_plist_node_free(&nodep);

    DEBUG(DEBUG_L1, "(%s) addr=0x%p", event, (void *) (*outp)->addr);
    return 1;
}

/**
 * smmap_plist_clear_and_iter - prepare an iterable list from a list which is
 *                              the deleted.
 *
 * @list: original list
 * @iterable: resalting iterable list
 */
void smmap_plist_clear_and_iter(smmap_plist_t *list, smmap_plist_t *iterable)
{
    unsigned long flags;

    DEBUG(DEBUG_L1, "Clearing (%s)", list->label);

    /* initialize the iterable list */
    smmap_plist_init(iterable, "clear-iter");

    /* clear and prepare the iterable list */
    spin_lock_irqsave(&list->lock, flags);
    list_cut_position(&iterable->head, &list->head, list->head.prev);
    iterable->length = list->length;
    list->length = 0;
    spin_unlock_irqrestore(&list->lock, flags);
}

void smmap_plist_clone_and_iter(smmap_plist_t *list, smmap_plist_t *iterable)
{
    unsigned long flags;
    smmap_plist_node_t *origp, *clonep;

    DEBUG(DEBUG_L1, "Cloning (%s)", list->label);

    /* initialize the iterable list */
    smmap_plist_init(iterable, "clone-iter");

    /* clone the list into the iterable one */
    spin_lock_irqsave(&list->lock, flags);
    INIT_LIST_HEAD(&iterable->head);
    list_for_each_entry(origp, &list->head, list) {
        clonep = smmap_plist_node_alloc();
        clonep->spp = smmap_page_alloc();
        smmap_page_copy(clonep->spp, origp->spp, true);
        list_add(&clonep->list, &iterable->head);
    }
    iterable->length = list->length;
    spin_unlock_irqrestore(&list->lock, flags);
}
