#ifndef _SMMAP_PAGE_LIST_H_
#define _SMMAP_PAGE_LIST_H_

#include <smmap_page.h>

typedef struct smmap_plist_node_s {
    struct list_head list;
    smmap_page_t *spp;
} smmap_plist_node_t;

typedef struct smmap_plist_s {
    struct list_head head;
    spinlock_t lock;
    size_t length;
    const char *label;
} smmap_plist_t;

struct smmap_proc_s;

/* initialization and deletion */
void smmap_plist_init(smmap_plist_t *list, const char *label);
void smmap_plist_node_init(void);
void smmap_plist_node_destroy(void);
/* element accessors */
size_t smmap_plist_size(smmap_plist_t *list, const char *event);
void smmap_plist_add(smmap_plist_t *list, smmap_page_t *smmap_page,
    const char *event);
void smmap_plist_add_or_replace(smmap_plist_t *list, smmap_page_t *smmap_page,
    const char *event);
void smmap_plist_clear(smmap_plist_t *list);
int smmap_plist_copy(smmap_plist_t *dst, smmap_plist_t *src, const char *event);
int smmap_plist_contains(smmap_plist_t *list, smmap_page_t **smmap_page,
    unsigned long addr, const char *event);
int smmap_plist_rcontains(smmap_plist_t *list, smmap_page_t **sp,
    unsigned long addr, const char *event);
int smmap_plist_empty(smmap_plist_t *list, const char *event);
/* iteration */
int smmap_plist_iter_next(smmap_plist_t *iterable, smmap_page_t **outp,
    const char *event);
void smmap_plist_clear_and_iter(smmap_plist_t *list, smmap_plist_t *iterable);
void smmap_plist_clone_and_iter(smmap_plist_t *list, smmap_plist_t *iterable);

#endif /* _SMMAP_PAGE_LIST_H_ */
