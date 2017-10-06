#ifndef _SMMAP_JOURNAL_H_
#define _SMMAP_JOURNAL_H_

#include <smmap_page_list.h>
#include <smmap_page.h>

#define SMMAP_DEFAULT_JOURNAL_SIZE  0

typedef struct smmap_merge_node_s {
    struct rb_node node;
    unsigned long addr;
    struct rb_root pages;
} smmap_journal_addr_t;

typedef struct smmap_journal_page_s {
    struct rb_node node;
    int checkpoint;
    smmap_page_t *spp;
} smmap_journal_page_t;

typedef struct smmap_journal_s {
    smmap_plist_t *checkpoints; /* all the checkpoint dbs allowed by the
                                   window */
    smmap_plist_t *inuse; /* pointer to the selected db */
    int slots_used; /* number of slots used. Max value is the window size */
    /* used for page lookup */
    struct {
        struct rb_root tree;
        bool isinit;
    } merge;
} smmap_journal_t;

void smmap_journal_init(smmap_journal_t *journal);
void smmap_journal_destroy(smmap_journal_t *journal);
int smmap_journal_set_next(smmap_journal_t *journal);
int smmap_journal_add(smmap_journal_t *journal, smmap_page_t *spp);
int smmap_journal_get_pages(smmap_journal_t *journal, int id,
    smmap_plist_t *outl);
int smmap_journal_get_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp);
int smmap_journal_has_page(smmap_journal_t *journal, int id,
    unsigned long addr, smmap_page_t *outp);
bool smmap_journal_valid_id(smmap_journal_t *journal, int id);
/* userspace search utilities */
int smmap_journal_tree_populate(smmap_journal_t *journal);
int smmap_journal_tree_destroy(smmap_journal_t *journal);

#endif /* _SMMAP_JOURNAL_H_ */
