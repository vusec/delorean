#ifndef _SMMAP_DEDUPLICATE_H_
#define _SMMAP_DEDUPLICATE_H_

#include <linux/rbtree.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/list.h>

#define PAGE_STATS_SIZE 1024

typedef struct smmap_dedup_tree_s {
    struct rb_root root;
    spinlock_t lock;
} smmap_dedup_tree_t;

typedef struct smmap_crc_node_s {
    struct list_head list;
    smmap_cpage_t *cpage;
} smmap_dedup_crc_node_t;

typedef struct smmap_dedup_node_s {
    struct rb_node node;
    smmap_cpage_t *cpage;
    unsigned long crc;
    smmap_dedup_crc_node_t crc_pages;
    int frequency;
} smmap_dedup_node_t;

typedef struct smmap_page_freq_s {
    char string[PAGE_STATS_SIZE];
    int num_zeroed;
    int *frequencies;
    int size;
    int i;
} smmap_page_freq_t;

/* used by the checkpoint counter variant */
extern int smmap_dedup_cpcounter;
extern smmap_page_freq_t smmap_page_freq;

int smmap_dedup_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos);
int smmap_dedup_init(void);
void smmap_dedup_clear(void);
void smmap_dedup_clear_orphans(void);
void smmap_dedup_close(void);
void smmap_dedup_add(smmap_page_t *spp, struct page *pagep, unsigned long *crcp,
    bool is_fixup, bool is_cow);
int smmap_dedup_page_freq_sysctl(ctl_table *ctl, int write, void __user *buffer,
    size_t *lenp, loff_t *ppos);

#endif /* _SMMAP_DEDUPLICATE_H_ */
