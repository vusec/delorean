#ifndef _SMMAP_PAGE_WQ_H_
#define _SMMAP_PAGE_WQ_H_

#include <linux/kfifo.h>

/* these values are assumed per-process */
#define SMMAP_DEFAULT_MAX_PAGES         0 /* by default, we use atomic pages */

typedef struct smmap_page_wq_s {
    DECLARE_KFIFO_PTR(fifo, struct page *);
    atomic_t expanding;
} smmap_page_wq_t;

void smmap_page_wq_init(void);
void smmap_page_wq_close(void);
struct page *smmap_page_wq_retrieve(bool fill_zeros);
int smmap_page_wq_return(smmap_page_t *smmap_page);
int smmap_page_wq_page_return(struct page **page, bool is_from_proc);

#endif /* _SMMAP_PAGE_WQ_H_ */
