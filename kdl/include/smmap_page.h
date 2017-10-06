#ifndef _SMMAP_PAGE_H_
#define _SMMAP_PAGE_H_

#include <linux/mm.h>

/* pages which were retrieve from the process when rollbacking are placed
   inside a smmap_page struct and must be managed differently than pages
   copied on COWs */
#define SMMAP_PAGE_FLAG_IS_PRESENT      1<<0
#define SMMAP_PAGE_FLAG_SPECULATED      1<<1
/* set for present pages to prevent modifications to the page when plugged in */
#define SMMAP_PAGE_FLAG_IS_WRITE        1<<2

/* flags used for CPAGE */
#define SMMAP_PAGE_FLAG_ZEROED          1<<0
#define SMMAP_PAGE_FLAG_COMPRESSED      1<<1


typedef struct smmap_proc_s smmap_proc_t;

typedef struct smmap_cpage_s {
    struct page *kpage;
    unsigned long handle;
    size_t clen;
    unsigned char flags;
    atomic_t count;
} smmap_cpage_t;

typedef struct smmap_page_s {
    unsigned long addr;
    union {
        smmap_cpage_t *cpage;
        struct page *ppage;
    };
    smmap_proc_t *proc;
    unsigned long crc;
    unsigned char flags;
} smmap_page_t;

#define smmap_flag_is_set(__entry, __flag) \
    !!((__entry)->flags & (__flag))

#define smmap_flag_set(__entry, __flag) \
    (__entry)->flags |= (__flag)

#define smmap_flag_reset(__entry, __flag) \
    (__entry)->flags &= ~(__flag);

#define PRINT_SMMAP_PAGE(P) \
    DEBUG(DEBUG_L2, \
          "smmap page: {addr=0x%p, cpage=0x%p, speculated=%d, " \
          "from_proc=%d, is_write=%d}", (void *) (P)->addr, (P)->cpage, \
          smmap_flag_is_set(P, SMMAP_PAGE_FLAG_SPECULATED), \
          smmap_flag_is_set(P, SMMAP_PAGE_FLAG_IS_PRESENT), \
          smmap_flag_is_set(P, SMMAP_PAGE_FLAG_IS_WRITE))

#define PRINT_SMMAP_CPAGE(CP) \
    DEBUG(DEBUG_L2, \
        "smmap cpage: {kpage=0x%p, handle=%lu, zeroed=%d, compressed=%d, " \
        "count=%d}", (CP)->kpage, (CP)->handle, (CP)->clen, \
        smmap_flag_is_set(CP, SMMAP_PAGE_FLAG_ZEROED), \
        smmap_flag_is_set(CP, SMMAP_PAGE_FLAG_COMPRESSED), \
        atomic_read((CP)->count))

#define smmap_get_page(__p) get_page((__p)->cpage->kpage)
#define smmap_put_page(__p) put_page((__p)->cpage->kpage)

void smmap_page_init(void);
void smmap_page_close(void);

/* smmap page management */
smmap_page_t *smmap_page_alloc(void);
void smmap_page_reset(smmap_page_t *sp);
void smmap_page_free(smmap_page_t **page);
void smmap_page_copy(smmap_page_t *dst, smmap_page_t const *src,
    bool copy_page);
int smmap_page_copy_page(smmap_page_t *smmap_page, struct page *from_page,
    unsigned long *crc, bool is_cow);
void smmap_page_set_page(smmap_page_t *spp, struct page *page);
void smmap_page_unset_page(smmap_page_t *spp);
struct page *smmap_page_get_page(smmap_page_t *spp);
bool smmap_page_has_page(smmap_page_t *spp);
void smmap_page_set_cpage(smmap_page_t *spp, smmap_cpage_t *cpage);

/* present pages */
void smmap_page_set_ppage(smmap_page_t *spp, struct page *page);
struct page *smmap_page_get_ppage(smmap_page_t *spp);

/* cpage managmenet */
#define smmap_cpage_set(__node, __cpp) \
    do { \
        (__node)->cpage = __cpp; \
        smmap_cpage_get((__node)->cpage); \
    } while (0)

#define smmap_cpage_unset(__node) \
    do { \
        if ((__node)->cpage) { \
            smmap_cpage_put((__node)->cpage); \
            smmap_cpage_free(&(__node)->cpage); \
        } \
    } while (0)

#define smmap_cpage_get(__cpp) atomic_inc(&(__cpp)->count);
#define smmap_cpage_put(__cpp) atomic_dec(&(__cpp)->count);

smmap_cpage_t *smmap_cpage_alloc(void);
void smmap_cpage_free(smmap_cpage_t **cpp);
void smmap_cpage_clear(smmap_cpage_t *cpp);
void smmap_cpage_set_page(smmap_cpage_t *cpage, struct page *pagep);
struct page *smmap_cpage_get_page(smmap_cpage_t *cpage);
void smmap_cpage_unset_page(smmap_cpage_t *cpage);
bool smmap_cpage_has_page(smmap_cpage_t *cpage);
int smmap_cpage_compare(smmap_cpage_t *lp, smmap_cpage_t *rp);

/* utilities */
int smmap_page_test(smmap_page_t *spp, char *expected);
struct page *smmap_copy_page(struct page *from_page, unsigned long *crcp);
void get_highpage_crc(struct page *page, unsigned long *crc);
int memcmp_pages(struct page *page1, struct page *page2);

#endif /* _SMMAP_PAGE_H_ */
