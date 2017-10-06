#ifndef _SMMAP_COMPRESS_H_
#define _SMMAP_COMPRESS_H_

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#include <linux/zsmalloc.h>
#endif

#include <linux/mm_types.h>
#include <smmap/smmap_common.h>
#include <smmap_page.h>

typedef struct smmap_compress_tools_s {
    struct zs_pool *pool;
    void *workmem;
    void *buffer;
    void *ctmp;
    spinlock_t lock;
} smmap_compress_tools_t;

int smmap_compress_conf_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos);
int smmap_compress_stat_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos);
int page_zero_filled(void *ptr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
int smmap_compress_init(void);
void smmap_compress_close(void);

int smmap_compress_page(smmap_cpage_t *cpp);
int smmap_compress_get_page(smmap_cpage_t *cpp, struct page **pagep);
int smmap_compress_free(smmap_cpage_t *cpp);
int smmap_compress_cmp(smmap_cpage_t *lp, smmap_cpage_t *rp);
void smmap_compress_size_sub(smmap_cpage_t *cpp);
void smmap_compress_update_stats(void);
void smmap_compress_clear_stats(void);

#else
#define smmap_compress_init()
#define smmap_compress_close()
#define smmap_compress_page(__cpp) (0)
#define smmap_compress_get_page(__cpp, __pagep) (0)
#define smmap_compress_free(__cpp) (0)
#define smmap_compress_cmp(__lp, __rp) (-1)
#define smmap_compress_size_sub(__cpp)
#define smmap_compress_read_size() (0)
#define smmap_compress_update_stats()
#define smmap_compress_clear_stats()
#endif

#endif /* _SMMAP_COMPRESS_H_ */
