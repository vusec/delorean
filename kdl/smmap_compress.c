/* smmap definitions */
#include <smmap_defs.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#include <linux/slab.h>
#include <linux/lzo.h>
#include <asm/unaligned.h>
#endif

static unsigned long used_mem = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
static const size_t max_zpage_size = PAGE_SIZE / 4 * 3;
/* use a lock to compress and use the buffers in a safe manner? */
static smmap_compress_tools_t tools = (smmap_compress_tools_t) {
    .pool = NULL, .workmem = NULL, .buffer = NULL };


int smmap_compress_init(void)
{
    int ret = 0;

    tools.workmem = kzalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
    if (!tools.workmem) {
        ret = -ENOMEM;
        goto out;
    }

    tools.buffer = (void *) __get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
    if (!tools.buffer) {
        ret = -ENOMEM;
        goto free_out;
    }

    tools.ctmp = (void *) kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!tools.ctmp) {
        ret = -ENOMEM;
        goto free_out;
    }

    tools.pool = zs_create_pool(GFP_ATOMIC);
    if (!tools.pool) {
        ret = -ENOMEM;
        goto free_out;
    }

    spin_lock_init(&tools.lock);

    goto out;

free_out:
    smmap_compress_close();
out:
    return ret;
}

void smmap_compress_close(void)
{
    if (tools.ctmp) {
        kfree(tools.ctmp);
        tools.ctmp = NULL;
    }

    if (tools.buffer) {
        free_pages((unsigned long) tools.buffer, 1);
        tools.buffer = NULL;
    }

    if (tools.workmem) {
        kfree(tools.workmem);
        tools.workmem = NULL;
    }

    if (tools.pool) {
        zs_destroy_pool(tools.pool);
        tools.pool = NULL;
    }
}

int smmap_compress_page(smmap_cpage_t *cpp)
{
    int ret = 0;
    unsigned long flags;
    bool needs_free = false;
    unsigned char *cmem, *buffer, *uncmem = NULL;
    bool is_compressed = smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED);
    bool is_locked = false;

    if (!cpp || !cpp->kpage) return -EINVAL;

    /* when the page is compressed already, there is nothing we need to do on
       the entry*/
    if (is_compressed) goto out;

    uncmem = kmap_atomic(cpp->kpage);

    if (page_zero_filled(uncmem)) {
        kunmap_atomic(uncmem);
        smmap_cpage_clear(cpp);
        smmap_flag_set(cpp, SMMAP_PAGE_FLAG_ZEROED);
        smmap_flag_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED);

        goto out;
    }

    /* lock to avoid concurrent access on workmem, buffer and memory pool */
    spin_lock_irqsave(&tools.lock, flags);
    is_locked = true;

    buffer = tools.buffer;
    lzo1x_1_compress(uncmem, PAGE_SIZE, buffer, &cpp->clen, tools.workmem);

    kunmap_atomic(uncmem);
    uncmem = NULL;

    if (unlikely(ret != LZO_E_OK)) {
        pr_err("Compression failed! err=%d\n", ret);
        ret = -EFAULT;
        goto out;
    }

    if (unlikely(cpp->clen >= max_zpage_size)) {
        cpp->clen = PAGE_SIZE;
        buffer = NULL;

    } else {
        unsigned long handle;
        size_t clen = cpp->clen;

        handle = zs_malloc(tools.pool, clen);
        if (!handle) {
            pr_info("Error allocating memory for compressed page: 0x%p, "
                "size=%zu\n", cpp->kpage, clen);
            cpp->clen = 0;
            ret = -ENOMEM;
            needs_free = true;
            goto out;
        }

        /* clear the cpage */
        smmap_cpage_clear(cpp);
        /* add the compression information */
        cpp->handle = handle;
        cpp->clen = clen;
        smmap_flag_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED);

        cmem = zs_map_object(tools.pool, handle, ZS_MM_WO);
        memcpy(cmem, buffer, clen);
        zs_unmap_object(tools.pool, handle);
    }

    /* Update statistics, if required */
    if (ret == 0) used_mem += cpp->clen;

out:
    if (needs_free)
        zs_free(tools.pool, cpp->handle);

    if (is_locked)
        spin_unlock_irqrestore(&tools.lock, flags);

    if (needs_free || ret) {
        cpp->handle = 0;
        cpp->clen = 0;
    }

    return ret;
}

int smmap_compress_free(smmap_cpage_t *cpp)
{
    unsigned long flags;

    if (!cpp)
        return -EINVAL;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED))
        return 0;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_ZEROED)) {
        spin_lock_irqsave(&tools.lock, flags);
        zs_free(tools.pool, cpp->handle);
        spin_unlock_irqrestore(&tools.lock, flags);
    }

    cpp->handle = 0;
    cpp->clen = 0;
    smmap_flag_reset(cpp, SMMAP_PAGE_FLAG_COMPRESSED);
    smmap_flag_reset(cpp, SMMAP_PAGE_FLAG_ZEROED);

    return 0;
}

int smmap_compress_get_page(smmap_cpage_t *cpp, struct page **outp)
{
    int ret;
    unsigned char *user_mem, *cmem;
    unsigned long flags;
    size_t len = PAGE_SIZE;

    if (!cpp || !outp) return -EINVAL;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED)) {
        /* to make sure that the page is not freed when returned by the caller
           we increase the counter here. */
        if (cpp->kpage) get_page(cpp->kpage);
        *outp = cpp->kpage;
        return 0;
    }

    /* a newly allocated page is set to zero. If the pae was zero-filed
       simply return  */
    if (smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_ZEROED)) {
        *outp = smmap_page_wq_retrieve(true);
        return 0;
    }

    *outp = smmap_page_wq_retrieve(false);
    if (!cpp->handle) BUG();

    /* lock to prevent concurrent access on tools */
    spin_lock_irqsave(&tools.lock, flags);

    /* otherwise, we need to uncompress the page and copy the uncompressed
       content in the the output page. */
    user_mem = kmap_atomic(*outp);
    cmem = zs_map_object(tools.pool, cpp->handle, ZS_MM_RO);
    ret = lzo1x_decompress_safe(cmem, cpp->clen, user_mem, &len);
    zs_unmap_object(tools.pool, cpp->handle);

    spin_unlock_irqrestore(&tools.lock, flags);

    if (unlikely(ret != LZO_E_OK)) {
        /* Should NEVER happen. At this point we know that the page was
           compressed, and we are keeping track of the compressed page. */
        pr_err("Decompression failed! err=%d, page=0x%p\n",
            ret, (void *) outp);
        smmap_page_wq_page_return(outp, false);
        kunmap_atomic(user_mem);
        BUG();
    }

    kunmap_atomic(user_mem);
    return 0;
}

int smmap_compress_cmp(smmap_cpage_t *lp, smmap_cpage_t *rp) {
    bool l_zeroed = smmap_flag_is_set(lp, SMMAP_PAGE_FLAG_ZEROED);
    bool r_zeroed = smmap_flag_is_set(rp, SMMAP_PAGE_FLAG_ZEROED);

    if (l_zeroed && r_zeroed) {
        return 0;

    } else if (!l_zeroed && !r_zeroed) {
        int ret;
        size_t clen = lp->clen;
        unsigned long flags;
        char *lcmem, *rcmem;

        if (lp->clen != rp->clen)
            return -1;

        /* at this point, compare the compressed memory areas
           NB: due to the way the compressed memory is managed by zsmalloc,
               two objects cannot be mapped at the same time on the same CPU.
               For this reason, we first copy the left object into a temporary
               page */
        spin_lock_irqsave(&tools.lock, flags);
        /* Copy the compressed data related to the left element */
        lcmem = zs_map_object(tools.pool, lp->handle, ZS_MM_RO);
        memcpy(tools.ctmp, lcmem, lp->clen);
        zs_unmap_object(tools.pool, lp->handle);

        /* compare the copied data with the right compressed element */
        rcmem = zs_map_object(tools.pool, rp->handle, ZS_MM_RO);
        ret = memcmp(tools.ctmp, rcmem, clen);
        zs_unmap_object(tools.pool, rp->handle);

        spin_unlock_irqrestore(&tools.lock, flags);

        return ret;
    }

    return -1;
}

void smmap_compress_size_sub(smmap_cpage_t *cpp) {
    if (used_mem > 0 && used_mem > cpp->clen)
        used_mem -= cpp->clen;
}


void smmap_compress_update_stats(void)
{
    SMMAP_STAT(compressed_size) = used_mem / 1024;
}

void smmap_compress_clear_stats(void)
{
    SMMAP_STAT(compressed_size) = 0;
    used_mem = 0;
}

#endif /* linux version >= 3.14 */

int page_zero_filled(void *ptr)
{
    unsigned int pos;
    unsigned long *page;

    page = (unsigned long *) ptr;
    for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
        if (page[pos]) return 0;
    }

    return 1;
}

int smmap_compress_conf_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos)
{
    int ret = 0;

    ret = proc_dointvec(table, write, buffer, lenp, p_pos);
    if (ret < 0) return ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
    if (write && SMMAP_CONF(compress) != COMPRESS_NONE) {
        printk(KERN_NOTICE "smmap: compression is not available on kernel "
            "prior to 3.14, since it depends on zmalloc. The request to "
            "enable compression will be ignored.\n");
        SMMAP_CONF(compress) = COMPRESS_NONE;
    }

#else
    if (write) {
        check_dedup_and_compress();
    }
#endif

    return ret;
}

int smmap_compress_stat_dointvec(struct ctl_table *table, int write,
    void __user *buffer, size_t *lenp, loff_t *p_pos)
{
    int ret;

    if (!write) {
        /* based on the updated local statistic, export the value size value
           in KB */
        SMMAP_STAT(compressed_size) = used_mem / 1024;
        ret = proc_dointvec(table, write, buffer, lenp, p_pos);
    } else {
        ret = proc_dointvec(table, write, buffer, lenp, p_pos);
        used_mem = SMMAP_STAT(compressed_size) * 1024;
    }

    return ret;
}
