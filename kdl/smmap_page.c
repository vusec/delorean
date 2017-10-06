#include <smmap_defs.h>

#include <linux/list.h>
#include <linux/slab.h>

static struct kmem_cache *smmap_page_cachep;
static struct kmem_cache *smmap_cpage_cachep;
static void copy_highpage_crc(struct page *to, struct page *from,
    unsigned long *crc);

void smmap_page_init(void)
{
    smmap_page_cachep = kmem_cache_create("smmap_page_cache",
            sizeof(smmap_page_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

    smmap_cpage_cachep = kmem_cache_create("smmap_cpage_cache",
            sizeof(smmap_cpage_t), 0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
}

smmap_cpage_t *smmap_cpage_alloc(void)
{
    smmap_cpage_t *cpp;

    cpp =  kmem_cache_alloc(smmap_cpage_cachep, GFP_ATOMIC);
    memset(cpp, 0, sizeof(smmap_cpage_t));
    return cpp;
}

void smmap_cpage_free(smmap_cpage_t **cpp)
{
    if (!cpp || !*cpp) return;

    DEBUG(DEBUG_L2, "Attempting to free cpage 0x%p", *cpp);
    if (atomic_read(&(*cpp)->count) > 0) return;

    smmap_cpage_clear(*cpp);

    DEBUG(DEBUG_L2, "Freeing cpage 0x%p", *cpp);
    kmem_cache_free(smmap_cpage_cachep, *cpp);
    *cpp = NULL;
}

void smmap_cpage_clear(smmap_cpage_t *cpp)
{
    int ret;

    if (!cpp) return;

    if (smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED)) {
        if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_ZEROED)) {
            ret = smmap_compress_free(cpp);
            if (ret < 0) BUG();
        }
    } else if (cpp->kpage) {
        smmap_cpage_unset_page(cpp);
    }

    /* clear flags */
    cpp->flags = 0;
}

void smmap_page_close(void)
{
    if (smmap_page_cachep)
        kmem_cache_destroy(smmap_page_cachep);

    if (smmap_cpage_cachep)
        kmem_cache_destroy(smmap_cpage_cachep);
}

void smmap_page_reset(smmap_page_t *spp)
{
    memset(spp, 0, sizeof(smmap_page_t));
}

smmap_page_t *smmap_page_alloc(void)
{
    smmap_page_t *spp;

    spp =  kmem_cache_alloc(smmap_page_cachep, GFP_ATOMIC);
    smmap_page_reset(spp);
    return spp;
}

void smmap_page_free(smmap_page_t **spp)
{
    if (!spp) return;

    smmap_page_unset_page(*spp);
    kmem_cache_free(smmap_page_cachep, *spp);
    *spp = NULL;
}

struct page *smmap_copy_page(struct page *from_page, unsigned long *crcp)
{
    struct page *to_page;

    /* retrieve a page from our cache */
    to_page = smmap_page_wq_retrieve(false);
    if (to_page == NULL) return ERR_PTR(-ENOMEM);

    /* copy the content of the page and assign it to the smmap page */
    if (crcp == NULL) copy_highpage(to_page, from_page);
    else copy_highpage_crc(to_page, from_page, crcp);

    return to_page;
}

/**
 * smmap_page_copy_page - copy a page when COW or speculation is triggered
 * @spp: pointer to the smmap_page struct which will contain the new page
 * @from_page: the page to be copied
 * @crcp: if crcp is not NULL, the checksum will be computed and stored in crcp
 *
 * Returns 0 on success, a negative value on error
 */
int smmap_page_copy_page(smmap_page_t *spp, struct page *from_page,
    unsigned long *crcp, bool is_cow)
{
    int ret = 0;
    bool do_dedup = SMMAP_CONF(dedup_type) > DEDUP_TYPE_NONE &&
            !(is_cow &&  SMMAP_CONF(dedup_location) == DEDUP_LOCATION_SPEC);

    if (!spp || !from_page)
        return -EINVAL;

    SMMAP_STAT_INC(num_total_pages);

    if (!do_dedup) {
        struct page *to_page = NULL;

        /* Do the copying */
        to_page = smmap_copy_page(from_page, crcp);
        if (IS_ERR(to_page)) return PTR_ERR(to_page);
        smmap_page_set_page(spp, to_page);
        PRINT_SMMAP_PAGE(spp);

    } else {
        smmap_dedup_add(spp, from_page, crcp, false, is_cow);
    }

    return ret;
}

/**
 * smmap_page_copy - copy an smmap_page content into another one
 * @dst: smmap page that will be populated
 * @src: smmap page from where to get the values
 * @copy_page: flag to decide whether to copy the page reference
 */
void smmap_page_copy(smmap_page_t *dst, smmap_page_t const *src, bool copy_page)
{
    /* copy the content of the smmap_page_t */
    memcpy(dst, src, sizeof(smmap_page_t));
    if (copy_page) {
        /* At this point, the cpage was already copied, since the destination
           entry now has the same pointer value. Just increase the counter. */
        smmap_cpage_get(dst->cpage);
    } else {
        dst->cpage = NULL;
    }
}

/*
 * smmap_set_page - set a new page into the smmap page struct
 * @spp: smmap page in which the page is set
 * @page: the page to be set. NB: this action will increase the reference count
 *        of the page since a new smmap page now owns a reference to it.
 */
void smmap_page_set_page(smmap_page_t *spp, struct page *pagep)
{
    if (!spp || !pagep) return;

    if (!spp->cpage) {
        spp->cpage = smmap_cpage_alloc();
        smmap_cpage_get(spp->cpage);
    }
    smmap_cpage_set_page(spp->cpage, pagep);
}

/**
 * smmap_unset_page - remove reference to the pointed page. This function has
 *                    to be called each time a smmap_page is either destroyed
 *                    or it exits the scope in which is held.
 * @spp: smmap page from which the page should be removed. NB: the reference
 *       count of the page will be decreased or, possibly, the page will be
 *       freed if the reference count drops.
 */
void smmap_page_unset_page(smmap_page_t *spp)
{
    if (!spp) return;

    if (smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_IS_PRESENT && spp->ppage)) {
        put_page(spp->ppage);
        spp->ppage = NULL;
    } else {
        smmap_cpage_unset(spp);
    }

    /* clear the flags */
    spp->flags = 0;
}

struct page *smmap_page_get_page(smmap_page_t *spp)
{
    if (!spp) BUG();

    return smmap_cpage_get_page(spp->cpage);
}

bool smmap_page_has_page(smmap_page_t *spp)
{
    if (!spp) return false;

    if (smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_IS_PRESENT)) return !!spp->ppage;
    else return smmap_cpage_has_page(spp->cpage);
}

/**
 * smmap_page_set_ppage - set present pages.
 *
 * @spp: smmap_page_t container that will containt the present page
 * @page: the page unplugged from the running process
 */
void smmap_page_set_ppage(smmap_page_t *spp, struct page *page)
{
    if (!spp) BUG();

    smmap_flag_set(spp, SMMAP_PAGE_FLAG_IS_PRESENT);
    spp->ppage = page;
    get_page(page);
}

struct page *smmap_page_get_ppage(smmap_page_t *spp)
{
    if (!spp || !smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_IS_PRESENT))
        BUG();

    return spp->ppage;
}

/**
 * smmap_page_set_cpage - sets a cpage in a smmap_page_t object. If the object
 *                        already points to a cpage, the cpage is un-set before
 *                        placing the new one.
 */
void smmap_page_set_cpage(smmap_page_t *spp, smmap_cpage_t *cpage)
{
    if (!spp || !cpage) BUG();

    if (spp->cpage)
        smmap_cpage_unset(spp);

    smmap_cpage_set(spp, cpage);
}

int smmap_cpage_compare(smmap_cpage_t *lp, smmap_cpage_t *rp)
{
    bool l_compressd = smmap_flag_is_set(lp, SMMAP_PAGE_FLAG_COMPRESSED);
    bool r_compressd = smmap_flag_is_set(rp, SMMAP_PAGE_FLAG_COMPRESSED);

    if (!l_compressd && !r_compressd)
        return memcmp_pages(lp->kpage, rp->kpage);
    else if (l_compressd && r_compressd)
        return smmap_compress_cmp(lp, rp);

    return -1;
}

void smmap_cpage_set_page(smmap_cpage_t *cpage, struct page *pagep)
{
    if (!cpage || !pagep) BUG();

    if (cpage->kpage) smmap_cpage_unset_page(cpage);

    cpage->kpage = pagep;
    get_page(cpage->kpage);
}

struct page *smmap_cpage_get_page(smmap_cpage_t *cpp)
{
    int ret;
    struct page *pagep = NULL;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED)) {
        return cpp->kpage;

    } else {
        ret = smmap_compress_get_page(cpp, &pagep);
        if (ret < 0) return ERR_PTR(ret);

        return pagep;
    }
}

void smmap_cpage_unset_page(smmap_cpage_t *cpage)
{
    if (!cpage->kpage) return;

    put_page(cpage->kpage);
    smmap_page_wq_page_return(&cpage->kpage, 0);
    cpage->kpage = NULL;
}

bool smmap_cpage_has_page(smmap_cpage_t *cpp)
{
    if (!cpp) return false;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED)) {
        return !!cpp->kpage;

    } else {
        if (smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_ZEROED)) return true;
        else return !!cpp->handle;
    }
}

/**
 * copy_highpage_crc - copy highpage computing the crc while copying
 * @to: page to which to copy
 * @from: page from which to copy
 * @crc: resulting checksum
 */
static inline void copy_highpage_crc(struct page *to, struct page *from,
    unsigned long *crc)
{
    char *vfrom, *vto;
    unsigned long _crc = 0;
    int len = PAGE_SIZE;

    unsigned long _src;
    unsigned long _dst;

    vfrom = kmap_atomic(from);
    vto = kmap_atomic(to);

    _src = ((unsigned long) vfrom); //+ PAGE_SIZE - 8 * sizeof(unsigned long);
    _dst = ((unsigned long) vto);   //+ PAGE_SIZE - 8 * sizeof(unsigned long);

    while (len) {
        unsigned long *__dst = (unsigned long* ) _dst;
        unsigned long *__src = (unsigned long *) _src;
        *__dst = *(unsigned long *)_dst;

        __dst[0] = __src[0];
        __dst[1] = __src[1];
        __dst[2] = __src[2];
        __dst[3] = __src[3];
        __dst[4] = __src[4];
        __dst[5] = __src[5];
        __dst[6] = __src[6];
        __dst[7] = __src[7];
        __dst[8] = __src[8];
        __dst[9] = __src[9];
        __dst[10] = __src[10];
        __dst[11] = __src[11];
        __dst[12] = __src[12];
        __dst[13] = __src[13];
        __dst[14] = __src[14];
        __dst[15] = __src[15];

        _crc += __src[0];
        _crc += __src[1];
        _crc += __src[2];
        _crc += __src[3];
        _crc += __src[4];
        _crc += __src[5];
        _crc += __src[6];
        _crc += __src[7];
        _crc += __src[8];
        _crc += __src[9];
        _crc += __src[10];
        _crc += __src[11];
        _crc += __src[12];
        _crc += __src[13];
        _crc += __src[14];
        _crc += __src[15];
        _dst += 16 * sizeof(unsigned long);
        _src += 16 * sizeof(unsigned long);
        len  -= 16 * sizeof(unsigned long);
    }
    *crc = _crc;

    kunmap_atomic(vto);
    kunmap_atomic(vfrom);
}

static int smmap_cpage_test(smmap_cpage_t *cpp, char *expected)
{
    int ret;
    char *paddr;

    if (!cpp) return -1;

    if (!smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_COMPRESSED)) {
        if (!cpp->kpage) return -1;

        paddr = kmap_atomic(cpp->kpage);
        ret = memcmp(paddr, (void *) expected, PAGE_SIZE);
        kunmap_atomic(paddr);

    } else {
        if (smmap_flag_is_set(cpp, SMMAP_PAGE_FLAG_ZEROED)) {
            /* this function follows the sematic imposed by memcmp. This means
               that if the page is zero-filled, and the function below returns
               true (or false), hence 1 (or 0), we need to return 0 (or 1) */
            ret = !page_zero_filled(expected);
        } else {
            struct page *pagep = NULL;

            /* decompress the page */
            ret = smmap_compress_get_page(cpp, &pagep);
            if (ret < 0) goto out;

            /* compare the content */
            paddr = kmap_atomic(pagep);
            ret = memcmp(paddr, (void *) expected, PAGE_SIZE);
            kunmap_atomic(paddr);

            /* drop the page */
            smmap_page_wq_page_return(&pagep, false);
        }
    }

out:
    return ret;
}

int smmap_page_test(smmap_page_t *spp, char *expected)
{
    int ret;

    if (!spp) return -1;

    ret = smmap_cpage_test(spp->cpage, expected);

    return ret;
}

/**
 * get_highpage_crc - get highpage crc
 * @page: page from which to obtain the crc
 * @crc: resulting checksum
 */
void get_highpage_crc(struct page *page, unsigned long *crc)
{
    char *vpage;
    unsigned long _crc = 0;
    int len = PAGE_SIZE;
    unsigned long _page;

    vpage = kmap_atomic(page);

    _page = (unsigned long) vpage;

    while (len) {
        unsigned long *__page = (unsigned long *) _page;

        _crc += __page[0];
        _crc += __page[1];
        _crc += __page[2];
        _crc += __page[3];
        _crc += __page[4];
        _crc += __page[5];
        _crc += __page[6];
        _crc += __page[7];
        _crc += __page[8];
        _crc += __page[9];
        _crc += __page[10];
        _crc += __page[11];
        _crc += __page[12];
        _crc += __page[13];
        _crc += __page[14];
        _crc += __page[15];
        _page += 16 * sizeof(unsigned long);
        len -= 16 * sizeof(unsigned long);
    }
    *crc = _crc;

    kunmap_atomic(vpage);
}

int memcmp_pages(struct page *page1, struct page *page2)
{
    char *addr1, *addr2;
    int ret;

    if (page1 == NULL || page2 == NULL)
        BUG();
    addr1 = kmap_atomic(page1);
    addr2 = kmap_atomic(page2);
    ret = memcmp(addr1, addr2, PAGE_SIZE);
    kunmap_atomic(addr2);
    kunmap_atomic(addr1);
    return ret;
}
