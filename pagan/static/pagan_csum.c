#include <common/pagan/pagan.h>
#include "pagan_uthash.h"


typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	unsigned long csum;
	int misses;
	UT_hash_handle hh;
} pagan_csum_page_t;

typedef struct pagan_csum_proc_handle_s {
	pagan_csum_page_t *csum_list;
	int miss_treshold;
} pagan_csum_proc_handle_t;

static void *pagan_csum_page_add(void *handle, void *addr, void *priv)
{
	pagan_csum_proc_handle_t *h = (pagan_csum_proc_handle_t *) handle;
	pagan_csum_page_t *p = NULL;
    void *old_priv = NULL;

	HASH_FIND_PTR(h->csum_list, &addr, p);
	pagan_debug(PAGAN_DEBUG_INFO, "page add: %p\n", addr);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_csum_page_t));
		pagan_assert(p != NULL);
		memset(p, 0, sizeof(pagan_csum_page_t));
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->csum_list, addr, p);
	} else {
        old_priv = p->user_priv;
        p->user_priv = priv;
    }
    return old_priv;
}


static void pagan_csum_page_del(void *handle, void *addr) 
{
	pagan_csum_proc_handle_t *h = (pagan_csum_proc_handle_t *) handle;
	pagan_csum_page_t *p = NULL;
	HASH_FIND_PTR(h->csum_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	HASH_DEL(h->csum_list, p);
	pagan_free(p);
}



static void pagan_csum_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	/* in csum scheme,we grow the working set constantly and never
	 * discard pages from the working set */
	pagan_csum_proc_handle_t *h = (pagan_csum_proc_handle_t *) handle;
	pagan_csum_page_t *p, *tmp = NULL;

	HASH_ITER(hh, h->csum_list, p, tmp) {
		if(p->misses > h->miss_treshold) {
			pagan_debug(PAGAN_DEBUG_INFO, "page discard: %p\n", p->addr);
			discard(p->addr, p->user_priv);
            destroy(p->user_priv);
			HASH_DEL(h->csum_list, p);
			pagan_free(p);
		} else {
			unsigned long csum;
			save(p->addr, p->user_priv, &csum);
			if (csum == p->csum) {
				p->misses++;
			} else {
				p->misses = 0;
				p->csum = csum;
			}
		}
	}
}

static void pagan_csum_read_conf(pagan_csum_proc_handle_t *h)
{
	h->miss_treshold = pagan_get_conf_or_default(
		"CSUM_MISS_TRESHOLD",
		5);
}

static void *pagan_csum_init(void)
{
	pagan_csum_proc_handle_t *h = pagan_malloc(sizeof(pagan_csum_proc_handle_t));
	pagan_assert(h!=NULL);
	h->csum_list = NULL;
	pagan_csum_read_conf(h);
	return h;
}


static void pagan_csum_deinit(void *handle, page_destroy_handler_t destroy_cb) 
{
	pagan_csum_proc_handle_t *h = (pagan_csum_proc_handle_t *) handle;
	pagan_csum_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->csum_list, p, tmp) {
		HASH_DEL(h->csum_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_csum_mechanism = {
	"csum",
	pagan_csum_page_add,
	pagan_csum_page_del,
	pagan_csum_process,
	pagan_csum_init,
	pagan_csum_deinit
};


