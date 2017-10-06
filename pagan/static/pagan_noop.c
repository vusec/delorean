#include <common/pagan/pagan.h>
#include "pagan_uthash.h"


typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	UT_hash_handle hh;
} pagan_noop_page_t;

typedef struct pagan_noop_proc_handle_s {
	pagan_noop_page_t *noop_list;
	unsigned long pagan_noop_list_len;
} pagan_noop_proc_handle_t;

static void *pagan_noop_page_add(void *handle, void *addr, void *priv)
{
	pagan_noop_proc_handle_t *h = (pagan_noop_proc_handle_t *) handle;
	pagan_noop_page_t *p = NULL;
    void *old_priv = NULL;
	HASH_FIND_PTR(h->noop_list, &addr, p);
	pagan_debug(PAGAN_DEBUG_INFO, "page add: %p\n", addr);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_noop_page_t));
		pagan_assert(p != NULL);
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->noop_list, addr, p);
		h->pagan_noop_list_len++;
	} else {
		old_priv = p->user_priv;
		p->user_priv = priv;
    }
    return old_priv;
}


static void pagan_noop_page_del(void *handle, void *addr) 
{
	pagan_noop_proc_handle_t *h = (pagan_noop_proc_handle_t *) handle;
	pagan_noop_page_t *p = NULL;
	HASH_FIND_PTR(h->noop_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->pagan_noop_list_len--;
	HASH_DEL(h->noop_list, p);
	pagan_free(p);
}


static void pagan_noop_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	pagan_noop_proc_handle_t *h = (pagan_noop_proc_handle_t *) handle;
	pagan_noop_page_t *p, *tmp = NULL;

	HASH_ITER(hh, h->noop_list, p, tmp) {
		pagan_debug(PAGAN_DEBUG_INFO, "page discard: %p\n", p->addr);
		discard(p->addr, p->user_priv);
		destroy(p->user_priv);
		HASH_DEL(h->noop_list, p);
		pagan_free(p);
		h->pagan_noop_list_len--;
	}
}


static void *pagan_noop_init(void)
{
	pagan_noop_proc_handle_t *h = pagan_malloc(sizeof(pagan_noop_proc_handle_t));
	pagan_assert(h!=NULL);
	h->noop_list = NULL;
	h->pagan_noop_list_len = 0;
	return h;
}


static void pagan_noop_deinit(void *handle, page_destroy_handler_t destroy_cb)
{
	pagan_noop_proc_handle_t *h = (pagan_noop_proc_handle_t *) handle;
	pagan_noop_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->noop_list, p, tmp) {
		HASH_DEL(h->noop_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_noop_mechanism = {
	"noop",
	pagan_noop_page_add,
	pagan_noop_page_del,
	pagan_noop_process,
	pagan_noop_init,
	pagan_noop_deinit
};
