#include <common/pagan/pagan.h>
#include "pagan_uthash.h"


typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	UT_hash_handle hh;
} pagan_acb_page_t;


typedef struct pagan_acb_proc_handle_s {
	pagan_acb_page_t *acb_list;
	unsigned long list_len;
} pagan_acb_proc_handle_t;

static void *pagan_acb_page_add(void *handle, void *addr, void *priv)
{
	pagan_acb_proc_handle_t *h = (pagan_acb_proc_handle_t *) handle;
	pagan_acb_page_t *p = NULL;
	HASH_FIND_PTR(h->acb_list, &addr, p);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_acb_page_t));
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->acb_list, addr, p);
		h->list_len++;
	}
    return NULL;
}


static void pagan_acb_page_del(void *handle, void *addr) 
{
	pagan_acb_proc_handle_t *h = (pagan_acb_proc_handle_t *) handle;
	pagan_acb_page_t *p = NULL;
	HASH_FIND_PTR(h->acb_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->list_len--;
	HASH_DEL(h->acb_list, p);
	pagan_free(p);
}


static void pagan_acb_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	pagan_acb_proc_handle_t *h = (pagan_acb_proc_handle_t *) handle;
	pagan_acb_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->acb_list, p, tmp) {
		if( pagan_was_accessed((unsigned long) p->addr, p->user_priv)) {
			pagan_clear_accessed((unsigned long) p->addr, p->user_priv);
			save(p->addr, p->user_priv, NULL);
		} else {
			discard(p->addr, p->user_priv);
            destroy(p->user_priv);
			HASH_DEL(h->acb_list, p);
			pagan_free(p);
			h->list_len--;
		}
	}
}


static void *pagan_acb_init(void) 
{
	pagan_acb_proc_handle_t * h = pagan_malloc(sizeof(pagan_acb_proc_handle_t));
	pagan_assert(h!=NULL);
	h->acb_list = NULL;
	h->list_len = 0;
	return h;
}


static void pagan_acb_deinit(void *handle, page_destroy_handler_t destroy_cb) 
{
	pagan_acb_proc_handle_t *h = (pagan_acb_proc_handle_t *) handle;
	pagan_acb_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->acb_list, p, tmp) {
		HASH_DEL(h->acb_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_acb_mechanism = {
	"acb",
	pagan_acb_page_add,
	pagan_acb_page_del,
	pagan_acb_process,
	pagan_acb_init,
	pagan_acb_deinit
};


