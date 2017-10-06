#include <common/pagan/pagan.h>
#include "pagan_uthash.h"

typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	UT_hash_handle hh;
} pagan_fifo_page_t;


typedef struct pagan_fifo_proc_handle_s {
	pagan_fifo_page_t *fifo_list;
	unsigned long target_len;
	unsigned long list_len;
} pagan_fifo_proc_handle_t;


static void *pagan_fifo_page_add(void *handle, void *addr, void *priv)
{
	pagan_fifo_proc_handle_t *h = (pagan_fifo_proc_handle_t *) handle;
	pagan_fifo_page_t *p = NULL;
	HASH_FIND_PTR(h->fifo_list, &addr, p);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_fifo_page_t));
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->fifo_list, addr, p);
		h->list_len++;
	}
    return NULL;
}


static void pagan_fifo_page_del(void *handle, void *addr) 
{
	pagan_fifo_proc_handle_t *h = (pagan_fifo_proc_handle_t *) handle;
	pagan_fifo_page_t *p = NULL;
	HASH_FIND_PTR(h->fifo_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->list_len--;
	HASH_DEL(h->fifo_list, p);
	pagan_free(p);
}

static void pagan_fifo_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	pagan_fifo_proc_handle_t *h = (pagan_fifo_proc_handle_t *) handle;
	pagan_fifo_page_t *p, *tmp = NULL;

	int pos = 0;

	HASH_ITER(hh, h->fifo_list, p, tmp) {
		if (pos++ < h->target_len) {
			save(p->addr, p->user_priv, NULL);
		} else {
			discard(p->addr, p->user_priv);
			destroy(p->user_priv);
			HASH_DEL(h->fifo_list, p);
			pagan_free(p);
			h->list_len--;
		}
	}
}


static void *pagan_fifo_init(void) 
{
	pagan_fifo_proc_handle_t * h = pagan_malloc(sizeof(pagan_fifo_proc_handle_t));
	pagan_assert(h!=NULL);
	h->fifo_list = NULL;
	h->list_len = 0;
	h->target_len = 12;
	return h;
}


static void pagan_fifo_deinit(void *handle, page_destroy_handler_t destroy_cb) 
{
	pagan_fifo_proc_handle_t *h = (pagan_fifo_proc_handle_t *) handle;
	pagan_fifo_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->fifo_list, p, tmp) {
		HASH_DEL(h->fifo_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_fifo_mechanism = {
	"fifo",
	pagan_fifo_page_add,
	pagan_fifo_page_del,
	pagan_fifo_process,
	pagan_fifo_init,
	pagan_fifo_deinit
};


