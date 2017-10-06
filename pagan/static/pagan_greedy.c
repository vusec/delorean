#include <common/pagan/pagan.h>
#include "pagan_uthash.h"


typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	UT_hash_handle hh;
} pagan_greedy_page_t;


typedef struct pagan_greedy_proc_handle_s {
	pagan_greedy_page_t *greedy_list;
	unsigned long pagan_greedy_list_len;
} pagan_greedy_proc_handle_t;

static void *pagan_greedy_page_add(void *handle, void *addr, void *priv)
{
	pagan_greedy_proc_handle_t *h = (pagan_greedy_proc_handle_t *) handle;
	pagan_greedy_page_t *p = NULL;
	HASH_FIND_PTR(h->greedy_list, &addr, p);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_greedy_page_t));
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->greedy_list, addr, p);
		h->pagan_greedy_list_len++;
	}
    return NULL;
}


static void pagan_greedy_page_del(void *handle, void *addr) 
{
	pagan_greedy_proc_handle_t *h = (pagan_greedy_proc_handle_t *) handle;
	pagan_greedy_page_t *p = NULL;
	HASH_FIND_PTR(h->greedy_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->pagan_greedy_list_len--;
	HASH_DEL(h->greedy_list, p);
	pagan_free(p);
}


static void pagan_greedy_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	/* in greedy scheme,we grow the working set constantly and never
	 * discard pages from the working set */
	pagan_greedy_proc_handle_t *h = (pagan_greedy_proc_handle_t *) handle;
	pagan_greedy_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->greedy_list, p, tmp) {
		save(p->addr, p->user_priv, NULL);
	}
}


static void *pagan_greedy_init(void) 
{
	pagan_greedy_proc_handle_t * h = pagan_malloc(sizeof(pagan_greedy_proc_handle_t));
	pagan_assert(h!=NULL);
	h->greedy_list = NULL;
	h->pagan_greedy_list_len = 0;
	return h;
}

static void pagan_greedy_deinit(void *handle, page_destroy_handler_t destroy_cb) 
{
	pagan_greedy_proc_handle_t *h = (pagan_greedy_proc_handle_t *) handle;
	pagan_greedy_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->greedy_list, p, tmp) {
		HASH_DEL(h->greedy_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}

pagan_mechanism_t pagan_greedy_mechanism = {
	"greedy",
	pagan_greedy_page_add,
	pagan_greedy_page_del,
	pagan_greedy_process,
	pagan_greedy_init,
	pagan_greedy_deinit
};


