#include <common/pagan/pagan.h>
#include "pagan_uthash.h"

#define SAMPLE_INTERVAL 50
#define SAMPLE_COUNT    10


typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	UT_hash_handle hh;
} pagan_leaky_sample_page_t;


typedef struct pagan_leaky_sample_proc_handle_s {
	pagan_leaky_sample_page_t *leaky_sample_list;
	unsigned long target_len;
	unsigned long list_len;
	unsigned long sample_counter;
	int samples[SAMPLE_COUNT];
	int sample_pos;
} pagan_leaky_sample_proc_handle_t;


static void *pagan_leaky_sample_page_add(void *handle, void *addr, void *priv)
{
	pagan_leaky_sample_proc_handle_t *h = (pagan_leaky_sample_proc_handle_t *) handle;
	pagan_leaky_sample_page_t *p = NULL;
    void *old_priv = NULL;
	HASH_FIND_PTR(h->leaky_sample_list, &addr, p);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_leaky_sample_page_t));
		p->user_priv = priv;
		p->addr = addr;
		HASH_ADD_PTR(h->leaky_sample_list, addr, p);
		h->list_len++;
	} else {
        old_priv = p->user_priv;
        p->user_priv = priv;
    }
	if (h->sample_counter == 0) {
		h->samples[h->sample_pos]++;
	}
    return old_priv;
}


static void pagan_leaky_sample_page_del(void *handle, void *addr) 
{
	pagan_leaky_sample_proc_handle_t *h = (pagan_leaky_sample_proc_handle_t *) handle;
	pagan_leaky_sample_page_t *p = NULL;
	HASH_FIND_PTR(h->leaky_sample_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->list_len--;
	HASH_DEL(h->leaky_sample_list, p);
	pagan_free(p);
}


static void pagan_leaky_sample_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	pagan_leaky_sample_proc_handle_t *h = (pagan_leaky_sample_proc_handle_t *) handle;
	int to_long;
	pagan_leaky_sample_page_t *p, *tmp = NULL;

	unsigned long p_leak = 0;

	if (h->sample_counter == 0) {
		int i, sample_sum=0;
		/* we just sampled the list_len */
		h->sample_counter = SAMPLE_INTERVAL;
		h->sample_pos = (h->sample_pos + 1) % SAMPLE_COUNT;
		for (i=0; i < SAMPLE_COUNT; i++) {
			sample_sum += h->samples[i];
		}
		h->target_len = sample_sum/SAMPLE_COUNT;
	}

	to_long = h->list_len - h->target_len;

	if (to_long > 0 && h->list_len) {
		p_leak = to_long * ( (~0UL) / h->list_len);
	}

	if (--h->sample_counter == 0) {
		HASH_ITER(hh, h->leaky_sample_list, p, tmp) {
			discard(p->addr, p->user_priv);
		}
	} else {
		HASH_ITER(hh, h->leaky_sample_list, p, tmp) {
			if (pagan_rand() > p_leak) {
				save(p->addr, p->user_priv, NULL);
			} else {
				discard(p->addr, p->user_priv);
				destroy(p->user_priv);
				HASH_DEL(h->leaky_sample_list, p);
				pagan_free(p);
				h->list_len--;
			}
		}
	}
}


static void *pagan_leaky_sample_init(void) 
{
	pagan_leaky_sample_proc_handle_t * h = pagan_malloc(sizeof(pagan_leaky_sample_proc_handle_t));
	pagan_assert(h!=NULL);
	memset(h, 0, sizeof(pagan_leaky_sample_proc_handle_t));
	h->target_len = 10;
	return h;
}


static void pagan_leaky_sample_deinit(void *handle,
    page_destroy_handler_t destroy_cb) 
{
	pagan_leaky_sample_proc_handle_t *h = (pagan_leaky_sample_proc_handle_t *) handle;
	pagan_leaky_sample_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->leaky_sample_list, p, tmp) {
		HASH_DEL(h->leaky_sample_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_leaky_sample_mechanism = {
	"leaky_sample",
	pagan_leaky_sample_page_add,
	pagan_leaky_sample_page_del,
	pagan_leaky_sample_process,
	pagan_leaky_sample_init,
	pagan_leaky_sample_deinit
};

