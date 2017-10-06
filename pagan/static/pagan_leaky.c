#include <common/pagan/pagan.h>
#include "pagan_uthash.h"

#ifdef pagan_printf
#undef pagan_printf
#endif
#define pagan_printf(X, ...)
#define SAMPLE_COUNT 10

typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	int do_remove;
	int do_delete;
	UT_hash_handle hh;
} pagan_leaky_page_t;

enum {
  PAGAN_WSSE_STATIC,
  PAGAN_WSSE_HEURISTIC,
  PAGAN_WSSE_MONOTONIC_SAMPLING,
  PAGAN_WSSE_EXPBACKOFF_SAMPLING,
};


enum {
	PAGAN_REPLACEMENT_CLOCK,
	PAGAN_REPLACEMENT_FIFO,
	PAGAN_REPLACEMENT_RANDOM,
	PAGAN_REPLACEMENT_ELASTIC,
};

typedef struct pagan_leaky_proc_handle_s {
	pagan_leaky_page_t *leaky_list;
	pagan_leaky_page_t *drop_list;
	void *cursor_key;
	unsigned long target_len;
	unsigned long new;
	unsigned long precopy;
	unsigned long cow;
	unsigned counter;

	int replacement_strategy;
	void *clock_cursor_key;

	int wsse_samples[SAMPLE_COUNT];
	int wsse_sample_pos;
	int wsse_until_next_sampling;
	unsigned long dropped;
	int wsse_static_intervall;

	unsigned long wsse_type;

	int wsse_is_sample_run;
	/* for the heuristic */
	unsigned long growth_factor;

} pagan_leaky_proc_handle_t;

static void pagan_leaky_page_remove_rand(pagan_leaky_proc_handle_t *h)
{
	pagan_leaky_page_t *p, *tmp = NULL;
	unsigned long rand = pagan_rand() % HASH_COUNT(h->leaky_list);
	HASH_ITER(hh, h->leaky_list, p, tmp) {
		if (!rand--) {
			HASH_DEL(h->leaky_list,p);
			HASH_ADD_PTR(h->drop_list, addr, p);
			return;
		}
	}
}


static void pagan_leaky_page_remove_fifo(pagan_leaky_proc_handle_t *h)
{
	pagan_leaky_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->leaky_list, p, tmp) {
		HASH_DEL(h->leaky_list,p);
		HASH_ADD_PTR(h->drop_list, addr, p);
		return;
	}
}


static void pagan_leaky_page_remove_clock(pagan_leaky_proc_handle_t *h)
{
	pagan_leaky_page_t *p = NULL;
	int stop = 3;
    int stop2;

	HASH_FIND_PTR(h->leaky_list, &h->clock_cursor_key, p);

	while (stop--) {
		if ( p == NULL) {
			p = h->leaky_list;
			/* not necessary, if used correctly, i.e. not on empty list */
			if ( p == NULL ) {
				return;
			}
		}
		stop2 = HASH_COUNT(h->leaky_list);
		while (p && stop2--) {
			/*	start iterating at cursor */
			if ( !pagan_was_accessed((unsigned long)p->addr, p->user_priv) ) {
				pagan_leaky_page_t *np = p->hh.next;
				if (np) {
					h->clock_cursor_key = np->addr;
				}
					return;
			}

			/* second chance */
			pagan_clear_accessed((unsigned long)p->addr, p->user_priv);
			p = p->hh.next;
		}
	}

	if (stop==0) {
		pagan_printf("hmmm...\n");
	}
}

static void pagan_leaky_make_space(pagan_leaky_proc_handle_t *h) 
{
	/* do we have to drop a page */
	if (h->target_len >= HASH_COUNT(h->leaky_list) - h->dropped) {
		pagan_printf("Don't drop\n");
		return;
	}
	pagan_printf("Have to drop a page!\n");
	switch ( h->replacement_strategy) {
		case PAGAN_REPLACEMENT_CLOCK:
			pagan_leaky_page_remove_clock(h);
			return;
		case PAGAN_REPLACEMENT_FIFO:
			pagan_leaky_page_remove_fifo(h);
			return;
		default:
			pagan_leaky_page_remove_rand(h);
	}
}

static void *pagan_leaky_page_add(void *handle, void *addr, void *priv)
{
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	pagan_leaky_page_t *p = NULL;
    void *old_priv = NULL;
	h->cow++;
	HASH_FIND_PTR(h->leaky_list, &addr, p);
	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_leaky_page_t));
		p->user_priv = priv;
		p->addr = addr;
		if (!h->wsse_is_sample_run) {
			pagan_leaky_make_space(h);
			HASH_ADD_PTR(h->leaky_list, addr, p);
		} else {
			HASH_ADD_PTR(h->drop_list, addr, p);
		}
	} else {
		/* this can happen because of the sampling. */
        old_priv = p->user_priv;
        p->user_priv = priv;
	}

	h->new++;

    return old_priv;
}


static void pagan_leaky_page_del(void *handle, void *addr) 
{
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	pagan_leaky_page_t *p = NULL;
	HASH_FIND_PTR(h->leaky_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	HASH_DEL(h->leaky_list, p);
	pagan_free(p);
}


static void pagan_leaky_elastic_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t  destroy)
{
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	int to_long = HASH_COUNT(h->leaky_list) - h->target_len;
	pagan_leaky_page_t *p, *tmp = NULL;

	unsigned long p_leak = 0;

	if (to_long > 0 && HASH_COUNT(h->leaky_list)) {
		p_leak = to_long * ( (~0UL) / HASH_COUNT(h->leaky_list));
	}

	HASH_ITER(hh, h->leaky_list, p, tmp) {
		if (pagan_rand() > p_leak) {
			h->precopy++;
			save(p->addr, p->user_priv,NULL);
		} else {
			discard(p->addr, p->user_priv);
			destroy(p->user_priv);
			HASH_DEL(h->leaky_list, p);
			pagan_free(p);
		}
	}

}


static void pagan_leaky_save_all(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	/* in leaky scheme,we grow the working set constantly and never
	 * discard pages from the working set */
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	pagan_leaky_page_t *p, *tmp = NULL;

	pagan_printf("before len: %d\n", HASH_COUNT(h->leaky_list));

	HASH_ITER(hh, h->leaky_list, p, tmp) {
		pagan_printf("saving page: %p\n", p->addr);
		save(p->addr, p->user_priv, NULL);
	}

	HASH_ITER(hh, h->drop_list, p, tmp) {
		pagan_printf("Dropping page: %p\n", p->addr);
		discard(p->addr, p->user_priv);
		destroy(p->user_priv);
		HASH_DEL(h->drop_list, p);
		pagan_free(p);
	}
	pagan_printf("after len: %d\n", HASH_COUNT(h->leaky_list));

}

static void pagan_leaky_discard_all(void *handle, page_save_handler_t save, page_discard_handler_t discard)
{
	/* in leaky scheme,we grow the working set constantly and never
	 * discard pages from the working set */
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	pagan_leaky_page_t *p, *tmp = NULL;

	HASH_ITER(hh, h->leaky_list, p, tmp) {
		discard(p->addr, p->user_priv);
	}
}

/* From linux kernel version 3.13.11, in lib/sort.c */
static void generic_swap(void *a, void *b, int size)
{
    char t;

    do {
        t = *(char *)a;
        *(char *)a++ = *(char *)b;
        *(char *)b++ = t;
    } while (--size > 0);
}

static int cmpint(const void *a, const void *b)
{
    return (*((int *) a) - *((int *) b));
}

/* From linux kernel version 3.13.11, in lib/sort.c */
static void sort(void *base, size_t num, size_t size,
      int (*cmp_func)(const void *, const void *))
{
    void (*swap_func)(void *, void *, int size);

    /* pre-scale counters for performance */
    int i = (num/2 - 1) * size, n = num * size, c, r;

    swap_func = generic_swap;

    /* heapify */
    for ( ; i >= 0; i -= size) {
        for (r = i; r * 2 + size < n; r  = c) {
            c = r * 2 + size;
            if (c < n - size &&
                    cmp_func(base + c, base + c + size) < 0)
                c += size;
            if (cmp_func(base + r, base + c) >= 0)
                break;
            swap_func(base + r, base + c, size);
        }
    }

    /* sort */
    for (i = n - size; i > 0; i -= size) {
        swap_func(base, base + i, size);
        for (r = 0; r * 2 + size < i; r = c) {
            c = r * 2 + size;
            if (c < i - size &&
                    cmp_func(base + c, base + c + size) < 0)
                c += size;
            if (cmp_func(base + r, base + c) >= 0)
                break;
            swap_func(base + r, base + c, size);
        }
    }
}

static void pagan_leaky_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
    pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;

	/* 
	 * if sampling is turned on we just have to protect all the pages.
	 */
	if ( h->wsse_type == PAGAN_WSSE_EXPBACKOFF_SAMPLING
	     || h->wsse_type == PAGAN_WSSE_MONOTONIC_SAMPLING) {
		h->wsse_until_next_sampling--;
		 if (h->wsse_until_next_sampling <= 0) {
		 	if (h->wsse_until_next_sampling == 0) {
				pagan_leaky_discard_all(h, save, discard);
				h->new=0;
				h->wsse_is_sample_run = 1;
				pagan_printf("Sampling.\n");
				return;
			} else {
				int samples[SAMPLE_COUNT];
				h->wsse_samples[h->wsse_sample_pos]=h->new;
				h->wsse_sample_pos= (h->wsse_sample_pos+1) % SAMPLE_COUNT;
				memcpy(samples, h->wsse_samples, sizeof(int)*SAMPLE_COUNT);
				sort(samples, SAMPLE_COUNT, sizeof(int), cmpint);
				h->target_len = samples[SAMPLE_COUNT/2] + samples[SAMPLE_COUNT/2]/8;
				pagan_printf("new_targetlen: %d.\n", h->target_len);
				h->wsse_until_next_sampling = h->wsse_static_intervall;
				h->wsse_is_sample_run = 0;
			}
		 }
	}

	/*
	 * if elastic replacement strategy is used (probability for dropping
	 * pages increases with list beeing longer then target len
	 */
	if ( h->replacement_strategy == PAGAN_REPLACEMENT_ELASTIC ) {
		pagan_leaky_elastic_process(h, save, discard, destroy);
	} else {
		pagan_leaky_save_all(h, save, discard, destroy);
	}

	if ( h->wsse_type == PAGAN_WSSE_HEURISTIC ) {
		/* determine new list_len */
		if (h->new == 0) {
			h->target_len = HASH_COUNT(h->leaky_list) - HASH_COUNT(h->leaky_list)/4;
			if (h->target_len <= 0) {
				h->target_len = 0;
			}
		} else {
			h->target_len =  h->new/h->growth_factor  + HASH_COUNT(h->leaky_list);
		}	
	}

	h->new = 0;
}


static  void pagan_leaky_read_conf(pagan_leaky_proc_handle_t *h)
{
	h->replacement_strategy = pagan_get_conf_or_default(
		"REPLACMENT_STRATEGY",
		PAGAN_REPLACEMENT_RANDOM);

	h->wsse_static_intervall = pagan_get_conf_or_default(
		"STATIC_SAMPLING_INTERVAL",
		50);
	
	h->wsse_type = pagan_get_conf_or_default(
		"WSS_ESTIMATION_TYPE",
		PAGAN_WSSE_MONOTONIC_SAMPLING);
	
	h->growth_factor = pagan_get_conf_or_default(
		"WS_GROWTH_FACTOR",
		2);

	pagan_printf("pagan leaky conf: %d %d ,%d, %d\n", 
		h->replacement_strategy,
		h->wsse_static_intervall,
		h->wsse_type,
		h->growth_factor);
}

static void *pagan_leaky_init(void) 
{
	pagan_leaky_proc_handle_t * h = pagan_malloc(sizeof(pagan_leaky_proc_handle_t));
	pagan_assert(h!=NULL);
	memset(h,0,sizeof(pagan_leaky_proc_handle_t));
	pagan_leaky_read_conf(h);
	h->wsse_until_next_sampling = h->wsse_static_intervall;
	h->target_len=10;
	return h;
}


static void pagan_leaky_deinit(void *handle, page_destroy_handler_t destroy_cb)
{
	pagan_leaky_proc_handle_t *h = (pagan_leaky_proc_handle_t *) handle;
	pagan_leaky_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->leaky_list, p, tmp) {
		HASH_DEL(h->leaky_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}


pagan_mechanism_t pagan_leaky_mechanism = {
	"leaky",
	pagan_leaky_page_add,
	pagan_leaky_page_del,
	pagan_leaky_process,
	pagan_leaky_init,
	pagan_leaky_deinit
};

