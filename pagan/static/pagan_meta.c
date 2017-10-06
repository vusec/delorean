#include <common/pagan/pagan.h>
#include "pagan_uthash.h"


enum {
	PAGAN_META_MECH_NOOP = 0,
	PAGAN_META_MECH_EVO,
	PAGAN_META_MECH_LEAKY,
	PAGAN_META_MECH_CSUM,
	PAGAN_META_MECH_COUNT,
};

extern pagan_mechanism_t pagan_noop_mechanism;
extern pagan_mechanism_t pagan_greedy_mechanism;
extern pagan_mechanism_t pagan_leaky_mechanism;
extern pagan_mechanism_t pagan_acb_mechanism;
extern pagan_mechanism_t pagan_fifo_mechanism;
extern pagan_mechanism_t pagan_leaky_sample_mechanism;
extern pagan_mechanism_t pagan_evo_mechanism;
extern pagan_mechanism_t pagan_csum_mechanism;

static pagan_mechanism_t *pagan_meta_mechs[PAGAN_META_MECH_COUNT] = {
	&pagan_noop_mechanism,
	&pagan_evo_mechanism,
	//&pagan_leaky_mechanism,
	&pagan_leaky_sample_mechanism,
	&pagan_csum_mechanism
};


typedef struct pagan_meta_page_s {
	void *addr;
	void *user_priv;
	char is_protected[PAGAN_META_MECH_COUNT];
	char handled_by[PAGAN_META_MECH_COUNT];
	char did_fault_in;
	unsigned long crc;
	UT_hash_handle hh;
} pagan_meta_page_t;

struct pagan_meta_proc_handle_s;

typedef struct pagan_meta_mech {
	struct pagan_meta_proc_handle_s *meta_handle;
	unsigned index;
	pagan_mechanism_t *mech;
	void *mech_handle;
	unsigned overcopy;
	unsigned copy;
	unsigned discard;
	unsigned faulted;
} pagan_meta_mech_t;


typedef struct pagan_meta_proc_handle_s {
	pagan_meta_page_t *meta_list;
	pagan_meta_mech_t mechs[PAGAN_META_MECH_COUNT];
	unsigned int num_fault;
	unsigned int iteration;
} pagan_meta_proc_handle_t;


static void *pagan_meta_page_add(void *handle, void *addr, void *priv)
{
	int i;
	pagan_meta_proc_handle_t *h = (pagan_meta_proc_handle_t *) handle;
	pagan_meta_page_t *p = NULL;
    void *old_priv = NULL;
	HASH_FIND_PTR(h->meta_list, &addr, p);

	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_meta_page_t));
		memset(p, 0, sizeof(pagan_meta_page_t));
		memset(p->is_protected, 1, sizeof(char)*PAGAN_META_MECH_COUNT);
		p->addr = addr;
	    p->user_priv = priv;
		HASH_ADD_PTR(h->meta_list, addr, p);
	} else {
        old_priv = p->user_priv;
        p->user_priv = priv;
    }

	
    /* XXX: it appears, that the same page might fault in twice. I suspect,
	 *      fork is responsible for that. D
	 */
	if (!p->did_fault_in) {
		p->crc++; /* we need to simulate a different crc */
		p->did_fault_in = 1;
		h->num_fault++;
		for ( i = 0 ; i < PAGAN_META_MECH_COUNT; i++ ) {
			if ( p->is_protected[i] ) {
				h->mechs[i].faulted++;
				h->mechs[i].mech->page_add(h->mechs[i].mech_handle, p->addr, &h->mechs[i]);
				p->is_protected[0]=0;
			}
		}
	}
    return old_priv;
}


static void pagan_meta_page_del(void *handle, void *addr)
{
	int i;
	pagan_meta_proc_handle_t *h = (pagan_meta_proc_handle_t *) handle;
	pagan_meta_page_t *p = NULL;

	HASH_FIND_PTR(h->meta_list, &addr, p);

	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}

	for (i = 0; i < PAGAN_META_MECH_COUNT ; i++ ) {
		h->mechs[i].mech->page_del(h->mechs[i].mech_handle ,p->addr);
	}

	HASH_DEL(h->meta_list, p);
	pagan_free(p);
}


static void pagan_meta_save_cb(void *addr, void* handle, unsigned long *crc)
{
	pagan_meta_mech_t *m = handle;
	pagan_meta_proc_handle_t *h = m->meta_handle;
	pagan_meta_page_t *p = NULL;
	HASH_FIND_PTR(h->meta_list, &addr, p);
	m->copy++;
	if ( p != NULL ) {
		/* virtually unprotect the page */
		p->is_protected[m->index] = 0;
		if (!p->did_fault_in) {
			m->overcopy++;
		}
		if (crc != NULL) {
			*crc=p->crc;
		}
		p->handled_by[m->index] = 1;
	} else {
		pagan_printf("pagan-meta: WARNING cannot find page. (Should never happen.)\n");
	}
}

static void pagan_meta_discard_cb(void *addr, void *handle)
{
	pagan_meta_mech_t *m = handle;
	pagan_meta_proc_handle_t *h = m->meta_handle;
	pagan_meta_page_t *p = NULL;
	HASH_FIND_PTR(h->meta_list, &addr, p);
	m->discard++;
	if ( p != NULL ) {
		/* virtually unprotect the page */
		p->is_protected[m->index] = 1;
		p->handled_by[m->index] = 1;
	} else {
		pagan_printf("pagan-meta: WARNING cannot find page. (Should never happen.)\n");
	}
}

static void pagan_meta_destroy_cb(void *handle)
{
}
static void pagan_meta_print(pagan_meta_mech_t *mech)
{
	//pagan_printf("META_PRINT %s copy: %d  discard: %d overcopy: %d faulted: %d  touched: %d KEY: %p\n", mech->mech->name, mech->copy, mech->discard, mech->overcopy, mech->faulted, mech->meta_handle->num_fault, mech->meta_handle);
	mech->copy     = 0;
	mech->discard  = 0;
	mech->overcopy = 0;
	mech->faulted  = 0;
	
}

static void pagan_meta_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	pagan_meta_proc_handle_t *h = (pagan_meta_proc_handle_t *) handle;
	pagan_meta_page_t *p, *tmp = NULL;
	int i;

//	pagan_printf("****** Meta Iteration %d ******\n", h->iteration++);
	for ( i = 0; i < PAGAN_META_MECH_COUNT; i++ ) {
		h->mechs[i].mech->process(h->mechs[i].mech_handle ,pagan_meta_save_cb, pagan_meta_discard_cb, pagan_meta_destroy_cb);
		pagan_meta_print(&h->mechs[i]);
	}

	HASH_ITER(hh, h->meta_list, p, tmp) {
		/* we always have to protect, but not delete */
		discard(p->addr, p->user_priv);
		for ( i = 0; i < PAGAN_META_MECH_COUNT; i++ ) {
			if (p->did_fault_in) {
				if (!p->handled_by[i]) {
					pagan_printf("OHJEHMINEE!! page %p not handled by %s\n",
						p->addr, h->mechs[i].mech->name);
				}
			}
			p->handled_by[i]=0;
		}

		p->did_fault_in=0;
	}
	h->num_fault=0;
}


static void *pagan_meta_init(void)
{
	int i;
	pagan_meta_proc_handle_t * h = pagan_malloc(sizeof(pagan_meta_proc_handle_t));
	pagan_assert(h!=NULL);
	memset(h, 0, sizeof(pagan_meta_proc_handle_t));
	for ( i = 0; i < PAGAN_META_MECH_COUNT; i++ ) {
		h->mechs[i].index = i;
		h->mechs[i].meta_handle =  h;
		h->mechs[i].mech        =  pagan_meta_mechs[i];
		h->mechs[i].mech_handle = h->mechs[i].mech->init();
	}
	return h;
}


static void pagan_meta_deinit(void *handle, page_destroy_handler_t destroy_cb)
{
	int i;
	pagan_meta_proc_handle_t *h = (pagan_meta_proc_handle_t *) handle;
	pagan_meta_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->meta_list, p, tmp) {
		HASH_DEL(h->meta_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	for ( i = 0; i < PAGAN_META_MECH_COUNT; i++ ) {
		h->mechs[i].mech->deinit(h->mechs[i].mech_handle, NULL);
	}
	pagan_free(h);
}

pagan_mechanism_t pagan_meta_mechanism = {
	"meta",
	pagan_meta_page_add,
	pagan_meta_page_del,
	pagan_meta_process,
	pagan_meta_init,
	pagan_meta_deinit
};

