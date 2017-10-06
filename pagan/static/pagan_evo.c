#include <common/pagan/pagan.h>
#include "pagan_uthash.h"

#define POP_MAX_SIZE         20
#define DEFAULT_POP_SIZE     5
#define DEFAULT_PRECOPY_COST  1
#define DEFAULT_COW_COST     8 

#define  ULONG_MAX (~0UL)

typedef enum {
	PROTECTED,
	UNPROTECTED,
	DISCARD,
} page_state_t;

typedef struct pagan_page_s {
	void *addr;
	void *user_priv;
	char gene[2][POP_MAX_SIZE];
	page_state_t state;
	UT_hash_handle hh;
	int is_new;
} pagan_evo_page_t;

typedef struct pagan_parents_s {
	int p1;
	int p2;
} pagan_parents_t;

enum {
	PAGAN_EVO_SELECTION_ROULETTE,
	PAGAN_EVO_SELECTION_TOURNAMENT
};

typedef struct pagan_evo_proc_handle_s {
	pagan_evo_page_t *evo_list;
	unsigned long list_len;
	unsigned int current_individual;
	unsigned int counter;
	pagan_parents_t parents[POP_MAX_SIZE];
	unsigned long scores[POP_MAX_SIZE];
	unsigned long score_max;
	int cow;
	int precopy;

	/* configuration */
	int cow_cost;
	int precopy_cost;
	int population_size;
	int selection_method;

} pagan_evo_proc_handle_t;



static void pagan_mate(pagan_evo_proc_handle_t *h)
{
	int cand1, cand2;
	int i, max;
	unsigned long scores = 0;
	for ( i=0 ; i < h->population_size; i++ ) {
		if ( h->selection_method == PAGAN_EVO_SELECTION_ROULETTE ) {
			cand1 = pagan_rand()/(ULONG_MAX/h->population_size);
			cand2 = pagan_rand()/(ULONG_MAX/h->population_size);
			h->parents[i].p1 = (h->scores[cand1] < h->scores[cand2]) ? cand1 : cand2;
			cand1 = pagan_rand()/(ULONG_MAX/h->population_size);
			cand2 = pagan_rand()/(ULONG_MAX/h->population_size);
			h->parents[i].p2 = (h->scores[cand1] < h->scores[cand2]) ? cand1 : cand2;
		} else {
			max=20;
			do {
				cand1 = pagan_rand()/(ULONG_MAX/h->population_size);
			} while (max-- > 0  && pagan_rand() <  (h->scores[cand1]*(ULONG_MAX / h->score_max)));
			max=20;
			do {
				cand2 = pagan_rand()/(ULONG_MAX/h->population_size);
			} while (max-- > 0 && pagan_rand() < (h->scores[cand2]*(ULONG_MAX / h->score_max)));

			h->parents[i].p1 = cand1;
			h->parents[i].p2 = cand2;
		}
		scores+=h->scores[i];
	}
	h->cow=0;
	h->precopy =0;
}

static void pagan_crossover(pagan_evo_proc_handle_t *h)
{
	pagan_evo_page_t *p = NULL , *tmp = NULL;
	int i;
	int crossover_positions[h->population_size];

	if (h->list_len == 0)
		goto out;

	for (i=0 ; i < h->population_size ; i++) {
		crossover_positions[i]=pagan_rand()%h->list_len;
		//crossover_positions[i]=0.5;
	}

	HASH_ITER(hh, h->evo_list, p, tmp) {
		int users=0;
		if (p->is_new) {
			for (i=0 ; i < h->population_size ; i++) {
				if(pagan_rand() < ULONG_MAX/8) {
					users++;
					p->gene[(h->counter+1)%2][i] = 1;
				}
			}
			p->is_new = 0;
		} else {
			for (i=0 ; i < h->population_size ; i++) {
				if (crossover_positions[i]-- > 0) {
					p->gene[(h->counter+1)%2][i] = p->gene[h->counter%2][h->parents[i].p1];
				} else {
					p->gene[(h->counter+1)%2][i] = p->gene[h->counter%2][h->parents[i].p2];
				}
				if (p->gene[(h->counter+1)%2][i]) {
					users++;
				}
			}
		}
#if 1
		if (users == 0) {
			if (p->state == PROTECTED ) {
				/* page is already protected... we can throw it out */
				h->list_len--;
				HASH_DEL(h->evo_list, p);
				pagan_free(p);
			} else {
				p->state=DISCARD;
			}
		}
#endif
	}

out:
	h->counter++;
}



static void pagan_procreate(pagan_evo_proc_handle_t *h)
{
	pagan_mate(h);
	pagan_crossover(h);
}

static void pagan_next_individual(pagan_evo_proc_handle_t *h)
{
	h->current_individual++;
	if ( h->current_individual == h->population_size) {
		pagan_procreate(h);
		h->current_individual = 0;
		h->score_max = 1;
	}
	h->scores[h->current_individual] = 0;
}

static void *pagan_evo_page_add(void *handle, void *addr, void *priv)
{
	pagan_evo_proc_handle_t *h = (pagan_evo_proc_handle_t *) handle;
	pagan_evo_page_t *p = NULL;
    void *old_priv = NULL;
	HASH_FIND_PTR(h->evo_list, &addr, p);

    pagan_debug(PAGAN_DEBUG_INFO, "Calling pagan_evo_page_add\n");

	h->cow++;

	if (p == NULL) {
		p = pagan_malloc(sizeof(pagan_evo_page_t));
		pagan_assert(p != NULL && "Cannot allocate memory.\n");
		memset(p,0,sizeof(pagan_evo_page_t));
		p->user_priv = priv;
		p->addr      = addr;
		HASH_ADD_PTR(h->evo_list, addr, p);
		h->list_len++;
		p->is_new = 1;
	} else {
        old_priv = p->user_priv;
        p->user_priv = priv;
    }

	if ( !p->gene[h->counter%2][h->current_individual] && !p->is_new ) {
		/* we only have to do that if the page was not already in WS of mechanism */
		h->scores[h->current_individual] += h->cow_cost;
		if (h->scores[h->current_individual] > h->score_max) {
				h->score_max = h->scores[h->current_individual];
		}
	}
//	p->gene[h->counter%2][h->current_individual]=1;
	p->state = UNPROTECTED;

    pagan_debug(PAGAN_DEBUG_INFO, "Completed for addr=0x%p\n", addr);
    pagan_debug(PAGAN_DEBUG_INFO, "\tstate: %d\n", p->state);

    return old_priv;
}


static void pagan_evo_page_del(void *handle, void *addr)
{
	pagan_evo_proc_handle_t *h = (pagan_evo_proc_handle_t *) handle;
	pagan_evo_page_t *p = NULL;
	HASH_FIND_PTR(h->evo_list, &addr, p);
	if (p == NULL) {
		pagan_printf_warn("Cannot find page %p to delete.\n", p);
		return;
	}
	h->list_len--;
	HASH_DEL(h->evo_list, p);
	pagan_free(p);
}


static void pagan_evo_process(void *handle, page_save_handler_t save, page_discard_handler_t discard, page_destroy_handler_t destroy)
{
	/* in evo scheme,we grow the working set constantly and never
	 * discard pages from the working set */
	pagan_evo_proc_handle_t *h = (pagan_evo_proc_handle_t *) handle;
	pagan_evo_page_t *p, *tmp = NULL;

	/* choose a new individual */
	pagan_next_individual(h);

	HASH_ITER(hh, h->evo_list, p, tmp) {


		if (p->state == DISCARD) {
			discard(p->addr, p->user_priv);
            destroy(p->user_priv);
			HASH_DEL(h->evo_list, p);
			pagan_free(p);
			h->list_len--;
			continue;
		}

		p->gene[h->counter%2][h->current_individual] =
			( pagan_rand() > (ULONG_MAX/100) )
			? p->gene[h->counter%2][h->current_individual] 
			: !p->gene[h->counter%2][h->current_individual];

		if (p->gene[h->counter%2][h->current_individual]) {
			h->precopy++;
			h->scores[h->current_individual]+=h->precopy_cost;
			if (h->scores[h->current_individual] > h->score_max) {
				h->score_max = h->scores[h->current_individual];
			}
			if (p->state==UNPROTECTED) {
				save(p->addr, p->user_priv, NULL);
			} else {
				/* If the page is still protected we will wait for it to fault in somewhen */
			}
		} else {
			if (p->state==UNPROTECTED) {
				discard(p->addr, p->user_priv);
				p->state=PROTECTED;
			} else {
				/* if the page is already protected we don't need to do a thing */
			}
		}
	}
}


static void pagan_evo_read_configuration(pagan_evo_proc_handle_t *h)
{
	h->precopy_cost     = pagan_get_conf_or_default(
		"EVO_PRECOPY_COST",
		DEFAULT_PRECOPY_COST); 
	h->cow_cost         = pagan_get_conf_or_default(
		"EVO_COW_COST",
		DEFAULT_COW_COST); 
	h->selection_method = pagan_get_conf_or_default(
		"EVO_SELECTION_STRATEGY",
		PAGAN_EVO_SELECTION_ROULETTE
		);
	h->population_size  = pagan_get_conf_or_default(
		"EVO_POPULATION_SIZE",
		DEFAULT_POP_SIZE);

	if ( h->population_size > POP_MAX_SIZE ) {
		h->population_size = POP_MAX_SIZE;
	}
}

static void *pagan_evo_init(void)
{
	pagan_evo_proc_handle_t * h = pagan_malloc(sizeof(pagan_evo_proc_handle_t));
	pagan_assert(h!=NULL);
	memset(h, 0, sizeof(pagan_evo_proc_handle_t));
	h->evo_list = NULL;
	h->list_len = 0;
	pagan_evo_read_configuration(h);
	return h;
}


static void pagan_evo_deinit(void *handle, page_destroy_handler_t destroy_cb)
{
	pagan_evo_proc_handle_t *h = (pagan_evo_proc_handle_t *) handle;
	pagan_evo_page_t *p, *tmp = NULL;
	HASH_ITER(hh, h->evo_list, p, tmp) {
		HASH_DEL(h->evo_list, p);
        if (destroy_cb) destroy_cb(p->user_priv);
		pagan_free(p);
	}
	pagan_free(h);
}

pagan_mechanism_t pagan_evo_mechanism = {
	"evo",
	pagan_evo_page_add,
	pagan_evo_page_del,
	pagan_evo_process,
	pagan_evo_init,
	pagan_evo_deinit
};


