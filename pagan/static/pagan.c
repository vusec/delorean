#include <common/pagan/pagan.h>
#include "pagan_uthash.h"

/* we do not need strong random data so we can cache some */
#define PAGAN_RAND_LEN 1024
static unsigned long random_data[PAGAN_RAND_LEN];

typedef struct pagan_context_s {
	unsigned long id;
	pagan_mechanism_t *am;
	void *mech_priv;
	UT_hash_handle hh;
} pagan_context_t;
pagan_callbacks_t *pagan_callbacks;


unsigned int pagan_debug_level = PAGAN_DEBUG_ERROR;
//unsigned int pagan_debug_level = PAGAN_DEBUG_INFO;

extern pagan_mechanism_t pagan_noop_mechanism;
extern pagan_mechanism_t pagan_greedy_mechanism;
extern pagan_mechanism_t pagan_leaky_mechanism;
extern pagan_mechanism_t pagan_acb_mechanism;
extern pagan_mechanism_t pagan_fifo_mechanism;
extern pagan_mechanism_t pagan_leaky_sample_mechanism;
extern pagan_mechanism_t pagan_evo_mechanism;
extern pagan_mechanism_t pagan_meta_mechanism;
extern pagan_mechanism_t pagan_csum_mechanism;

pagan_mechanism_t *pagan_mechanisms[] =	{
	&pagan_noop_mechanism, 
	&pagan_greedy_mechanism, 
	&pagan_leaky_mechanism,
	&pagan_acb_mechanism,
	&pagan_fifo_mechanism,
	&pagan_leaky_sample_mechanism,
	&pagan_evo_mechanism,
	&pagan_meta_mechanism,
	&pagan_csum_mechanism,
};

static pagan_context_t  *ctx_handles = NULL;

void pagan_init(pagan_callbacks_t *cbs)
{
	int i;
	pagan_callbacks = cbs;

	for (i = 0; i < PAGAN_RAND_LEN ; i++)  {
		random_data[i] = cbs->rand();
	}

	pagan_debug(PAGAN_DEBUG_INFO, "pagan_initialized.\n");
}


void pagan_deinit(page_destroy_handler_t destroy_cb) {
	pagan_context_t *ctx, *tmp;
	HASH_ITER(hh, ctx_handles, ctx, tmp) {
		ctx->am->deinit(ctx->mech_priv, destroy_cb);
		HASH_DEL(ctx_handles, ctx);
		pagan_free(ctx);
	}
}

unsigned long pagan_rand(void) {
	static int rand_pos = 0;
	unsigned long r= random_data[rand_pos++];
	if (rand_pos >= PAGAN_RAND_LEN ) {
		rand_pos = 0;
	}
	return r;
}

void *pagan_malloc(unsigned long size) 
{
	return pagan_callbacks->malloc(size);
}


void pagan_free(void *ptr)
{
	pagan_callbacks->free(ptr);
}


int pagan_was_accessed(unsigned long addr, void* priv)
{
	return pagan_callbacks->was_accessed(addr, priv);
}


void pagan_clear_accessed(unsigned long addr, void* priv)
{
	pagan_callbacks->clear_accessed(addr, priv);
}


void pagan_fatal(void)
{
	pagan_callbacks->fatal();
}


static pagan_context_t * pagan_get_context_for_id(unsigned long id)
{
	pagan_context_t *c = NULL;
	pagan_debug(PAGAN_DEBUG_INFO, "looking up proc for %x\n", id);
	HASH_FIND_INT(ctx_handles, &id, c);
 	return c;
}


static void pagan_add_context(pagan_context_t *c)
{
	HASH_ADD_INT(ctx_handles, id, c);
}


void pagan_init_context(unsigned long id, int mechanism)
{
	pagan_context_t *c = pagan_get_context_for_id(id);
	pagan_assert(mechanism <= PAGAN_MECH_COUNT && mechanism >=0 && "Invalid mechanism");
	pagan_assert(c == NULL && "context id already taken?");
	c = pagan_malloc(sizeof(pagan_context_t));
	pagan_assert (c != NULL && "out of memory?");
	c->id = id;
	c->am = pagan_mechanisms[mechanism];
	pagan_printf("Initializing mechanism %s\n", c->am->name);
	c->mech_priv = c->am->init();
	pagan_add_context(c);
	pagan_debug(PAGAN_DEBUG_INFO, "pagan: context initialized for process %lx\n", id);
}


void pagan_deinit_context(unsigned long id, page_destroy_handler_t destroy_cb)
{
	pagan_context_t *c = pagan_get_context_for_id(id);
	pagan_assert(c != NULL && "cannot find context");
	c->am->deinit(c->mech_priv, destroy_cb);
	HASH_DEL(ctx_handles, c);
	pagan_free(c);
}


void *pagan_page_add(unsigned long id, void *addr, void *priv) 
{
    void *old_priv;
	pagan_context_t *c = pagan_get_context_for_id(id);
	pagan_assert(c != NULL && "cannot find context");
	pagan_assert(c->am && "pagan not initialized?");
	pagan_debug(PAGAN_DEBUG_INFO, "pagan_page_add: %p\n", addr);
	old_priv = c->am->page_add(c->mech_priv,addr,priv);
    return old_priv;
}


void pagan_page_del(unsigned long id, void *addr)
{
	pagan_context_t *c = pagan_get_context_for_id(id);
	pagan_assert(c != NULL && "cannot find context");
	pagan_assert(c->am && "pagan not initialized?");
	c->am->page_del(c->mech_priv, addr);
}


void pagan_process(unsigned long id, page_save_handler_t save_cb, page_discard_handler_t discard_cb, page_destroy_handler_t destroy_cb) 
{
	pagan_context_t *c = pagan_get_context_for_id(id);
	pagan_assert(c != NULL&& "cannot find context");
	pagan_assert(c->am && "pagan not initialized?");
	c->am->process(c->mech_priv, save_cb, discard_cb, destroy_cb);
}

typedef struct pagan_conf_entry_s {
	char key[PAGAN_CONF_KEY_LEN+1];
	unsigned long value;
	UT_hash_handle hh;
} pagan_conf_entry_t;

static pagan_conf_entry_t *conf_entries;

void pagan_set_conf(char *newkey, unsigned long value)
{
	pagan_conf_entry_t *cv = NULL;
	char key[PAGAN_CONF_KEY_LEN];

	key[PAGAN_CONF_KEY_LEN-1] = 0;

	strncpy(key, newkey, PAGAN_CONF_KEY_LEN-1);

	HASH_FIND_STR(conf_entries, key, cv);

	if (cv == NULL) {
		cv = pagan_malloc(sizeof(pagan_conf_entry_t));
		pagan_assert (cv != NULL && "out of memory?");
		strncpy(key, key, PAGAN_CONF_KEY_LEN);
		HASH_ADD_STR(conf_entries, key, cv);
	}

	cv->value = value;
}

int pagan_get_conf(char * newkey, unsigned long *value)
{
	pagan_conf_entry_t *cv = NULL;
	char key[PAGAN_CONF_KEY_LEN];

	key[PAGAN_CONF_KEY_LEN-1] = 0;

	strncpy(key, newkey, PAGAN_CONF_KEY_LEN-1);

	HASH_FIND_STR(conf_entries, key, cv);

	if (cv == NULL) {
		return 0;
	}

	*value = cv->value;

	return 1;
}

unsigned long pagan_get_conf_or_default(char * key, unsigned long dv)
{
	unsigned long dvr = dv;
	pagan_get_conf(key, &dv);
	return dvr;
}

void pagan_del_conf(char *newkey)
{
	pagan_conf_entry_t *cv = NULL;
	char key[PAGAN_CONF_KEY_LEN];

	key[PAGAN_CONF_KEY_LEN-1] = 0;

	strncpy(key, newkey, PAGAN_CONF_KEY_LEN-1);

	HASH_FIND_STR(conf_entries, key, cv);

	if (cv == NULL) {
		return;
	}

	HASH_DEL(conf_entries, cv);
	pagan_free(cv);
}

void pagan_clear_conf()
{
	pagan_conf_entry_t *cv = NULL, *tmp = NULL;
	HASH_ITER(hh, conf_entries, cv, tmp)
	{
		HASH_DEL(conf_entries,cv);
		pagan_free(cv);
	}
}
