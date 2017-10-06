#ifndef _PAGAN_PAGAN_H
#define _PAGAN_PAGAN_H


typedef void (*page_save_handler_t)(void * addr, void *priv, unsigned long *crc);

/* removes page from working set -> has to be protected by
 * chackpoint mechanism */
typedef void (*page_discard_handler_t)(void *addr, void*priv);

/* we get rid of the page completely and don't need the reference to priv anymore */
typedef void (*page_destroy_handler_t)( void*priv);

void pagan_dump_statistic(void);

enum {
	PAGAN_MECH_NOOP = 0,
	PAGAN_MECH_GREEDY,
	PAGAN_MECH_LEAKY,
	PAGAN_MECH_ACCESS_BITS,
	PAGAN_MECH_FIFO,
	PAGAN_MECH_LEAKY_SAMPLE,
	PAGAN_MECH_EVO_SAMPLE,
	PAGAN_MECH_META,
	PAGAN_MECH_CSUM,
	PAGAN_MECH_COUNT,
};

typedef struct pagan_mechanism_s {
	char *name;
	void  *(*page_add)(void *handle, void *addr, void *priv);
	void  (*page_del)(void *handle, void *addr);
	void  (*process)(void *handle, page_save_handler_t save_cb, page_discard_handler_t discard_cb, page_destroy_handler_t destroy_cb);
	void *(*init)(void);
	void  (*deinit)(void * handle, page_destroy_handler_t destroy_cb);
} pagan_mechanism_t;

typedef struct pagan_callbacks_s {
	void *(*malloc)(unsigned long s);
	void  (*free)(void *ptr);
	void  (*printf)(char *str, ...);
	void  (*fatal)(void);
	unsigned long  (*rand)(void);
	int  (*was_accessed)(unsigned long addr, void *priv);
	void  (*clear_accessed)(unsigned long addri, void *priv);
} pagan_callbacks_t;

extern pagan_callbacks_t *pagan_callbacks;

void pagan_init(pagan_callbacks_t *cbs);
void pagan_deinit(page_destroy_handler_t destroy_cb);

void pagan_init_context(unsigned long handle, int mechanism);
void pagan_deinit_context(unsigned long handle, page_destroy_handler_t destroy_cb);

/* returns the old priv if page was already there */
void *pagan_page_add(unsigned long handle, void *addr, void *priv);
void pagan_page_del(unsigned long handle, void *addr);
int  pagan_was_accessed(unsigned long addr, void *priv);
void pagan_clear_accessed(unsigned long addr, void *priv);

void pagan_process(unsigned long handle, page_save_handler_t save_cb, page_discard_handler_t discard_cb, page_destroy_handler_t destroy_cb);

#define PAGAN_CONF_KEY_LEN 32

void pagan_set_conf(char *key, unsigned long val);
int  pagan_get_conf(char *key, unsigned long *val);
unsigned long pagan_get_conf_or_default(char *key,  unsigned long default_val);
void pagan_del_conf(char *);
void pagan_clear_conf(void);


/****************************************************************************/
/* INTERNAL FUNCTIONS                                                       */
/****************************************************************************/
void *pagan_malloc(unsigned long s);
void  pagan_free(void *);
void  pagan_fatal(void);
unsigned long  pagan_rand(void);

extern unsigned int pagan_debug_level;

enum {
	PAGAN_DEBUG_ERROR,
	PAGAN_DEBUG_WARN,
	PAGAN_DEBUG_VERBOSE,
	PAGAN_DEBUG_INFO,
};


#define pagan_debug(level, ...)                   \
do {                                              \
	if (pagan_callbacks) {                        \
		if ( level <= pagan_debug_level)          \
			pagan_callbacks->printf(__VA_ARGS__); \
	}                                             \
} while(0)


#define pagan_printf(...)                     \
do {                                          \
	if (pagan_callbacks) {                    \
		pagan_callbacks->printf(__VA_ARGS__); \
	}                                         \
} while(0)

#define pagan_printf_warn(...) \
do {pagan_printf(__VA_ARGS__);}while(0)

#define pagan_assert(X)                  \
do {                                     \
    if (!(X)){                           \
	    pagan_printf("Assert failed: " #X); \
		pagan_fatal();                  \
	}                                    \
} while (0)
#endif
