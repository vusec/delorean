#include <smmap_defs.h>
#include <linux/random.h>
#include <common/pagan/pagan.h>

smmap_t smmap;

int pagan_initialized = 0;

static void * smmap_pagan_alloc(size_t size)
{
	void * ret;
	ret = kmalloc(size, GFP_ATOMIC);
	return ret;
}

static void smmap_pagan_free(void *ptr)
{
	kfree(ptr);
}

static unsigned long smmap_pagan_rand(void)
{
	unsigned long r;
	get_random_bytes(&r, sizeof(unsigned long));
	return r;
}

static void smmap_pagan_fatal(void) {
   BUG();
}

static void smmap_pagan_printf(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

static int smmap_pagan_was_accessed(unsigned long addr, void *data)
{
	smmap_proc_t *proc = (smmap_proc_t *) data;
	pte_t *pte;
    spinlock_t *ptl;
	int ret = 0;
    struct mm_struct *mm;

	smmap_map_t *map = smmap_map_lookup(proc, &addr, NULL);

	if (!map) {
		/* TODO: how can this happen? */
		return 0;
	}

	mm = map->owner->mm;
	smmap_get_locked_pte(pte, mm, addr, &ptl);

	if (pte_present(*pte)) {
		ret = smmap_ptep_accessed(pte);
	}

	spin_unlock(ptl);
    pte_unmap(pte);

	return ret;
}


static void smmap_pagan_clear_accessed(unsigned long addr, void* data)
{
	smmap_proc_t *proc = (smmap_proc_t *) data;
	pte_t *pte;
    spinlock_t *ptl;
    struct mm_struct *mm;
	smmap_map_t *map = smmap_map_lookup(proc, &addr, NULL);

   	if (!map) {
		/* TODO: how can this happen? */
		return;
	}

 	mm = map->owner->mm;
    smmap_get_locked_pte(pte, mm, addr, &ptl);
	if (pte_present(*pte)) {
		smmap_ptep_unset_accessed(mm,addr,pte);
	}
	spin_unlock(ptl);
	proc->needs_tlb_flush=1;
    pte_unmap(pte);
}


pagan_callbacks_t pagan_cb = {
	smmap_pagan_alloc,
	smmap_pagan_free,
	smmap_pagan_printf,
	smmap_pagan_fatal,
	smmap_pagan_rand,
	smmap_pagan_was_accessed,
	smmap_pagan_clear_accessed
};

void smmap_proc_print_all(void)
{
    smmap_proc_t *proc;

#ifdef ENABLE_DEBUG
    if (SMMAP_CONF(debug_verbosity) < DEBUG_L2) return;
#endif

    printk("--- PROCS (%d):\n", SMMAP_STAT(num_procs));
    SMMAP_PROC_ITER(proc,
        SMMAP_PROC_PRINT(proc); printk("\n");
        smmap_map_print_all(proc);
    );
}

smmap_proc_t* smmap_proc_lookup(struct mm_struct *mm)
{
    smmap_proc_t *proc;

    if (!mm)
        return NULL;

    SMMAP_PROC_ITER(proc,
        if (proc->mm == mm) {
            return proc;
        }
    );

    return NULL;
}

int smmap_proc_create(smmap_proc_t *data, smmap_proc_t **proc_ptr)
{
    smmap_proc_t *proc;
    int i = 0;
    smmap_map_t *maps;

    while (i < max_procs && smmap.procs[i].active) i++;
    if (i >= max_procs)
        return -ENOMEM;

    proc = &smmap.procs[i];
    maps = proc->maps;
    memcpy(proc, data, sizeof(smmap_proc_t));
    proc->maps = maps;
    proc->active = 1;
    SMMAP_STAT_INC(num_procs);
    BUG_ON(!data->mm);
    if (proc_ptr) {
        *proc_ptr = proc;
    }

	/* create pagan context if necessary */
	if (SMMAP_CONF(use_pagan)) {
		/* initialize pagan if not done yet */
		if (!pagan_initialized) {
			pagan_init(&pagan_cb);
			pagan_initialized = 1;
			printk("initialized pagan...\n");
		} else {
		}
		pagan_init_context((unsigned long) proc,
				SMMAP_CONF(pagan_mechanism));
		proc->use_pagan = 1;
	}

    smmap_rb_info_init(&proc->rb_info);
    /* initialize checkpoint list, present list and journal */
    smmap_plist_init(&proc->checkpoint, "checkpoint list");
    smmap_plist_init(&proc->present, "present list");
    smmap_journal_init(&proc->journal);
    /* initialize hardware breakpoint array */
    smmap_hwbp_init(proc);
    /* initialize checkpoint info */
    smmap_cps_info_init(&proc->checkpoints_info);

    return 0;
}

void smmap_proc_destroy(smmap_proc_t *proc)
{
    if (proc == NULL) return;

    proc->active = 0;
	if (proc->use_pagan) {
		pagan_deinit_context((unsigned long) proc, smmap_pagan_destroy_cb);
	}
    smmap_plist_clear(&proc->checkpoint);
    smmap_plist_clear(&proc->present);
    smmap_journal_destroy(&proc->journal);
    smmap_cps_info_destroy(&proc->checkpoints_info);
    smmap_hwbp_cleanup(proc);

    SMMAP_STAT_DEC(num_procs);

    if (SMMAP_STAT(num_procs) == 0 && !SMMAP_CONF(dedup_no_clear) &&
        !SMMAP_CONF(page_freq)) {

        /* if not processes are under smmap anymore, the deduplication tree
           can be completely cleared out */
        smmap_dedup_clear();
    }
}
