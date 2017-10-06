/*
 * smmap.c
 *
 * Implements smmap(), smumap(), smctl() pseudo (sysctl-based) syscalls.
 * Intercepts do_exit(), handle_mm_fault().
 *
 * usage: insmod smmap.ko [max_procs=p] [max_maps=m] [max_pages=s]
 *                        [journal_size=c]
 *
 */

#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>
#include <linux/workqueue.h>

#include <smmap_defs.h>
#include <smmap_page_list.h>

#include <common/pagan/pagan.h>

#define INFO_SIZES_STR_SIZE 1000
static char smmap_sizes[INFO_SIZES_STR_SIZE];     /* general info */

/* Module parameters. */
int max_procs __read_mostly = SMMAP_DEFAULT_MAX_PROCS;
module_param(max_procs, int, 0);
MODULE_PARM_DESC(max_procs, "Max number of processes supported.");

int max_maps __read_mostly = SMMAP_DEFAULT_MAX_MAPS;
module_param(max_maps, int, 0);
MODULE_PARM_DESC(max_maps, "Max number of maps supported.");

int max_pages __read_mostly = SMMAP_DEFAULT_MAX_PAGES;
module_param(max_pages, int, 0);
MODULE_PARM_DESC(max_pages, "Workqueue size for page allocation.");

int journal_size __read_mostly = SMMAP_DEFAULT_JOURNAL_SIZE;
module_param(journal_size, int, 0);
MODULE_PARM_DESC(journal_size, "Number of checkpoints kept in the journal.");

#ifdef ENABLE_DEBUG
int debug_verbosity __read_mostly = SMMAP_DEFAULT_DEBUG_VERBOSITY;
module_param(debug_verbosity, int, 0);
MODULE_PARM_DESC(debug_verbosity, "Debug messages verbosity {from 1 to 3}.");
#endif /* ENABLE_DEBUG */


int smmap_oracle_log_maxsize __read_mostly = SMMAP_ORACLE_LOG_DEFAULT_MAXSIZE;
module_param(smmap_oracle_log_maxsize, int, 0);
MODULE_PARM_DESC(debug_verbosity, "Maximium size of the oracle log.");

int smmap_oracle_log_enabled __read_mostly = 0;
module_param(smmap_oracle_log_enabled, int, 0);
MODULE_PARM_DESC(debug_verbosity, "Enable oracle?");

int *smmap_oracle_log;
int smmap_oracle_log_pos  = 0;
int smmap_oracle_log_size = 0;

static smmap_ctl_t smmap_ctl;
static DEFINE_MUTEX(smmap_ctl_lock);

static struct workqueue_struct *smmap_wq;

typedef struct smmap_work_s {
  struct work_struct work;
  void *data;
  unsigned long pid;
} smmap_work_t;

smmap_conf_t smmap_conf __read_mostly = SMMAP_CONF_INITIALIZER;
struct page *smmap_priv_pages[SMMAP_NUM_PRIV_PAGES];


#ifdef ENABLE_DEBUG
#define SMMAP_STATUS(S) \
    do { \
        DEBUG(DEBUG_L2, "status %s:", S); \
        smmap_proc_print_all(); \
    } while(0)
#else
#define SMMAP_STATUS(S)
#endif

/* sysctl handlers. */
#define SMMAP_CTL_PROC_HANDLER_OP(OP, R) do { \
        mutex_lock(&smmap_ctl_lock); \
        R = smmap_ctl_ ## OP((smmap_ctl_ ## OP ## _t *) &(((smmap_ctl_t*) ctl->data)->u), \
            smmap_proc_lookup(current->mm)); \
        mutex_unlock(&smmap_ctl_lock); \
        DEBUG(DEBUG_L1, "ctl request for %s() returned %d", #OP, R); \
    } while(0)

#define test_page_content(__data, __aligned, __spp) \
    do { \
        int __ret; \
        struct page *__pagep; \
        char *__mem; \
        unsigned long __offset = (__data)->addr - __aligned; \
        __pagep = smmap_page_get_page(__spp); \
        __mem = kmap_atomic(__pagep); \
        __ret = memcmp(&__mem[__offset], (__data)->valuep, (__data)->size); \
        kunmap_atomic(__mem); \
        /* if the page was not compressed, return the page obtained */ \
        if (smmap_flag_is_set((__spp)->cpage, SMMAP_PAGE_FLAG_COMPRESSED)) \
            smmap_page_wq_page_return(&__pagep, false); \
        /* the value was found in the page, so we stop the search */ \
        if (__ret == 0) (__data)->found = true; \
    } while(0)

#define rollback_search(__journal, __data, __id, __aligned) \
    do { \
        int __ret; \
        smmap_page_t __sp; \
        smmap_page_reset(&__sp); \
        /* retrieve page from the journal for the specified checkponit ID. */ \
        __ret = smmap_journal_get_page(__journal, __id, __aligned, &__sp); \
        if (__ret < 0) return __ret; \
        else if (__ret == 0) continue; \
        else if (__ret == 1) test_page_content(__data, __aligned, &__sp); \
        /* sp is going out of scope, unset the page */ \
        smmap_page_unset_page(&__sp); \
    } while (0)

static int __smmap_ctl_smmap(smmap_ctl_smmap_t *data, smmap_proc_t *proc)
{
    smmap_map_t map_data;
    int ret;

    DEBUG(DEBUG_L1, "request for smmap");
    if (!proc) {
        /* Create process entry at the first entry. */
        smmap_proc_t proc_data;
        memset(&proc_data, 0, sizeof(smmap_proc_t));
        proc_data.mm = current->mm;
        ret = smmap_proc_create(&proc_data, &proc);
        if (ret != 0)
            return ret;
    }

    map_data.addr = (unsigned long) data->addr;
    map_data.shadow_addr = (unsigned long) data->shadow_addr;
    map_data.size = data->size;
    ret = smmap_map_create(proc, &map_data, NULL);
    if (ret == 0 && likely(!SMMAP_CONF(skip_regs_info))) {
        smmap_cp_info_t info;

        smmap_cp_info_init(&info);
        ret = smmap_cps_info_set(&proc->checkpoints_info, &info, true);
    }

    SMMAP_STATUS("after smmap()");

    return ret;
}

static int __smmap_ctl_smunmap(smmap_ctl_smunmap_t *data, smmap_proc_t *proc)
{
    smmap_map_t *map;

    DEBUG(DEBUG_L1, "request for smunmap");

    if (!proc) {
        return -ENOENT;
    }
    map = smmap_map_lookup(proc, (unsigned long*) &data->addr, NULL);
    if (!map) {
        return -ENOENT;
    }
    if (map->addr != (unsigned long) data->addr) {
        return -EINVAL;
    }

    smmap_map_destroy(map);

    SMMAP_STATUS("after smunmap()");

    return 0;
}


static void smmap_ctl_simulate_copying_n_pages(int num_pages)
{
    int i;
    for (i=0; i<num_pages; i++) {
        copy_highpage(smmap_priv_pages[i%SMMAP_NUM_PRIV_PAGES],
                smmap_priv_pages[(i+1)%SMMAP_NUM_PRIV_PAGES]);
    }
}

static inline int __smmap_ctl_smctl_checkpoint_oracle_record(smmap_proc_t *proc)
{
    int ret = smmap_map_fixup_page_list(proc, "checkpoint");
    smmap_oracle_log_pos  = (smmap_oracle_log_pos + 1) % SMMAP_ORACLE_LOG_MAXSIZE;
    smmap_oracle_log_size = smmap_oracle_log_pos;
    smmap_oracle_log[smmap_oracle_log_pos] = 0;
    return ret;
}


static inline int __smmap_ctl_smctl_checkpoint_oracle_replay(smmap_proc_t *proc)
{
    int num_pages = smmap_oracle_log[smmap_oracle_log_pos];
    smmap_oracle_log_pos = (smmap_oracle_log_pos + 1) % smmap_oracle_log_size;
    smmap_ctl_simulate_copying_n_pages(num_pages);
    return 0;
}


static inline int __smmap_ctl_smctl_checkpoint_oracle(smmap_proc_t *proc)
{
    switch(SMMAP_CONF(oracle)) {
    case SMMAP_ORACLE_REPLAY:
        return __smmap_ctl_smctl_checkpoint_oracle_replay(proc);
    case SMMAP_ORACLE_RECORD:
        return __smmap_ctl_smctl_checkpoint_oracle_record(proc);
    default:
        printk("smmap: WARN invalid oracle value...\n");
        return -EINVAL;
    }
}



static inline int __smmap_ctl_smctl_checkpoint_generic(smmap_proc_t *proc)
{
    int ret;
    bool out_of_window;

    if (!proc) return -EINVAL;

    /* start a new journal db for this process */
    if ((ret = smmap_journal_set_next(&proc->journal)) < 0) return ret;
    else out_of_window = !!ret;

    /* fixup the checkpoint list and save the old pages */
    if ((ret = smmap_map_fixup_page_list(proc, "checkpoint")) < 0) return ret;

    /* If requested, proceed with deduplication tree cleanup. This is done
       on purpose after the fixup. Depending on the configuration, the fixup
       can trigger new pages to be added to the checkpoint list. In this way,
       we allow to deduplicate those pages with possible orphans, before
       clearing the orphans away from the tree. */
    if (SMMAP_CONF(dedup_clear) == DEDUP_CLEAR_ON_WIN_EXIT && out_of_window &&
        SMMAP_CONF(dedup_type) != DEDUP_TYPE_NONE) {

        smmap_dedup_clear_orphans();

    } else if (SMMAP_CONF(dedup_clear) == DEDUP_CLEAR_ON_COUNT &&
        SMMAP_CONF(dedup_type) != DEDUP_TYPE_NONE) {

        if (++smmap_dedup_cpcounter >= SMMAP_CONF(dedup_clear_count)) {
            smmap_dedup_cpcounter = 0;
            smmap_dedup_clear_orphans();
        }
    }

    if (SMMAP_CONF(simulate_copying_num_checkpointed_pages) != 0) {
        unsigned long num_pages;
        if (SMMAP_CONF(simulate_copying_num_checkpointed_pages) < 0) {
            /* Simulate copying all the dirty pages. */
            num_pages = 0;
            ret = smmap_map_mkclean_all(proc, &num_pages);
            BUG_ON(ret);
            SMMAP_STAT(num_dirty_pages) += num_pages;
        } else {
            num_pages = SMMAP_CONF(simulate_copying_num_checkpointed_pages);
        }
        smmap_ctl_simulate_copying_n_pages(num_pages);
    }

    return ret;
}

static inline int __smmap_ctl_smctl_checkpoint(smmap_proc_t *proc,
    smmap_cp_info_t *info)
{
    int ret;

    if (!proc) return -ENOENT;

    if (likely(!SMMAP_CONF(skip_regs_info))) {
        ret = smmap_cps_info_set(&proc->checkpoints_info, info, false);
        if (ret < 0) return ret;
    }

    SMMAP_STAT_INC(num_checkpoints);
    if SMMAP_CONF(oracle) {
        return __smmap_ctl_smctl_checkpoint_oracle(proc);
    } else {
        return __smmap_ctl_smctl_checkpoint_generic(proc);
    }
}

void set_breakpoint_cb(struct perf_event *bp,
    struct perf_sample_data *data, struct pt_regs *regs)
{
    int ret;
    smmap_cp_info_t info;

    smmap_proc_t *proc = smmap_proc_lookup(current->mm);
    if (!proc) {
        printk(KERN_ALERT "Unable to retrieve proc.\n");
        return;
    }

    smmap_cp_info_init(&info);
    /* retrieve resgisters */
    info.pc = regs->ip;
    if (!SMMAP_CONF(hwbp_skip_regs)) {
        info.eflags = regs->flags;
        info.ss = regs->ss;
        info.cs = regs->cs;
        info.rsp = regs->sp;
        info.rbp = regs->bp;
        info.rax = regs->ax;
        info.rbx = regs->bx;
        info.rcx = regs->cx;
        info.rdx = regs->dx;
        info.rsi = regs->si;
        info.rdi = regs->di;
        info.r8 = regs->r8;
        info.r9 = regs->r9;
        info.r10 = regs->r10;
        info.r11 = regs->r11;
        info.r12 = regs->r12;
        info.r13 = regs->r13;
        info.r14 = regs->r14;
        info.r15 = regs->r15;
    }

    /* request new checkpoint */
    if ((ret = __smmap_ctl_smctl_checkpoint(proc, &info)) != 0) {
        printk(KERN_ALERT "%s: Unable to take checkpoint; error: %d\n",
                __func__, ret);
    }

    DEBUG(DEBUG_L1, "checkpoint successful using hw breakpoint set @0x%p",
        (void *) bp->attr.bp_addr);
}

static int __smmap_ctl_smctl_set_checkpoint(smmap_ctl_hwbp_t *data,
    smmap_proc_t *proc)
{
    int ret;

    if (!proc || !data) return -EINVAL;

    if ((ret = smmap_hwbp_set(proc, data)) != 0) {
        printk(KERN_ALERT "Unable to set hardware breakpoint at @%08lx.\n",
               data->addr);
        return ret;
    }

    DEBUG(DEBUG_L1, "hw breakpoint set @%p\n", (void *) data->addr);
    return 0;
}

static inline int __smmap_ctl_smctl_drop_checkpoint(smmap_ctl_hwbp_t *data,
    smmap_proc_t *proc)
{
    int ret;

    if (!proc || !data) return -EINVAL;

    if ((ret = smmap_hwbp_drop(proc, data)) != 0) {
        DEBUG(DEBUG_L1, "failed to drop hardware breakpoint @0x%p",
            (void *) data->addr);
        return ret;
    }

    DEBUG(DEBUG_L1, "successfully drop hw breakpoint @0x%p.\n",
        (void *) data->addr);

    return 0;
}

static inline int __smmap_ctl_smctl_dropall_checkpoints(smmap_proc_t *proc)
{
    if (!proc) return -EINVAL;

    smmap_hwbp_cleanup(proc);
    DEBUG(DEBUG_L1, "dropped all hw breakpoints");
    return 0;
}


/**
 * __smmap_ctl_smctl_test_page - test the content of a checkpointed page
 * @data: data provided from the user space
 * @proc: pointer to the smmap_proc_t structure for the current process
 *
 * Returns
 * SMMAP_TEST_PAGE_MATCH: if the page was found and matched,
 * SMMAP_TEST_PAGE_NOT_FOUND: if the page was not found,
 * SMMAP_TEST_PAGE_NOT_MATCH: if the page found did not match what expected
 * Negative value: if an error occurred.
 */
static inline int __smmap_ctl_smctl_test_page(smmap_ctl_test_page_t *data,
    char *expected, smmap_proc_t *proc)
{
    int ret, id, found = SMMAP_TEST_PAGE_NOT_FOUND;
    unsigned long aligned;
    smmap_page_t sp;

    if (!proc || !data ||
        !smmap_journal_valid_id(&proc->journal, data->checkpoint)) {

        return -EINVAL;
    }

    smmap_page_reset(&sp);
    /* search in the checkpoint specified and compare the contents */
    aligned = PAGE_ALIGNED(data->addr) ? data->addr :
        PAGE_ALIGN(data->addr)-PAGE_SIZE;

    id = data->checkpoint;
    ret = smmap_journal_get_page(&proc->journal, id, aligned, &sp);
    if (ret < 0) return ret;

    if (ret == 0)
        found = SMMAP_TEST_PAGE_NOT_FOUND;
    else if (ret == 1)
        found = (smmap_page_test(&sp, expected) == 0) ? SMMAP_TEST_PAGE_MATCH :
            SMMAP_TEST_PAGE_NOT_MATCH;

    /* sp is going out of scope, unset the page */
    smmap_page_unset_page(&sp);

    return found;
}

static int __smmap_ctl_smctl_rollback(smmap_ctl_rollback_t *data,
    smmap_proc_t *proc)
{
    int ret;

    if (!proc || !data) return -EINVAL;

    /* Before rolling back, extract the provided parameters. */
    if (data->checkpoint < 0) {
        DEBUG(DEBUG_L2, "Invalid checkpoint %d\n", data->checkpoint);
        return -EINVAL;
    }

    if (!smmap_rb_info_needs_rb(&proc->rb_info, data->checkpoint)) {
        DEBUG(DEBUG_L2, "No rollback is required");
        return 0;
    }

    /* Perform rollback by eagerly switching the checkpointed pages and saving
       the current-state pages */
    ret = smmap_map_rollback(proc, data->checkpoint, "rollback-state");
    if (ret != 0) return ret;

    /* Update book-keeping information */
    smmap_rb_info_set(&proc->rb_info, &proc->checkpoints_info,
        data->checkpoint);
    DEBUG(DEBUG_L1, "rollbacked to checkpoint %d", data->checkpoint);

    SMMAP_STAT_INC(num_rollbacks);
    return 0;
}

static inline int __smmap_ctl_smctl_rollback_ondemand(
    smmap_ctl_rollback_ondemand_t *data, smmap_proc_t *proc)
{
    int ret;
    const char *event = "ondemand-rollback";

    if (!proc || !data) return -EINVAL;

    /* rollback all the pages involved in the on-demand rollback request. */
    if ((ret = smmap_map_rollback_ondemand(proc, data, event)) < 0)
        return ret;

    /* Update book-keeping information */
    smmap_rb_info_set(&proc->rb_info, &proc->checkpoints_info,
        data->checkpoint);
    DEBUG(DEBUG_L1, "on-demand rollback completed successfully.");

    return 0;
}

static int __smmap_ctl_smctl_usearch_start(smmap_proc_t *proc)
{
    if (!proc) return -EINVAL;

    return smmap_journal_tree_populate(&proc->journal);
}

static int __smmap_ctl_smctl_usearch_stop(smmap_proc_t *proc)
{
    if (!proc) return -EINVAL;

    return smmap_journal_tree_destroy(&proc->journal);
}

/*
 * XXX: this API is for benchmark only. To make it production-ready, it
 *      needs to deal with memory areas that spawn two pages. It also needs
 *      to provie with better response communication to the caller.
 *      Additionally, the API only supports equality checks. Should be extended
 *      with additional checks.
 */
static int __smmap_ctl_smctl_search(smmap_ctl_search_t *data,
    smmap_proc_t *proc)
{
    int id = -1, ret = 0;
    unsigned long aligned;

    if (!proc || !data) return -EINVAL;

    data->found = 0;

    aligned = PAGE_ALIGNED(data->addr) ? data->addr :
        PAGE_ALIGN(data->addr)-PAGE_SIZE;
    if (!data->binary) {
        for (id = proc->journal.slots_used; id >= 0; --id) {
            smmap_page_t sp;
            int last_seen = -1;

            smmap_page_reset(&sp);
            ret = smmap_journal_has_page(&proc->journal, id, aligned, &sp);
            if (ret < 0)  {
                goto exit;
            } else if (ret == 1) {
                test_page_content(data, aligned, &sp);
                if (!data->found) last_seen = id;
            }

            /* sp is going out of scope, unset the page */
            smmap_page_unset_page(&sp);

            if (data->found) {
                id =  last_seen + 1;
                break;
            }
        }

    } else {
        /* in-kernel binary search */
        int l = 0, r = proc->journal.slots_used, m;

        /* first, initialize the tree-based search datastructure */
        __smmap_ctl_smctl_usearch_start(proc);

        id = -1;
        while (l<=0) {
            m = (l+r)/2;

            rollback_search(&proc->journal, data, m, aligned);
            if (data->found) {
                /* set the last-found ID, and go further in past closer to when
                   this started to be true */
                id = m;
                l = m + 1;
            } else {
                /* go further close to the present to see if the condition
                   is satisfied */
                r = m - 1;
            }
        }
        /* required to make sure that if at least a match was found, this
           result is treated accordingly and passed back to the caller. */
        if (id != -1) data->found = true;

        /* cleanup tree-based search datastructure */
        __smmap_ctl_smctl_usearch_stop(proc);
    }

    if (data->found) {
        smmap_ctl_rollback_t rbdata;

        /* issue a request to rollback to the ID we found */
        rbdata.checkpoint = id;
        ret = __smmap_ctl_smctl_rollback(&rbdata, proc);
        if (ret < 0) goto exit;
    }

exit:
    return ret;
}

static inline int __smmap_ctl_smctl_restore(smmap_proc_t *proc)
{
    int id;
    unsigned ret;

    if (!smmap_rb_info_is_in_rb(&proc->rb_info)) return 0;

    if (!proc) return -EINVAL;

    if ((ret = smmap_map_restore(proc, "restore-state")) != 0) return ret;

    id = smmap_rb_info_get_id(&proc->rb_info);
    smmap_rb_info_reset(&proc->rb_info);
    DEBUG(DEBUG_L1, "restored process state from checkpoint %d", id);

    SMMAP_STAT_INC(num_restores);
    return 0;
}

static inline int __smmap_ctl_smctl_rollback_default(smmap_proc_t *proc)
{
    int ret;

    if (!proc) return -EINVAL;

    ret = smmap_map_default_page_list(proc, "rollback-default-map");
    if (ret != 0) return ret;

    ret = smmap_map_fixup_page_list(proc, "rollback-default-fixup");

    SMMAP_STAT_INC(num_rollbacks);
    return ret;
}

static int __smmap_ctl_smctl_get_checkpoints_info(
    smmap_ctl_smctl_t *data, smmap_proc_t *proc)
{
    int ret;
    smmap_ctl_info_t info;
    smmap_cp_info_t *cp_infop;
    int cp_id;

    if (!data || !proc) return -EINVAL;

    /* retrieve the CP-ID parameter */
    copy_from_user(&info, data->ptr, sizeof(smmap_ctl_info_t));
    if (info.cp_id < PRESENT_STATE || info.cp_id > proc->journal.slots_used)
        return -EINVAL;

    cp_id = info.cp_id;
    if (cp_id == PRESENT_STATE && proc->rb_info.cp_id != PRESENT_STATE) {
        /* user requested the current state - the state is in rollback */
        info.cp_id = proc->rb_info.cp_id;
        cp_infop = proc->rb_info.cp_info;

    } else if (cp_id == PRESENT_STATE && proc->rb_info.cp_id == PRESENT_STATE) {
        /* user requested the current state - the state "present" under
           current interval */
        info.cp_id = 0;
        cp_infop = smmap_cps_info_get(&proc->checkpoints_info, 0);

    } else {
        cp_infop = smmap_cps_info_get(&proc->checkpoints_info, cp_id);
    }

    if (IS_ERR_OR_NULL(cp_infop)) return -EFAULT;

    memcpy(&info.cp_info, cp_infop, sizeof(smmap_cp_info_t));
    info.is_in_rollback = proc->rb_info.cp_id != PRESENT_STATE;
    info.max_cp_id = proc->journal.slots_used;

    ret = copy_to_user(data->ptr, &info, sizeof(smmap_ctl_info_t));
    if (ret != 0) return -EFAULT;

    return 0;
}

static int __smmap_ctl_smctl_is_in_rb(smmap_proc_t *proc) {
    if (!proc) return -EINVAL;

    return smmap_rb_info_is_in_rb(&proc->rb_info);
}

static int __smmap_ctl_smctl_get_stats(smmap_ctl_smctl_t *data)
{
    int ret;

    if (!data->ptr) return -EINVAL;

    /* first update compression statistics */
    smmap_compress_update_stats();
    /* return statistics to the user-space */
    ret = copy_to_user(data->ptr, &smmap.stats, sizeof(smmap_stats_t));
    if (ret != 0) return -EFAULT;
    return 0;
}

static inline int __smmap_ctl_smctl_clear_stats(void)
{
    int num_procs = SMMAP_STAT(num_procs);
    int num_maps = SMMAP_STAT(num_maps);

    memset(&smmap.stats, 0, sizeof(smmap_stats_t));
    /* clear compression statistics */
    smmap_compress_clear_stats();
    /* restore read-only statistics*/
    SMMAP_STAT(num_procs) = num_procs;
    SMMAP_STAT(num_maps) = num_maps;

    return 0;
}

static int __smmap_ctl_smctl_clear_dedup(void)
{
    smmap_dedup_clear();
    return 0;
}

static inline int smmap_ctl_smctl(smmap_ctl_smctl_t *data,
    smmap_proc_t *proc)
{
    int ret;
    struct mm_struct *mm = current->mm;

    DEBUG(DEBUG_L1, "request for smctl (operation: %d)", data->op);
    switch(data->op) {
    case SMMAP_SMCTL_CHECKPOINT:
        {
            smmap_cp_info_t info;

            if (data->ptr)
                copy_from_user(&info, data->ptr, sizeof(smmap_cp_info_t));

            down_write(&mm->mmap_sem);
            ret = __smmap_ctl_smctl_checkpoint(proc,
                (data->ptr) ? &info : NULL);
            up_write(&mm->mmap_sem);
        }
        break;
    case SMMAP_SMCTL_SET_CHECKPOINT:
        {
            smmap_ctl_hwbp_t hwbp_data;
            smmap_ctl_hwbp_t *ptr = data->ptr;

            if (!data->ptr) return -EINVAL;

            copy_from_user(&hwbp_data, ptr, sizeof(smmap_ctl_hwbp_t));
            ret = __smmap_ctl_smctl_set_checkpoint(&hwbp_data, proc);
        }
        break;
    case SMMAP_SMCTL_DROP_CHECKPOINT:
        {
            smmap_ctl_hwbp_t hwbp_data;
            smmap_ctl_hwbp_t *ptr = data->ptr;

            if (!data->ptr) return -EINVAL;

            /* copy required data from userspace */
            copy_from_user(&hwbp_data, ptr, sizeof(smmap_ctl_hwbp_t));
            /* call hanlder */
            ret = __smmap_ctl_smctl_drop_checkpoint(&hwbp_data, proc);
        }
        break;
    case SMMAP_SMCTL_DROPALL_CHECKPOINTS:
        ret = __smmap_ctl_smctl_dropall_checkpoints(proc);
        break;
    case SMMAP_SMCTL_TEST_PAGE:
        {
            smmap_ctl_test_page_t test_data;
            char *expected;

            if (!data->ptr) return -EINVAL;

            /* copy required data from userspace */
            copy_from_user(&test_data, data->ptr,
                    sizeof(smmap_ctl_test_page_t));
            expected = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
            copy_from_user(expected, (const void *) test_data.expected,
                    PAGE_SIZE);

            /* call hanlder */
            down_read(&mm->mmap_sem);
            ret = __smmap_ctl_smctl_test_page(&test_data, expected, proc);
            up_read(&mm->mmap_sem);

            /* free allocated memory */
            kfree(expected);
        }
        break;
    case SMMAP_SMCTL_ROLLBACK_DEFAULT:
        down_write(&mm->mmap_sem);
        ret = __smmap_ctl_smctl_rollback_default(proc);
        up_write(&mm->mmap_sem);
        break;
    case SMMAP_SMCTL_ROLLBACK:
        {
            smmap_ctl_rollback_t rb_data;

            if (!data->ptr) return -EINVAL;

            /* copy required data from userspace */
            copy_from_user(&rb_data, data->ptr, sizeof(smmap_ctl_rollback_t));
            /* call hanlder */
            down_write(&mm->mmap_sem);
            ret = __smmap_ctl_smctl_rollback(&rb_data, proc);
            up_write(&mm->mmap_sem);
        }
        break;
    case SMMAP_SMCTL_ROLLBACK_ONDEMAND:
        {
            smmap_ctl_rollback_ondemand_t rb_data;
            smmap_ctl_rollback_ondemand_t *user_data;

            if (!data->ptr) return -EINVAL;

            user_data = (smmap_ctl_rollback_ondemand_t *) data->ptr;
            /* copy required data from userspace */
            copy_from_user(&rb_data, user_data,
                sizeof(smmap_ctl_rollback_ondemand_t));
            /*  copy also the array of variables provided by the user */
            if (rb_data.slots > 0) {
                rb_data.vars = kmalloc(
                    sizeof(smmap_rollback_var_t)*rb_data.slots, GFP_KERNEL);
                copy_from_user(
                    rb_data.vars, user_data->vars,
                    sizeof(smmap_rollback_var_t)*rb_data.slots);
            } else {
                rb_data.vars = NULL;
            }

            /* call hanlder */
            down_write(&mm->mmap_sem);
            ret = __smmap_ctl_smctl_rollback_ondemand(&rb_data, proc);
            up_write(&mm->mmap_sem);

            /* free allocated vars memory */
            if (rb_data.vars) kfree(rb_data.vars);
        }
        break;
    case SMMAP_SMCTL_RB_SEARCH_START:
        ret = __smmap_ctl_smctl_usearch_start(proc);
        break;
    case SMMAP_SMCTL_RB_SEARCH_STOP:
        ret = __smmap_ctl_smctl_usearch_stop(proc);
        break;
    case SMMAP_SMCTL_SEARCH:
        {
            smmap_ctl_search_t kdata, *udata;

            if (!data->ptr) return -EINVAL;

            /* collect information from user-space */
            udata = (smmap_ctl_search_t *) data->ptr;
            copy_from_user(&kdata, udata, sizeof(smmap_ctl_search_t));
            /* copy also the value to compare the content of the page to */
            kdata.valuep = kmalloc(kdata.size, GFP_KERNEL);
            copy_from_user(kdata.valuep, udata->valuep, udata->size);

            /* perform the search */
            down_write(&mm->mmap_sem);
            ret = __smmap_ctl_smctl_search(&kdata, proc);
            up_write(&mm->mmap_sem);
            copy_to_user(&udata->found, &kdata.found, sizeof(unsigned short));

            /* free allocated memory */
            kfree(kdata.valuep);
        }
        break;
    case SMMAP_SMCTL_RESTORE:
        down_write(&mm->mmap_sem);
        ret = __smmap_ctl_smctl_restore(proc);
        up_write(&mm->mmap_sem);
        break;
    case SMMAP_SMCTL_GET_INFO:
        ret = __smmap_ctl_smctl_get_checkpoints_info(data, proc);
        break;
    case SMMAP_SMCTL_IS_IN_RB:
        ret = __smmap_ctl_smctl_is_in_rb(proc);
        break;
    case SMMAP_SMCTL_GET_STATS:
        ret = __smmap_ctl_smctl_get_stats(data);
        break;
    case SMMAP_SMCTL_CLEAR_STATS:
        ret = __smmap_ctl_smctl_clear_stats();
        break;
    case SMMAP_SMCTL_CLEAR_DEDUP:
        ret = __smmap_ctl_smctl_clear_dedup();
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static int smmap_ctl_smmap(smmap_ctl_smmap_t *data, smmap_proc_t *proc)
{
    int ret;
    struct mm_struct *mm = current->mm;

    down_write(&mm->mmap_sem);
    ret = __smmap_ctl_smmap(data, proc);
    up_write(&mm->mmap_sem);

    return ret;
}

static int smmap_ctl_smunmap(smmap_ctl_smunmap_t *data, smmap_proc_t *proc)
{
    int ret;
    struct mm_struct *mm = current->mm;

    down_write(&mm->mmap_sem);
    ret = __smmap_ctl_smunmap(data, proc);
    up_write(&mm->mmap_sem);

    return ret;
}

static int smmap_ctl_proc_handler(struct ctl_table *ctl, int write,
    void __user *buffer, size_t *lenp, loff_t *ppos)
{
    int ret;

    if (!write) {
        return -EPERM;
    }
    if (*lenp > ctl->maxlen) {
        return -E2BIG;
    }
    copy_from_user(ctl->data, buffer, *lenp);

    switch (smmap_ctl.op) {
    case SMMAP_CTL_SMMAP:
        SMMAP_CTL_PROC_HANDLER_OP(smmap, ret);
        break;
    case SMMAP_CTL_SMUNMAP:
        SMMAP_CTL_PROC_HANDLER_OP(smunmap, ret);
        break;
    case SMMAP_CTL_SMCTL:
        SMMAP_CTL_PROC_HANDLER_OP(smctl, ret);
        break;
    default:
        ret = -EINVAL;
        printk("smmap: invalid ctl (%d)\n", smmap_ctl.op);
        break;
    }

    return ret;
}


/* we have to wrap proc_dostring as we have to notify pagan of the changes */
static int smmap_proc_dostring(struct ctl_table *      table,
                             int      write,
                             void __user *      buffer,
                             size_t *      lenp,
                             loff_t *      ppos )
{
    /* key will be cut in pagan */
    char key[2*PAGAN_CONF_KEY_LEN];
    unsigned long val;
    int ret, ret_val;
    ret_val = proc_dostring(table, write, buffer, lenp, ppos);
    if ( (ret = sscanf(table->data, "%s=%ld", key, &val)) == 2) {
        pagan_set_conf(key, val);
    }
    return ret_val;
}


static int smmap_oracle_log_do_intvec(struct ctl_table *table, int write,
                                  void __user *buffer, size_t *lenp, loff_t *p_pos)
{
    int ret;

    if (!smmap_oracle_log_enabled || smmap_oracle_log == NULL)
        return -EINVAL;

    if (write) {
        /* if it was a write we have a new entry in the log now */
        if (smmap_oracle_log_size < (smmap_oracle_log_maxsize-1)) {
            smmap_oracle_log_size++;
            table->data = &smmap_oracle_log[smmap_oracle_log_size];
        }
    }

    ret = proc_dointvec(table, write, buffer, lenp, p_pos);\

    if (!write) {
    /* if it was a write we have a new entry in the log now */
        if (smmap_oracle_log_size > 0) {
            smmap_oracle_log_size--;
            table->data = &smmap_oracle_log[smmap_oracle_log_size];
        }
    }

    return ret;
}

static int smmap_oracle_dointvec(struct ctl_table *table, int write,
                                  void __user *buffer, size_t *lenp, loff_t *p_pos)
{
    int ret;

    if (!smmap_oracle_log_enabled || smmap_oracle_log == NULL)
        return -EINVAL;

    ret = proc_dointvec(table, write, buffer, lenp, p_pos);\
    if (write) {
        switch(SMMAP_CONF(oracle)) {
        case SMMAP_ORACLE_REPLAY:
            /* we start replaying from the beginning */
            smmap_oracle_log_pos=0;
            break;
        case SMMAP_ORACLE_RECORD:
            /* we start logging at the beginning, and reset the clear the log
             * be reseting the size to 0
             */
             smmap_oracle_log_pos = smmap_oracle_log_size = 0;
            break;
        default: break;
        }
    }
    return ret;
}

static int __smmap_sysctl_sizes(ctl_table *ctl, int write, void __user *buffer,
    size_t *lenp, loff_t *ppos)
{
    char *smmap_sizesp = smmap_sizes;
    int ret, pos = 0;

    if (!*lenp || (*ppos && !write)) {
        *lenp = 0;
        return 0;
    }

    pos += ret = scnprintf(smmap_sizesp, INFO_SIZES_STR_SIZE - pos,
        "{\n");
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_page_t\" : \t%lu,\n", (unsigned long) sizeof(smmap_page_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_cpage_t\" :\t%lu,\n", (unsigned long) sizeof(smmap_cpage_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_plist_node_t\" :\t%lu,\n",
        (unsigned long) sizeof(smmap_plist_node_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_plist_t\" :\t%lu,\n", (unsigned long) sizeof(smmap_plist_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_dedup_node_t\" :\t%lu,\n",
        (unsigned long) sizeof(smmap_dedup_node_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos,
        "\t\"smmap_dedup_crc_node_t\" :\t%lu\n",
        (unsigned long) sizeof(smmap_dedup_crc_node_t));
    if (!ret) goto error;
    pos += ret = scnprintf(smmap_sizesp + pos, INFO_SIZES_STR_SIZE - pos, "}");
    if (!ret) goto error;

    goto exit;

error:
    pr_info("smmap: (%s) info buffer too small\n", __func__);

exit:
    return proc_dostring(ctl, write, buffer, lenp, ppos);
}


/*
 * sysctl-tuning infrastructure.
 */
static struct ctl_table smmap_conf_table[] = {
    {
        .procname        = "wrprotect",
        .data            = &SMMAP_CONF(wrprotect),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "shadow",
        .data            = &SMMAP_CONF(shadow),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "shadow_zero_pages",
        .data            = &SMMAP_CONF(shadow_zero_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "tlb_batch_flush",
        .data            = &SMMAP_CONF(tlb_batch_flush),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "spc_type",
        .data            = &SMMAP_CONF(spc_type),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "simulate_copying_num_checkpointed_pages",
        .data            = &SMMAP_CONF(simulate_copying_num_checkpointed_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "count_mergeable_pages",
        .data            = &SMMAP_CONF(count_mergeable_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "use_pagan",
        .data            = &SMMAP_CONF(use_pagan),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "pagan_mechanism",
        .data            = &SMMAP_CONF(pagan_mechanism),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "pagan_conf",
        .data            = &SMMAP_CONF(pagan_config_value),
        .maxlen          = sizeof(PAGAN_CONF_KEY_LEN*2),
        .mode            = 0666,
        .proc_handler    = smmap_proc_dostring,
    },
#ifdef ENABLE_DEBUG
    {
        .procname        = "debug_verbosity",
        .data            = &SMMAP_CONF(debug_verbosity),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
#endif
    {
        .procname        = "oracle",
        .data            = &SMMAP_CONF(oracle),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = smmap_oracle_dointvec,
    },
    {
        .procname        = "dedup_type",
        .data            = &SMMAP_CONF(dedup_type),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = smmap_dedup_dointvec,
    },
    {
        .procname        = "dedup_location",
        .data            = &SMMAP_CONF(dedup_location),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "dedup_clear",
        .data            = &SMMAP_CONF(dedup_clear),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "dedup_clear_count",
        .data            = &SMMAP_CONF(dedup_clear_count),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "dedup_no_clear",
        .data            = &SMMAP_CONF(dedup_no_clear),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "compress",
        .data            = &SMMAP_CONF(compress),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = smmap_compress_conf_dointvec,
    },
    {
        .procname        = "page_freq",
        .data            = &SMMAP_CONF(page_freq),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "skip_regs_info",
        .data            = &SMMAP_CONF(skip_regs_info),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "hwbp_skip_regs",
        .data            = &SMMAP_CONF(hwbp_skip_regs),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    { }
};


static struct ctl_table smmap_stats_table[] = {
    {
        .procname        = "num_procs",
        .data            = &SMMAP_STAT(num_procs),
        .maxlen          = sizeof(int),
        .mode            = 0444,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_maps",
        .data            = &SMMAP_STAT(num_maps),
        .maxlen          = sizeof(int),
        .mode            = 0444,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_checkpoints",
        .data            = &SMMAP_STAT(num_checkpoints),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_restores",
        .data            = &SMMAP_STAT(num_restores),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_rollbacks",
        .data            = &SMMAP_STAT(num_rollbacks),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_cows",
        .data            = &SMMAP_STAT(num_cows),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_atomics",
        .data            = &SMMAP_STAT(num_atomics),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_faults",
        .data            = &SMMAP_STAT(num_faults),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_dirty_pages",
        .data            = &SMMAP_STAT(num_dirty_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "log_last_entry",
        .data            = &smmap_oracle_log_size,
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = smmap_oracle_log_do_intvec,
    },
    {
        .procname        = "log_len",
        .data            = &smmap_oracle_log_size,
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_unique_pages",
        .data            = &SMMAP_STAT(num_unique_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_unique_crcs",
        .data            = &SMMAP_STAT(num_unique_crcs),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_total_pages",
        .data            = &SMMAP_STAT(num_total_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    {
        .procname        = "num_spec_pages",
        .data            = &SMMAP_STAT(num_spec_pages),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = proc_dointvec,
    },
    /* Currently, this entry is expressed in KB to account for the fact
       that the size could exceed sizeof(int). This should further improved to
       avoid overflow. */
    {
        .procname        = "compressed_size",
        .data            = &SMMAP_STAT(compressed_size),
        .maxlen          = sizeof(int),
        .mode            = 0666,
        .proc_handler    = smmap_compress_stat_dointvec,
    },
    { }
};

static struct ctl_table smmap_info_table[] = {
    {
        .procname        = "sizes",
        .data            = &smmap_sizes,
        .maxlen          = INFO_SIZES_STR_SIZE,
        .mode            = 0444,
        .proc_handler    = __smmap_sysctl_sizes,
    },
    {
        .procname        = "page_freq",
        .data            = &smmap_page_freq.string,
        .maxlen          = PAGE_STATS_SIZE,
        .mode            = 0444,
        .proc_handler    = smmap_dedup_page_freq_sysctl,
    },
    {
        .procname        = "page_zeroed_count",
        .data            = &smmap_page_freq.num_zeroed,
        .maxlen          = sizeof(int),
        .mode            = 0444,
        .proc_handler    = proc_dointvec,
    },
    {}
};

static struct ctl_table smmap_table[] = {
    {
        .procname        = "conf",
        .mode            = 0555,
        .child           = smmap_conf_table,
    },
    {
        .procname        = "stats",
        .mode            = 0555,
        .child           = smmap_stats_table,
    },
    {
        .procname        = "ctl",
        .data            = &smmap_ctl,
        .maxlen          = sizeof(smmap_ctl),
        .mode            = 0222,
        .proc_handler    = smmap_ctl_proc_handler,
    },
    /* String file for information only */
    {
        .procname        = "info",
        .mode            = 0555,
        .child           = smmap_info_table,
    },
    { }
};

static struct ctl_table smmap_dir[] = {
    {
        .procname        = "smmap",
        .mode            = 0555,
        .child           = smmap_table,
    },
    { }
};

static struct ctl_table_header *sysctl_header;

static void __init init_sysctl(void)
{
    sysctl_header = register_sysctl_table(smmap_dir);
}

static void __exit cleanup_sysctl(void)
{
    unregister_sysctl_table(sysctl_header);
}

/* Kprobe handlers. */
#define SMMAP_KRETPROBE_RET_VAL(R) (regs_return_value(R))
#define SMMAP_KRETPROBE_SYS_ARG_VAL(R, A) (A == 1 ? (R)->bx : A == 2 ? (R)->cx :\
    A == 3 ? (R)->dx : A == 4 ? (R)->si : A == 5 ? (R)->di : 0)

#ifdef ENABLE_DEBUG
#define SMMAP_KRETPROBE_RET_DEBUG(RI, REGS) \
    do { \
        if (smmap_proc_lookup(current->mm)) { \
            unsigned long ret = SMMAP_KRETPROBE_RET_VAL(REGS); \
            DEBUG(DEBUG_L1, "%s returned %lu (0x%p)", \
                (RI)->rp->kp.symbol_name, ret, (void *) ret); \
        } \
    } while(0)
#define SMMAP_KRETPROBE_SYS_ENTRY_DEBUG(RI, REGS, N) \
    do { \
        if (smmap_proc_lookup(current->mm)) { \
            int i; \
            DEBUG(DEBUG_L1, "%s called with %d arguments.", \
                (RI)->rp->kp.symbol_name, (N)); \
            for (i=1; i <= (N); i++) { \
                unsigned long arg = SMMAP_KRETPROBE_SYS_ARG_VAL(REGS, i); \
                DEBUG(DEBUG_L1, "%s%lu (0x%p)%s", ((i == 1) ? "[ " : ", "), \
                    arg, (void *) arg, ((i == (N)) ? " ]": "")); \
            } \
        } \
    } while(0)
#else
#define SMMAP_KRETPROBE_RET_DEBUG(RI, REGS)
#define SMMAP_KRETPROBE_SYS_ENTRY_DEBUG(RI, REGS, N)
#endif

static void do_deferred_exit(struct work_struct *work)
{
    smmap_work_t *smmap_work = (smmap_work_t*) work;
    smmap_proc_t *proc;

    mutex_lock(&smmap_ctl_lock);
    proc = smmap_proc_lookup((struct mm_struct*) smmap_work->data);
    if (proc) {
        DEBUG(DEBUG_L1, "deferred exit pid: %lu", smmap_work->pid);
        smmap_map_destroy_all(proc);
    }
    mutex_unlock(&smmap_ctl_lock);

    kfree(smmap_work);
}

static int kretprobe_do_exit_entry_handler(struct kretprobe_instance *ri,
    struct pt_regs *regs)
{
    smmap_proc_t *proc;
    smmap_work_t *smmap_work;

    /* check if the owner of mm is actually completing the execution. In case
       of multiple threads, each thread calls do_exit so we need to guarantee
       that only the last thread triggers a cleanup */
    if (current->mm != NULL && current != current->mm->owner) return 0;

    SMMAP_KRETPROBE_SYS_ENTRY_DEBUG(ri, regs, 1);

    proc = smmap_proc_lookup(current->mm);
    if (proc) {
        smmap_work = (smmap_work_t*)kmalloc(sizeof(smmap_work_t), GFP_ATOMIC);
        if (!smmap_work) {
            BUG();
        }

        smmap_work->data = current->mm;
        smmap_work->pid = task_pid_nr(current);
        INIT_WORK((struct work_struct *) smmap_work, do_deferred_exit);
        queue_work(smmap_wq, (struct work_struct *) smmap_work);
    }

    return 0;
}

struct kretprobe kretprobes[] = {
    {
        .kp                 = { .symbol_name = "do_exit" },
        .entry_handler      = kretprobe_do_exit_entry_handler,
        .maxactive          = NR_CPUS,
    },
    {}
};

static int init_kretprobe(struct kretprobe *probe)
{
    int ret;

    ret = register_kretprobe(probe);
    if (ret < 0) {
        printk("smmap: register_kretprobe for %s failed, returned %d\n",
            probe->kp.symbol_name, ret);
        return ret;
    }
    printk("smmap: registered ret probe at %s: 0x%p\n",
        probe->kp.symbol_name, probe->kp.addr);

    return 0;
}

static void cleanup_kretprobe(struct kretprobe *probe)
{
    unregister_kretprobe(probe);
    printk("smmap: %s ret probe unregistered (%d probings missed)\n",
        probe->kp.symbol_name, probe->nmissed);
}

static smmap_map_t *__handle_mm_fault_get_map(struct mm_struct *mm,
        struct vm_area_struct *vma, unsigned long address)
{
    smmap_map_t *smmap_map;
    smmap_proc_t *smmap_proc;
    if (!is_cow_mapping(vma->vm_flags) || !SMMAP_CONF(wrprotect)) return NULL;

    /* Go lockless, we'll perform (consistent) lookups again later. */
    smmap_proc = smmap_proc_lookup(mm);
    if (!smmap_proc) return NULL;

    if (!(smmap_map = smmap_map_lookup(smmap_proc, &address, NULL)))
        return  NULL;

    return smmap_map;
}


static void __smmap_map_handle_mm_fault_checkpoint_no_pte(smmap_map_t *smmap_map,
        unsigned long address)
{
    const char *event = "fault";
    smmap_proc_t *proc = smmap_map->owner;
    smmap_page_t *spp;
    struct page *anonp;

    /* XXX:
       when could this happen?
       a) when a memory area under smmap is unmapped and then remapped.
          Possibly, the kernel might remove the fileds (ptes, pmds) from the
          memory data-strcutures and we might not be able to access the page
       b) if pages are zapped. Currently we do not zap pages, and even in case
          we do, anonymous pages would still map to zero filled pages. However,
          this does *not apply for files* (will need to think about it later) */

    /* prepare page */
    spp = smmap_page_alloc();
    spp->proc = proc;
    spp->addr = address;

    /* by design, when a area is newly mapped into the process, such a page
       is anonymous and zero-ed out. Based on this assumption, since we
       cannot allocate the pgd/pmd/pte structures, we assumes such pages are
       zero filled */
    anonp = smmap_page_wq_retrieve(true);
    smmap_page_set_page(spp, anonp);
    /* XXX: add logic for deduplication and compression when requested */

    /* add page to the checkpoint list */
    smmap_plist_add(&proc->checkpoint, spp, event);

    SMMAP_STAT_INC(num_faults);
}


static void
__smmap_map_handle_mm_fault_checkpoint_cow(smmap_map_t *smmap_map,
        struct vm_area_struct *vma, pte_t *ptep, unsigned long address)
{
    struct page *orig_page;
    smmap_proc_t *proc = smmap_map->owner;
    smmap_page_t *spp;
    int ret;

    orig_page = smmap_vm_normal_page(vma, address, *ptep);

    /* preapre the smmap page */
    spp = smmap_page_alloc();
    spp->proc = proc;
    spp->addr = address;
    /* copy page */
    if ((ret = smmap_page_copy_page(spp, orig_page, NULL, true)) < 0 ||
        !smmap_page_has_page(spp)) {

        struct page *anonp;

        printk(KERN_ALERT "The page was not present, restoring "
            "default anonymous page (address=0x%p).\n", (void *) address);
        anonp = smmap_page_wq_retrieve(true);
        smmap_page_set_page(spp, anonp);
    }
    /* add page to the checkpoint list */
    smmap_plist_add(&proc->checkpoint, spp, "COW");

    SMMAP_STAT_INC(num_cows);
}

static void
__smmap_map_handle_mm_fault_rb(smmap_map_t *smmap_map,
    struct vm_area_struct *vma, pte_t *ptep, unsigned long address,
    unsigned int flags)
{
    struct page *oldp, *newp;
    smmap_proc_t *proc = smmap_map->owner;
    smmap_page_t *spp;
    static char *event = "rb fault";
    int ret;

    if (!(flags & FAULT_FLAG_WRITE) || pte_write(*ptep)) return;

    ret = smmap_plist_contains(&proc->present, NULL, address, event);
    if (ret == 1) return;
    else if (ret < 0) {
        printk(KERN_ALERT "Error handling fault during rollback "
            "(err=%d).\n", ret);
        BUG();
    }

    oldp = smmap_vm_normal_page(vma, address, *ptep);

    /* preapre the smmap page */
    spp = smmap_page_alloc();
    spp->addr = address;
    /* copy the page before the write takes effect; we need to copy
       also the flags of the page */
    newp = smmap_copy_page(oldp, NULL);
    smmap_page_set_ppage(spp, newp);
    if (pte_write(*ptep)) smmap_flag_set(spp, SMMAP_PAGE_FLAG_IS_WRITE);

    /* add page to the present list */
    smmap_plist_add(&proc->present, spp, event);
}


static void
__smmap_map_handle_mm_fault_checkpoint_generic(smmap_map_t *smmap_map,
        struct vm_area_struct *vma, pte_t *pte, unsigned long address,
        unsigned int flags)
{
    if (pte == NULL || !pte_present(*pte)) {
        __smmap_map_handle_mm_fault_checkpoint_no_pte(smmap_map, address);
    } else if ((flags & FAULT_FLAG_WRITE) && !pte_write(*pte)) {
        __smmap_map_handle_mm_fault_checkpoint_cow(smmap_map, vma, pte, address);
    }
}


static void
__smmap_map_handle_mm_fault_checkpoint_oracle_cow(smmap_map_t *smmap_map,
        struct vm_area_struct *vma, pte_t *pte, unsigned long address)
{
    /* normally we would turn this into a COW
     * but as we are recording we don't */
    smmap_proc_t *proc = smmap_map->owner;
    smmap_page_t *spp;

    /* prepare the smmap page */
    spp = smmap_page_alloc();
    spp->proc = proc;
    spp->addr = address;
    smmap_page_set_page(spp, smmap_vm_normal_page(vma, address, *pte));
    /* add the smmap page */
    smmap_plist_add(&proc->checkpoint, spp, "ORACLE");
    if (smmap_oracle_log_size < SMMAP_ORACLE_LOG_MAXSIZE) {
        smmap_oracle_log[smmap_oracle_log_pos]++;
    }
}


static void
__smmap_map_handle_mm_fault_checkpoint_oracle(smmap_map_t *smmap_map,
        struct vm_area_struct *vma, pte_t *pte, unsigned long address,
        unsigned int flags)
{
    if(SMMAP_CONF(oracle) == SMMAP_ORACLE_REPLAY)
        return;
    if (!pte_present(*pte)) {
        __smmap_map_handle_mm_fault_checkpoint_no_pte(smmap_map, address);
    } else if ( ((flags & FAULT_FLAG_WRITE) && !pte_write(*pte)) ) {
        __smmap_map_handle_mm_fault_checkpoint_oracle_cow(smmap_map,
                vma, pte, address);
    }
}


static void
__smmap_map_handle_mm_fault_checkpoint(smmap_map_t *smmap_map,
        struct vm_area_struct *vma, pte_t *pte, unsigned long address,
        unsigned int flags)
{
    if(SMMAP_CONF(oracle)) {
        __smmap_map_handle_mm_fault_checkpoint_oracle(
                smmap_map, vma, pte, address, flags);
        return;
    } else {
        __smmap_map_handle_mm_fault_checkpoint_generic(
                smmap_map, vma, pte, address, flags);
    }
}

static int jprobe_handle_mm_fault_entry_handler(struct mm_struct *mm,
    struct vm_area_struct *vma, unsigned long address, unsigned int flags)
{
    /* XXX
     * Due to the restrictions imposed by executing in a kprobe context,
     * this code assumes some conditions, which, if not respected, could
     * break the correctness of the checkpoint.
     *
     * a) Huge tables: currently, we are ignoring HugeTables. The function
     *                 handle_mm_fault deals with the specified special cases
     *                 and occasionally requires to allocate memory.
     *                 Additionally, many of the functions required to deal
     *                 with huge tables are not exported.
     * b) Impossible allocate pgd/pud/pmd entries: code paths that allocate the
     *                 intermediate elements table entries perform GFP_KERNEL
     *                 allocations. In kprobe context we cannot do the same.
     *                 This means that, if the debugged information unmaps often
     *                 memory areas, we are going to lose the pages changed
     *                 later.
     *                 To avoid this issue, we let the "failures" pass through
     *                 and at rollback we simply retrieve a zero filled page.
     *                 This approach does not work with file mapped pages. We
     *                 will have a wrong rollback in such a case.
     */

    pgd_t *pgd;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    pte_t *pte = NULL;
    smmap_map_t *smmap_map;
    unsigned long aligned = 0;

    if ((smmap_map = __handle_mm_fault_get_map(mm, vma, address)) == NULL)
        goto out;

    aligned = PAGE_ALIGNED(address) ? address : PAGE_ALIGN(address) - PAGE_SIZE;
    /* Determine if we are able to handle the COW */
    pgd = pgd_offset(mm, address);
    if (!pgd_none(*pgd)) pud = pud_offset(pgd, address);
    if (!pud || pud_none(*pud)) {
        DEBUG(DEBUG_L1, KERN_ALERT "unable to determine PUD @0x%p",
            (void *) aligned);
        goto handle;
    }
    pmd = pmd_offset(pud, address);
    if (!pmd || pmd_none(*pmd)) {
        DEBUG(DEBUG_L1, KERN_ALERT "unable to determine PMD @0x%p",
            (void *) aligned);
        goto handle;
    }
    pte = pte_offset_map(pmd, address);
    if (!pte) {
        DEBUG(DEBUG_L1, KERN_ALERT "unable to determine PTE @0x%p",
            (void *) aligned);
        goto handle;
    }

handle:
    if (!smmap_rb_info_is_in_rb(&smmap_map->owner->rb_info)) {
        __smmap_map_handle_mm_fault_checkpoint(smmap_map, vma, pte,
                aligned, flags);
    } else {
        __smmap_map_handle_mm_fault_rb(smmap_map, vma, pte, aligned, flags);
    }

out:
    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}

static struct jprobe jprobes[] = {
    {
        .kp = { .symbol_name = "handle_mm_fault" },
        .entry = jprobe_handle_mm_fault_entry_handler,
    },
    {}
};

static int init_jprobe(struct jprobe *probe)
{
    int ret;

    ret = register_jprobe(probe);
    if (ret < 0) {
        printk("smmap: register_jprobe for %s failed, returned %d\n",
            probe->kp.symbol_name, ret);
        return ret;
    }
    printk("smmap: registered jprobe at %s: 0x%p\n",
        probe->kp.symbol_name, probe->kp.addr);

    return 0;
}

static void cleanup_jprobe(struct jprobe *probe)
{
    unregister_jprobe(probe);
    printk("smmap: %s jprobe unregistered\n",
        probe->kp.symbol_name);
}

static int __init init_kprobes(void)
{
    int kret_idx, j_idx , cleanup_until, ret = 0;

    for(kret_idx=0; kretprobes[kret_idx].kp.symbol_name; kret_idx++) {
        ret = init_kretprobe(&kretprobes[kret_idx]);
        if (ret < 0) {
            goto cleanup_kretprobes;
        }
    }

    for(j_idx=0; jprobes[j_idx].kp.symbol_name; j_idx++) {
        ret = init_jprobe(&jprobes[j_idx]);
        if (ret < 0) {
            goto cleanup_jprobes;
        }
    }

    return ret;

cleanup_jprobes:
    cleanup_until = j_idx;
    printk("smmap: cleaning up jprobes\n");
    for(j_idx = 0; j_idx < cleanup_until; j_idx++) {
        cleanup_jprobe(&jprobes[j_idx]);
    }

cleanup_kretprobes:
    cleanup_until = kret_idx;
    printk("smmap: cleaning up kretprobes\n");
    for(kret_idx = 0; kret_idx < cleanup_until; kret_idx++) {
        cleanup_kretprobe(&kretprobes[kret_idx]);
    }

    return ret;
}

static void cleanup_kprobes(void)
{
    int i;

    for(i=0; kretprobes[i].kp.symbol_name; i++) {
        cleanup_kretprobe(&kretprobes[i]);
    }

    for(i=0; jprobes[i].kp.symbol_name; i++) {
        cleanup_jprobe(&jprobes[i]);
    }
}

static int smmap_check_modparams(void)
{
    if (journal_size < 0) {
        printk("journal size cannot be negative.\n");
        return -EINVAL;
    }

    return 0;
}

static void smmap_data_init(void)
{
    size_t size;
    char *buff;
    int i;

    size = sizeof(smmap_proc_t)+max_maps*sizeof(smmap_map_t);
    size *= max_procs;
    buff = kzalloc(size, GFP_KERNEL);

    smmap.procs = (smmap_proc_t*) buff;
    buff += max_procs*sizeof(smmap_proc_t);
    for (i=0; i<max_procs; i++) {
        smmap.procs[i].maps = (smmap_map_t*) buff;
        buff += max_maps*sizeof(smmap_map_t);
    }

    BUG_ON(buff != (char*)smmap.procs+size);

    for (i=0;i<SMMAP_NUM_PRIV_PAGES;i++) {
        smmap_priv_pages[i] = alloc_page(GFP_HIGHUSER_MOVABLE);
        BUG_ON(!smmap_priv_pages[i]);
    }
}

static void smmap_data_close(void)
{
    int i;

    kfree(smmap.procs);

    for (i=0;i<SMMAP_NUM_PRIV_PAGES;i++) {
        __free_page(smmap_priv_pages[i]);
    }
}

static int __init smmap_init(void)
{
    int ret;

#ifdef ENABLE_DEBUG
    /* set the value of the debug verbosity based on the value of the module
       parameter into the module configuration */
    SMMAP_CONF(debug_verbosity) = debug_verbosity;
#endif

    /* check module parameters */
    if ((ret = smmap_check_modparams()) != 0) return ret;

    if (smmap_oracle_log_enabled) {
        smmap_oracle_log = vmalloc(smmap_oracle_log_maxsize * sizeof(int));
        printk("allocated log with %d entries\n", smmap_oracle_log_maxsize);
        if (!smmap_oracle_log)
            return -ENOMEM;
        smmap_oracle_log[0] = 0;
    }

    DEBUG(DEBUG_L1, "init requested");
    ret = init_kprobes();
    if (ret < 0) return ret;
    smmap_wq = create_workqueue("smmap_wq");
    if (!smmap_wq) {
        cleanup_kprobes();
        return -ENOMEM;
    }
    /* this is required by all the code dealing with lists */
    smmap_plist_node_init();
    smmap_dedup_init();
    smmap_compress_init();
    smmap_data_init();
    smmap_import_init();
    smmap_page_init();
    smmap_page_wq_init();
    init_sysctl();
    printk("smmap: module loaded\n");

    return 0;
}

static void __exit smmap_exit(void)
{
    DEBUG(DEBUG_L1, "exit requested");
    flush_workqueue(smmap_wq);
    destroy_workqueue(smmap_wq);
    cleanup_sysctl();
    cleanup_kprobes();
    smmap_page_wq_close();
    smmap_page_close();
    smmap_data_close();
    smmap_compress_close();
    smmap_dedup_close();
    if (pagan_initialized) {
        pagan_deinit(smmap_pagan_destroy_cb);
    }
    /* this must be called after all the code dealing with lists */
    smmap_plist_node_destroy();
    printk("smmap: module unloaded\n");
}

module_init(smmap_init)
module_exit(smmap_exit)
MODULE_LICENSE("GPL");
