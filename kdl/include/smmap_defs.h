#ifndef _SMMAP_DEFS_H_
#define _SMMAP_DEFS_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <common/pagan/pagan.h>

#include <smmap/smmap_common.h>

#include <smmap_import.h>
#include <smmap_info.h>
#include <smmap_journal.h>
#include <smmap_deduplicate.h>
#include <smmap_compress.h>
#include <smmap_page_list.h>
#include <smmap_proc.h>
#include <smmap_hwbp.h>
#include <smmap_map.h>
#include <smmap_page.h>
#include <smmap_page_wq.h>
#include <ksym.h>

/* Identifier of the process running, hence not rollbacked. A non-negative
   value indicates that the process is currently rollbacked */
#define PRESENT_STATE  -1

/* debugging levels */
#define DEBUG_L1     1
#define DEBUG_L2     2
#define DEBUG_L3     3
/* debugging macro (disabled by default at compile time) */
#ifdef ENABLE_DEBUG
extern int debug_verbosity;
/**
 * DEBUG - macro to print debugging messages. This macro is completely
 *         disabled at compilation time to remove the overhead of conditions
 *         evaluations at runtime.
 *         The macro appends information to the debugging message in respect
 *         to the context of execution.
 *         oid: owner process id, namely the process for which SMMAP is doing
 *              bookkeeping. If this information is not available, the entry
 *              is not shown.
 *         tid: the thread ID which is currently taking care of the execution.
 *              This number can differ from the oid in various contexts, like
 *              interrupt handlers and do_exit deferred tasks.
 *         func: function name where the debug message is produced.
 *
 *
 * L: debugging level
 * FMT: format string
 * ...: variadic variables used in the format string
 */
#define DEBUG(L, FMT, ...) \
    do { \
        if (L <= SMMAP_CONF(debug_verbosity)) { \
            struct pid *pid; \
            struct task_struct *owner; \
            if (current->mm != NULL && (owner = current->mm->owner) != NULL && \
                (pid = get_task_pid(owner, PIDTYPE_PID)) != NULL) { \
                printk("smmap: [oid=%d][tid=%d][func=%s] " FMT "\n", \
                    pid_nr(pid), task_pid_nr(current), __func__, \
                    ## __VA_ARGS__); \
                put_pid(pid); \
            } else { \
                printk("smmap: [tid=%d][func=%s] " FMT "\n", \
                    task_pid_nr(current), __func__, ## __VA_ARGS__);  \
            } \
        } \
    } while (0)
#else
#define DEBUG(L, FMT, ...)
#endif

#ifndef PAGE_ALIGNED
#define PAGE_ALIGNED(addr)      IS_ALIGNED((unsigned long)addr, PAGE_SIZE)
#endif

#ifndef is_cow_mapping
#define is_cow_mapping(F) (((F) & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE)
#endif

#ifndef VM_DONTDUMP
#define VM_DONTDUMP VM_NODUMP
#endif

typedef struct smmap_conf_s {
    int wrprotect;
    int shadow;
    int shadow_zero_pages;
    int tlb_batch_flush;
    int spc_type;
    int simulate_copying_num_checkpointed_pages;
    int count_mergeable_pages;
    int use_pagan;
    int pagan_mechanism;
    int oracle;
#ifdef ENABLE_DEBUG
    int debug_verbosity;
#endif
    char pagan_config_value[PAGAN_CONF_KEY_LEN*2];
    int dedup_type;
    int dedup_location;
    int dedup_clear;
    int dedup_clear_count;
    int dedup_no_clear;
    int compress;
    int page_freq;
    int skip_regs_info;
    /* enable/disable hardware-breakpoint capability to checkpoint registers */
    int hwbp_skip_regs;
} smmap_conf_t;
extern smmap_conf_t smmap_conf;

/* Module parameters */
extern int max_procs;
extern int max_maps;
extern int max_pages;
extern int journal_size;


#define SMMAP_CONF(C)          (smmap_conf.C)
#define SMMAP_CONF_INITIALIZER { .wrprotect = 1, .shadow = 0 }

#define SMMAP_STAT(S)     (smmap.stats.S)
#define SMMAP_STAT_INC(S) (SMMAP_STAT(S)++)
#define SMMAP_STAT_DEC(S) (SMMAP_STAT(S)--)

#define SMMAP_ORACLE_NONE   0
#define SMMAP_ORACLE_RECORD 1
#define SMMAP_ORACLE_REPLAY 2
#define SMMAP_ORACLE_LOG_DEFAULT_MAXSIZE  (1024*1024*100)
#define SMMAP_ORACLE_LOG_MAXSIZE smmap_oracle_log_maxsize

/* declared in smmap_mod.c */
extern int *smmap_oracle_log;
extern int smmap_oracle_pos;
extern int smmap_oracle_size;
extern int smmap_oracle_log_maxsize;
extern int smmap_oracle_enabled;

/* compatibility checks */
#define check_dedup_and_compress() \
    do { \
        bool __both_enabled = SMMAP_CONF(dedup_type) != DEDUP_TYPE_NONE && \
            SMMAP_CONF(compress) != COMPRESS_NONE; \
        bool __both_compatible = SMMAP_CONF(dedup_type) != DEDUP_TYPE_NONE && \
            SMMAP_CONF(dedup_location) == DEDUP_LOCATION_CP && \
            SMMAP_CONF(compress) == COMPRESS_FIXUP; \
        if (__both_enabled && !__both_compatible) { \
            printk(KERN_ALERT "smmap: incompatible compress and dedup_type"); \
            printk(KERN_NOTICE "smmap: compression and deduplication " \
                "can only be mixed if *both* are executed at *fixup*.\n"); \
            SMMAP_CONF(dedup_type) = DEDUP_TYPE_NONE; \
            smmap_dedup_clear(); \
            printk(KERN_NOTICE "smmap: deduplication disabled (value: %d)\n", \
                SMMAP_CONF(dedup_type)); \
            SMMAP_CONF(compress) = COMPRESS_NONE; \
            printk(KERN_NOTICE "smmap: compression disabled (value: %d)\n", \
                SMMAP_CONF(compress)); \
        } \
    } while(0);

#include <smmap_pte.h>

#endif /* _SMMAP_DEFS_H_ */
