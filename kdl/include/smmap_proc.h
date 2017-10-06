#ifndef _SMMAP_PROC_H_
#define _SMMAP_PROC_H_

#include <smmap_page_list.h>
#include <smmap_page_wq.h>
#include <smmap_map.h>
#include <smmap_hwbp.h>

#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/types.h>

typedef struct smmap_proc_s {
    unsigned char active;
    unsigned num_maps;
    struct mm_struct *mm;
    smmap_map_t *maps;
	int needs_tlb_flush;
	int use_pagan;
    smmap_rb_info_t rb_info;
    smmap_plist_t checkpoint; /* current checkpoint */
    smmap_cps_info_t checkpoints_info; /* information reguarding the current
                                          checkpoint */
    smmap_journal_t journal; /* checkpoint journal/database containing the
                                n-most recent checkpoints */
    smmap_plist_t present; /* list of present-state pages */
    struct perf_event *hbreaks[MAX_HWBREAKPOINTS]; /* hardware brekpoints */
} smmap_proc_t;

typedef struct smmap_s {
    smmap_stats_t stats;
    smmap_proc_t *procs;
} smmap_t;
extern smmap_t smmap;

#define SMMAP_PROC_PRINT(P) printk("PROC={ active=%d, num_maps=%d, pid=%d }", \
    (P)->active, (P)->num_maps, (P)->active ? task_pid_nr((P)->mm->owner) : 0)

#define SMMAP_PROC_ITER(P, B) do { \
    int __i, __num_procs = SMMAP_STAT(num_procs); \
    for (__i=0; __i<max_procs && __num_procs>0; __i++) { \
        if (smmap.procs[__i].active) { \
            P = &smmap.procs[__i]; \
            __num_procs--; \
            { B } \
        } \
    } \
} while(0)

void smmap_proc_print_all(void);
smmap_proc_t* smmap_proc_lookup(struct mm_struct *mm);
int smmap_proc_create(smmap_proc_t *data, smmap_proc_t **proc_ptr);
void smmap_proc_destroy(smmap_proc_t *proc);
int smmap_proc_start_interval(smmap_proc_t *proc);

extern int pagan_initialized;

#endif /* _SMMAP_PROC_H_ */
