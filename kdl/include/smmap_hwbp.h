#ifndef _SMMAP_HWBP_H_
#define _SMMAP_HWBP_H_

#include <linux/hw_breakpoint.h>

#define MAX_HWBREAKPOINTS   4

void smmap_hwbp_init(smmap_proc_t *proc);
int smmap_hwbp_set(smmap_proc_t *proc, smmap_ctl_hwbp_t *data);
int smmap_hwbp_drop(smmap_proc_t *proc, smmap_ctl_hwbp_t *data);
void smmap_hwbp_cleanup(smmap_proc_t *proc);

/* this callback is defined in smmap_mod.c */
void set_breakpoint_cb(struct perf_event *bp, struct perf_sample_data *data,
    struct pt_regs *regs);

#endif /* _SMMAP_HWBP_H_ */
