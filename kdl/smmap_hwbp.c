#include <smmap_defs.h>

#include <linux/ptrace.h>

void smmap_hwbp_init(smmap_proc_t *proc)
{
    if (!proc) return;

    memset(proc->hbreaks, 0, sizeof(struct perf_event *) * MAX_HWBREAKPOINTS);
}

int smmap_hwbp_set(smmap_proc_t *proc, smmap_ctl_hwbp_t *data)
{
    struct perf_event_attr attr;
    struct perf_event *bp;
    int i;

    if (!proc) return -EINVAL;

    ptrace_breakpoint_init(&attr);
    attr.bp_addr = data->addr;
    attr.disabled = 0;
    /* Values for x86 architectures; see ptrace.c and 
       arch/x86/include/asm/hw_breakpoint.h */
    attr.bp_len = sizeof(long);
    attr.bp_type = HW_BREAKPOINT_X;

    bp = register_user_hw_breakpoint(&attr, set_breakpoint_cb, NULL, current);
    if (IS_ERR(bp)) return -EPERM;

    /* Save the pointer of the breakpoint event. It is later used for retrieving
       information and deleting breakpoints */
    for (i=0; i<MAX_HWBREAKPOINTS; ++i) {
        if (proc->hbreaks[i] == NULL) {
            proc->hbreaks[i] = bp;
            break;
        }
    }
    if (i == 4) return -E2BIG;

    return 0;
}

int smmap_hwbp_drop(smmap_proc_t *proc, smmap_ctl_hwbp_t *data)
{
    int i;
    struct perf_event *bp;
    int ret = -EFAULT;

    if (!proc || !data) return -EINVAL;

    for (i=0; i<MAX_HWBREAKPOINTS; ++i) {
        bp = proc->hbreaks[i];
        if (bp && bp->attr.bp_addr == data->addr) {
            unregister_hw_breakpoint(bp);
            ret = 0;
        }
    }

    return ret;
}

void smmap_hwbp_cleanup(smmap_proc_t *proc)
{
    int i;

    if (!proc) return;

    for (i=0; i<MAX_HWBREAKPOINTS; ++i) 
        unregister_hw_breakpoint(proc->hbreaks[i]);
}
