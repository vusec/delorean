#include <string.h>
#include <stdlib.h>

#include <libdl/smmap.h>
#include <libdl/smmap_lib.h>
#include <include/common/smmap_common.h>

int dl_map(void *addr, void *shadow_addr, size_t size)
{
    int ret;

    ret = smmap(addr, shadow_addr, size);
    smctl_is_smmapped = ret == 0;

    return ret;
}

int dl_unmap(void *addr)
{
    return smunmap(addr);
}

smmap_cp_info_t *dl_cp_info_alloc(void)
{
    smmap_cp_info_t *info;

    if (smctl_wmem->util.size < sizeof(smmap_ctl_info_t))
        return NULL;

    info = (smmap_cp_info_t *) smctl_wmem->util.ptr;
    memset(info, 0, sizeof(smmap_cp_info_t));
    return info;
}

int dl_checkpoint(smmap_cp_info_t *info)
{
    return smctl(SMMAP_SMCTL_CHECKPOINT, info);
}

int dl_set_checkpoint(unsigned long location)
{
    smmap_ctl_hwbp_t data = { .addr = location };

    return smctl(SMMAP_SMCTL_SET_CHECKPOINT, (void *) &data);
}

smmap_ctl_info_t *dl_get_info(int cp_id)
{
    smmap_ctl_info_t *datap;
    long ret;

    if (smctl_wmem->util.size < sizeof(smmap_ctl_info_t))
        return NULL;

    datap = (smmap_ctl_info_t *) smctl_wmem->util.ptr;
    memset(datap, 0, sizeof(smmap_ctl_info_t));

    datap->cp_id = cp_id;
    if ((ret = smctl(SMMAP_SMCTL_GET_INFO, (void *) datap)) < 0)
        return NULL;

    return datap;
}

int dl_is_initialized(void)
{
    return smctl_is_init && smctl_is_smmapped;
}

int dl_is_in_rb(void)
{
    return smctl(SMMAP_SMCTL_IS_IN_RB, NULL);
}

int dl_drop_checkpoint(unsigned long location)
{
    smmap_ctl_hwbp_t data = { .addr = location };

    return smctl(SMMAP_SMCTL_DROP_CHECKPOINT, (void *) &data);
}

int dl_dropall_checkpoints(void)
{
    return smctl(SMMAP_SMCTL_DROPALL_CHECKPOINTS, NULL);
}

int dl_search_start(void)
{
    return smctl(SMMAP_SMCTL_RB_SEARCH_START, NULL);
}

int dl_search_stop(void)
{
    return smctl(SMMAP_SMCTL_RB_SEARCH_STOP, NULL);
}

int dl_rollback(int checkpoint)
{
    smmap_ctl_rollback_t data = { .checkpoint = checkpoint };

    return smctl(SMMAP_SMCTL_ROLLBACK, (void *) &data);
}

int dl_restore(void)
{
    return smctl(SMMAP_SMCTL_RESTORE, NULL);
}

int dl_rollback_ondemand(smmap_ctl_rollback_ondemand_t *data, int checkpoint)
{
    if (data == NULL) return -EINVAL;

    data->checkpoint = checkpoint;
    return smctl(SMMAP_SMCTL_ROLLBACK_ONDEMAND, (void *) data);
}

smmap_ctl_rollback_ondemand_t *dl_vars_alloc(int slots)
{
    size_t slots_size, total_size;

    smmap_ctl_rollback_ondemand_t *datap;

    if (slots <= 0) return NULL;

    slots_size = slots * sizeof(smmap_rollback_var_t);
    total_size = slots_size + sizeof(smmap_ctl_rollback_ondemand_t);

    if (smctl_wmem->util.size < total_size)
        return NULL;

    datap = (smmap_ctl_rollback_ondemand_t *) smctl_wmem->util.ptr;
    memset(datap, 0, sizeof(smmap_ctl_rollback_ondemand_t));

    datap->slots = slots;
    datap->vars = (smmap_rollback_var_t *)
        sizeof(smmap_ctl_rollback_ondemand_t) + (unsigned long) datap;
    memset(datap->vars, 0, slots_size);

    return datap;
}

int dl_vars_set(smmap_ctl_rollback_ondemand_t *data, unsigned long addr,
    unsigned long size, int index)
{
    if (!data || index < 0 || index >= data->slots) return -EINVAL;

    /* set the variable information */
    data->vars[index].addr = addr;
    data->vars[index].size = size;

    if (++index >= data->slots) return -ENOMEM;

    return index;
}
