#include <smmap_defs.h>


void smmap_cps_info_init(smmap_cps_info_t *cps_infop)
{
    memset(cps_infop, 0, sizeof(smmap_cps_info_t));
    cps_infop->slots = journal_size+1;
    /* allocate array of pointers that will point to the
       information checkpointed */
    cps_infop->info = (smmap_cp_info_t **) vmalloc(
        sizeof(smmap_cp_info_t *)*cps_infop->slots);
    memset(cps_infop->info, 0, sizeof(smmap_cp_info_t *)*cps_infop->slots);
}

void smmap_cps_info_destroy(smmap_cps_info_t *cps_infop)
{
    int i;

    for (i=0; i<cps_infop->slots; ++i)
        if (cps_infop->info[i])
            kfree(cps_infop->info[i]);

    vfree(cps_infop->info);
    memset(cps_infop, 0, sizeof(smmap_cps_info_t));
}

int smmap_cps_info_set(smmap_cps_info_t *cps_infop, smmap_cp_info_t *cp_infop,
    bool is_smmap)
{
    if (cp_infop == NULL && !is_smmap) return -EINVAL;

    /* Only the first call of smmap requires to set the information pointer
       since the "current interval" just started. All the other requestes are
       part of an already on-going interval, hence the information do not
       change */
    if (is_smmap && cps_infop->inuse)
        return 0;

    if (!cps_infop->inuse) {
        cps_infop->inuse = cps_infop->info;
    } else {
        int idx;
        unsigned long inuse_addr = (unsigned long) cps_infop->inuse;
        unsigned long info_addr = (unsigned long) cps_infop->info;

        idx = (int)((inuse_addr - info_addr) / sizeof(smmap_cp_info_t *));
        if (idx < 0) return -ERANGE;
        idx = (idx + 1) % cps_infop->slots;
        cps_infop->inuse = &cps_infop->info[idx];
    }

    *(cps_infop->inuse) = (smmap_cp_info_t *) kmalloc(
            sizeof(smmap_cp_info_t), GFP_KERNEL);

    if (cp_infop) {
        cp_infop->from_smmap = is_smmap;
        memcpy(*cps_infop->inuse, cp_infop, sizeof(smmap_cp_info_t));
    } else {
        /* set an unknown flag just to identify that the information in this
           case cannot be registered */
        memset(cps_infop->inuse, 0, sizeof(smmap_cp_info_t));
        (*cps_infop->inuse)->from_smmap = is_smmap;
        (*cps_infop->inuse)->is_unknown = 1;
    }

    return 0;
}

smmap_cp_info_t *smmap_cps_info_get(smmap_cps_info_t *cps_infop, int id)
{
    int idx;
    unsigned long inuse_addr;
    unsigned long info_addr;

    if (!cps_infop || id >= cps_infop->slots || id < 0)
        return ERR_PTR(-EINVAL);

    inuse_addr = (unsigned long) cps_infop->inuse;
    info_addr = (unsigned long) cps_infop->info;

    idx = (int)((inuse_addr - info_addr) / sizeof(smmap_cp_info_t *));
    if (idx < 0) return ERR_PTR(-ERANGE);
    idx = (idx - id) % cps_infop->slots;
    idx = (idx < 0) ? idx + cps_infop->slots : idx;

    return cps_infop->info[idx];
}


void smmap_cp_info_init(smmap_cp_info_t *cp_infop)
{
    if (cp_infop == NULL) return;

    memset(cp_infop, 0, sizeof(smmap_cp_info_t));
}


void smmap_rb_info_init(smmap_rb_info_t *rb_infop)
{
    if (rb_infop == NULL) return;

    memset(rb_infop, 0, sizeof(smmap_rb_info_t));
    rb_infop->cp_id = PRESENT_STATE;
}

void smmap_rb_info_set(smmap_rb_info_t *rb_infop, smmap_cps_info_t *cps_infop,
    int cp_id)
{
    if (rb_infop == NULL) return;

    rb_infop->cp_id = cp_id;
    /* search for the associated checkpoint information */
    rb_infop->cp_info = smmap_cps_info_get(cps_infop, cp_id);
}

int smmap_rb_info_get_id(smmap_rb_info_t *rb_infop)
{
    return rb_infop->cp_id;
}

bool smmap_rb_info_needs_rb(smmap_rb_info_t *rb_infop, int cp_id)
{
    if (rb_infop->cp_id == PRESENT_STATE) return true;

    if (rb_infop->cp_id == cp_id) return false;

    return true;
}

bool smmap_rb_info_is_in_rb(smmap_rb_info_t *rb_infop)
{
    if (!rb_infop || rb_infop->cp_id == PRESENT_STATE) return false;

    return true;
}

void smmap_rb_info_reset(smmap_rb_info_t *rb_infop)
{
    smmap_rb_info_init(rb_infop);
}
