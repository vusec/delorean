#ifndef _SMMAP_CP_INFO_H_
#define _SMMAP_CP_INFO_H_

#include <smmap/smmap_common.h>

typedef struct smmap_cps_info_s {
    smmap_cp_info_t **info; /* array of elements. The size corresponds to all
                               the available checkpoints, hence
                               journal-size + 1 */
    smmap_cp_info_t **inuse;
    int slots;
} smmap_cps_info_t;

typedef struct smmap_rb_info_s {
    int cp_id;
    smmap_cp_info_t *cp_info;
} smmap_rb_info_t;


/* Management functions for checkpoints information */
void smmap_cps_info_init(smmap_cps_info_t *cps_infop);
void smmap_cps_info_destroy(smmap_cps_info_t *cps_infop);
int smmap_cps_info_set(smmap_cps_info_t *cps_infop, smmap_cp_info_t *cp_infop,
    bool is_smmap);
smmap_cp_info_t *smmap_cps_info_get(smmap_cps_info_t *cps_infop, int id);

/* Management functions for single checkpoint information */
void smmap_cp_info_init(smmap_cp_info_t *cp_infop);

/* Management functions for rollback information */
void smmap_rb_info_init(smmap_rb_info_t *rb_infop);
void smmap_rb_info_set(smmap_rb_info_t *rb_infop, smmap_cps_info_t *cps_infop,
    int cp_id);
int smmap_rb_info_get_id(smmap_rb_info_t *rb_infop);
bool smmap_rb_info_needs_rb(smmap_rb_info_t *rb_infop, int cp_id);
bool smmap_rb_info_is_in_rb(smmap_rb_info_t *rb_infop);
void smmap_rb_info_reset(smmap_rb_info_t *rb_infop);

#endif /* _SMMAP_CP_INFO_H_ */
