#ifndef _SMMAP_COMMON_H_
#define _SMMAP_COMMON_H_

/* Definitions. */
#define SMMAP_DEFAULT_MAX_PROCS             256
#define SMMAP_DEFAULT_MAX_MAPS               10
#define SMMAP_NUM_PRIV_PAGES                100
#define SMMAP_DEFAULT_DEBUG_VERBOSITY         1

#define SMMAP_CTL_PATH "/proc/sys/smmap/ctl"

typedef enum smmap_ctl_op_e {
    SMMAP_CTL_SMMAP,
    SMMAP_CTL_SMUNMAP,
    SMMAP_CTL_SMCTL,
    __NUM_SMMAP_CTL_OPS
} smmap_ctl_op_t;

/* sysctl available actions */
typedef enum smmap_smctl_op_e {
    SMMAP_SMCTL_CHECKPOINT,
    SMMAP_SMCTL_SET_CHECKPOINT,  /* Add a checkpoint HW breakpoint */
    SMMAP_SMCTL_DROP_CHECKPOINT, /* Removes a checkpoint HW breakpoint */
    SMMAP_SMCTL_DROPALL_CHECKPOINTS, /* Drop all hardware breakpoints */
    SMMAP_SMCTL_TEST_PAGE, /* Test the content of a page in the
                              specified checkpoint */
    SMMAP_SMCTL_ROLLBACK_DEFAULT,
    SMMAP_SMCTL_ROLLBACK,
    SMMAP_SMCTL_ROLLBACK_ONDEMAND,
    /* Signal the start/stop of multiple searches in the journal. This will
       construct a temporary representation of the journal as a tree
       structure to make the looping over checkpoints faster. */
    SMMAP_SMCTL_RB_SEARCH_START,
    SMMAP_SMCTL_RB_SEARCH_STOP,
    SMMAP_SMCTL_SEARCH, /* In-kernel linear search, implemented only for
                           benchmark purposes */
    SMMAP_SMCTL_RESTORE,
    /* Information retrival entrypoints */
    SMMAP_SMCTL_GET_INFO,  /* Retrieves information related to the status of
                              the module and checkpoint info currently taken */
    SMMAP_SMCTL_IS_IN_RB,
    /* Statistics */
    SMMAP_SMCTL_GET_STATS,
    SMMAP_SMCTL_CLEAR_STATS,
    SMMAP_SMCTL_CLEAR_DEDUP,
    __NUM_SMMAP_SMCTL_OPS
} smmap_smctl_op_t;

/* Retrun types for the sysctl action "SMMAP_SMCTL_TEST_PAGE" */
typedef enum smmap_test_page_e {
    SMMAP_TEST_PAGE_MATCH,
    SMMAP_TEST_PAGE_NOT_FOUND,
    SMMAP_TEST_PAGE_NOT_MATCH,
} smmap_test_page_t;

/* Configuration values for the type of deduplication */
enum {
    DEDUP_TYPE_NONE, /* No deduplication */
    DEDUP_TYPE_PAGE, /* Deduplication page content */
    DEDUP_TYPE_CRC,  /* Deduplication using CRC */
    DEDUP_TYPE_NUM
};

/* Configuration options for the location where deduplication should be
   performed */
enum {
    DEDUP_LOCATION_COW_COPY,    /* Perform deduplication on COW; always copy */
    DEDUP_LOCATION_COW_SEARCH,  /* Perform deduplication on COW; copy only if
                                   necessary (page not found) */
    DEDUP_LOCATION_CP,          /* Perform deduplication on checkpoint */
    DEDUP_LOCATION_SPEC,        /* Perform deduplication only when speculating
                                   a page*/
    DEDUP_LOCATION_NUM
};

/* Configuration values for the type of compression */
enum {
    COMPRESS_NONE,
    COMPRESS_FIXUP,
    COMPRESS_COUNT,
};

/* Cleanup options for deduplication */
enum {
    DEDUP_CLEAR_NONE, /* do not clean orphans from the deduplication tree */
    DEDUP_CLEAR_ON_WIN_EXIT, /* Try clean-up pages with count dropped to 1
                                when the checkpoint exits the window */
    DEDUP_CLEAR_ON_COUNT, /* Try clean-up every n checkpoints */
    DEDUP_CLEAR_INLINE, /* Try clean-up while searching in the tree */
    DEDUP_CLEAR_COUNT
};

/* Control data structures. */
typedef struct __attribute__ ((__packed__)) smmap_ctl_smmap_s {
    void *addr;
    void *shadow_addr;
    unsigned long size;
} smmap_ctl_smmap_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_smunmap_s {
    void *addr;
} smmap_ctl_smunmap_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_smctl_s {
    smmap_smctl_op_t op;
    void *ptr;
} smmap_ctl_smctl_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_s {
    smmap_ctl_op_t op;
    union {
        smmap_ctl_smmap_t smmap;
        smmap_ctl_smunmap_t smunmap;
        smmap_ctl_smctl_t smctl;
    } u;
} smmap_ctl_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_rollback_s {
    int checkpoint;
}  smmap_ctl_rollback_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_hwbp_s {
    unsigned long addr; /* address where to set the breakpoint */
}  smmap_ctl_hwbp_t;

typedef struct __attribute__ ((__packed__)) smmap_cp_info_s {
    /* x86_64 registers */
    unsigned long pc;
    unsigned long ss;
    unsigned long cs;
    unsigned long eflags;
    /* general purpose */
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rbp;
    unsigned long rsp;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    /* other flags */
    int from_smmap;
    int is_unknown;
} smmap_cp_info_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_info_s {
    int cp_id; /* used as parameter by the user when requesting a
                  specific CP_ID */
    int max_cp_id;
    int is_in_rollback;
    smmap_cp_info_t cp_info;
} smmap_ctl_info_t;

typedef struct __attribute__ ((__packed__)) smmap_rollback_var_s {
    unsigned long addr;
    unsigned long size;
} smmap_rollback_var_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_rollback_ondemand_s {
    smmap_rollback_var_t *vars;
    int slots;
    int checkpoint;
} smmap_ctl_rollback_ondemand_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_test_page_s {
    unsigned long addr;
    unsigned long expected;
    int checkpoint;
} smmap_ctl_test_page_t;

typedef struct __attribute__ ((__packed__)) smmap_ctl_search_s {
    unsigned long addr;
    unsigned long size;
    void *valuep;
    unsigned short binary;
    unsigned short found;
} smmap_ctl_search_t;

typedef struct smmap_stats_s {
    unsigned num_procs;
    unsigned num_maps;
    unsigned num_checkpoints;
    unsigned num_restores;
    unsigned num_rollbacks;
    unsigned num_cows;
    unsigned num_atomics;
    unsigned num_faults;
    unsigned num_dirty_pages;
    /* deduplication */
    unsigned num_unique_pages;
    unsigned num_unique_crcs;
    unsigned num_total_pages;
    unsigned num_spec_pages;
    /* compression */
    unsigned compressed_size;
} smmap_stats_t;

#define SMMAP_STATS_PRINT(P, S) \
    P("STATS={ num_procs=%u, num_maps=%u, num_checkpoints=%u, " \
      "num_restores%u, num_rollbacks=%u, num_cows=%u, num_atomics=%u, " \
      "num_faults=%u, num_dirty_pages=%u, num_unique_pages=%u, " \
      "num_unique_crcs=%u, num_total_pages=%u, num_spec_pages=%u, " \
      "compressed_size=%u }", \
      (S)->num_procs, (S)->num_maps, (S)->num_checkpoints, (S)->num_restores, \
      (S)->num_rollbacks, (S)->num_cows, (S)->num_atomics, (S)->num_faults, \
      (S)->num_dirty_pages, (S)->num_unique_pages, (S)->num_unique_crcs, \
      (S)->num_total_pages, (S)->num_spec_pages, (S)->compressed_size)

#endif /* _SMMAP_COMMON_H_ */
