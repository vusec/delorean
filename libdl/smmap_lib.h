/* Shared Library SMMAP header
 *
 * In some occasions we want SMMAP to be available as a shared library. In
 * this manner the functionality can be injected inside a process and used
 * directly from inside the application. This header is realted to the shared
 * library verions of the SMMAP user API.
 *
 * NB: clean-up has to be done in a proper context. In the GDB plugin where
 *     this library is extensively used, we avoid using the cleanup function
 *     since exit_group will cause cleanup anyway.
 */

#ifndef _SMMAP_LIB_H_
#define _SMMAP_LIB_H_

#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <smmap/smmap_common.h>

#define WORKER_STACK_SIZE       PTHREAD_STACK_MIN
#define WORKER_MEM_SIZE    4096

typedef struct smctl_wmem_s {
    pthread_t thread;
    int lwp;
    void *stack;
    pthread_cond_t condlwp; /* lwp access condition */
    pthread_cond_t condc; /* consumer condition */
    pthread_mutex_t mutex;
    unsigned short has_to_stop;
    /* The rest of the memory area is used for parameter passing to avoid
       using malloc (libc is generally under checkpointing). */
    struct util_s {
        void *ptr;
        size_t size;
    } util;
} smctl_wmem_t;


smctl_wmem_t *smctl_wmem = NULL;
bool smctl_is_init = false;
bool smctl_is_smmapped = false;

int tm_map(void *addr, void *shadow_addr, size_t size);
int tm_unmap(void *addr);
/* checkpoint specific functions */
smmap_cp_info_t *tm_cp_info_alloc(void);
void tm_cp_info_destory(smmap_cp_info_t *info);
int tm_checkpoint(smmap_cp_info_t *info);
/* information retrival */
smmap_ctl_info_t *tm_get_info(int cp_id);
int tm_is_in_rb(void);
int tm_is_initialized(void);

int tm_set_checkpoint(unsigned long location);
int tm_drop_checkpoint(unsigned long location);
int tm_dropall_checkpoints(void);
int tm_search_start(void);
int tm_search_stop(void);
int tm_rollback(int checkpoint);
int tm_restore(void);
pthread_t tm_get_worker_tid(void);
/* On-Demand rollback API. This set of functions is meant for GDB to allocate,
   initialize and cleanup the required memory to provide the areas to the
   kernel space */
int tm_rollback_ondemand(smmap_ctl_rollback_ondemand_t *data, int checkpoint);
smmap_ctl_rollback_ondemand_t *tm_vars_alloc(int slots);
void tm_vars_destroy(smmap_ctl_rollback_ondemand_t *data);


/* WORKER LOGIC - Used by GDB to perform operations on stack and heap. */
static void *smctl_worker() {
    pthread_mutex_lock(&smctl_wmem->mutex);
    smctl_wmem->lwp = syscall(SYS_gettid);
    pthread_cond_signal(&smctl_wmem->condlwp);
    pthread_mutex_unlock(&smctl_wmem->mutex);

    for(;;) {
        pthread_mutex_lock(&smctl_wmem->mutex);
        while (!smctl_wmem->has_to_stop)
            pthread_cond_wait(&smctl_wmem->condc, &smctl_wmem->mutex);

        /* if requested, exit this thread */
        if (smctl_wmem->has_to_stop)
            goto exit;

        pthread_mutex_unlock(&smctl_wmem->mutex);
    }

exit:
    pthread_mutex_unlock(&smctl_wmem->mutex);
    pthread_exit(0);
}


/* When dealing with rollbacks and restores, where the memory pages are
   swapped to effectively time-travel in the process execution, we need to 
   make sure that the stack where such operations are executed is not under
   smmap control. These two functions start and stop a worker thread created
   for this purpose. */
/* Must be called before configurint the mappings for smmap */
int tm_init(void)
{
    pthread_attr_t attr;

    /* prepare a memory area for the worker thread */
    smctl_wmem = mmap(0, WORKER_MEM_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
    if (smctl_wmem == NULL || smctl_wmem == MAP_FAILED) goto err;
    memset(smctl_wmem, 0, WORKER_MEM_SIZE);

    /* set information related to the available user memory */
    smctl_wmem->util.ptr = (void *) (
        (unsigned long) smctl_wmem + sizeof(smctl_wmem_t));
    smctl_wmem->util.size = WORKER_MEM_SIZE - sizeof(smctl_wmem_t);
    /* set the stack of the process */
    smctl_wmem->stack = mmap(0, WORKER_STACK_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
    if (smctl_wmem->stack == NULL || smctl_wmem->stack == MAP_FAILED) goto err;
    memset(smctl_wmem->stack, 0, WORKER_STACK_SIZE);

    smctl_wmem->lwp = -1;
    /* prepare mutex and conditions */
    if (pthread_mutex_init(&smctl_wmem->mutex, NULL) != 0) goto err;
    if (pthread_cond_init(&smctl_wmem->condc, NULL) != 0) goto err;
    if (pthread_cond_init(&smctl_wmem->condlwp, NULL) != 0) goto err;
    /* create the worker thread */
    if (pthread_attr_init(&attr) != 0) goto err;
    if (pthread_attr_setstack(&attr, smctl_wmem->stack, WORKER_STACK_SIZE) != 0)
        goto err;
    if (pthread_create(&smctl_wmem->thread, &attr, smctl_worker, NULL) != 0)
        goto err;
    /* destory the attributes which are not needed anymore */
    if (pthread_attr_destroy(&attr) != 0) goto err;

    /* return the location of the memory map just created */
    smctl_is_init = true;
    return 0;

err:
    if (smctl_wmem != NULL && smctl_wmem->stack != NULL && smctl_wmem->stack != MAP_FAILED)
        munmap(smctl_wmem->stack, WORKER_STACK_SIZE);
    if (smctl_wmem != NULL && smctl_wmem != MAP_FAILED)
        munmap(smctl_wmem, WORKER_MEM_SIZE);
    return -EFAULT;
}

int tm_close(void)
{
    /* We let process delete the thread and the maps allocated previously
       since this function is often called when exit_group is called and,
       as a result, it would deadlock due to locks already grabbed by process
       while exiting. */
    smctl_is_init = false;
    smctl_is_smmapped = false;

    return 0;
}

pthread_t tm_get_worker_tid(void)
{
    struct timespec ts;

    pthread_mutex_lock(&smctl_wmem->mutex);
    while (smctl_wmem->lwp == -1) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;
        pthread_cond_timedwait(&smctl_wmem->condlwp, &smctl_wmem->mutex, &ts);
    }
    pthread_mutex_unlock(&smctl_wmem->mutex);

    return smctl_wmem->lwp;
}

#endif /* _SMMAP_LIB_H_ */
