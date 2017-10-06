/**
 * DESIGN CHOICES FOR PAGE ALLOCATION
 * Due to the design of the kernel module, we require to allocate pages in a
 * non preemptible and non interruptible context, namely from a jprobe handler.
 * For this reason we need to reduce remove concurrency when dealing with the
 * queues.
 * To achieve this goal, we have decided to use per-CPU fifo queues.
 *
 * PAGE ALLOCATION.
 * Page allocation is triggered when the per-CPU fifo queue reaches 0 pages
 * available. This causes a job post on the workqueue which triggers a high
 * priority worker to fill-in all the missing pages.
 *
 * CONCURRENCY.
 * On the one hand, since the access to the local per-CPU fifo queues makes the
 * process non-preemptible, only one producer at the time can access the queue.
 * On the other hand, we retrieve pages when checkpointing, hence in a jprobe
 * context. Such a context is non-preemptible and non-interruptible. This means
 * that only one jprobe at the time can retrieve a page, hence we have a single
 * consumer. This allows us to use the pages without the need for locking.
 */

#include <linux/percpu.h>

#include <smmap_defs.h>

/* per-CPU page-queue */
static DEFINE_PER_CPU(smmap_page_wq_t, pqinfo);
/* High priority queue for page allocation */
static struct workqueue_struct *smmap_pages_wq;
static bool use_atomic_only;

static void __smmap_page_wq_alloc_cb(struct work_struct *work);
static void __smmap_page_wq_post(smmap_page_wq_t *pqinfop);
static int __smmap_page_wq_alloc(smmap_page_wq_t *pqinfop, bool all);
static void __smmap_page_wq_cleanup(smmap_page_wq_t *pqinfop);

/**
 * smmap_page_wq_init - prepares the necessary high priority workqueue and
 *                      all the queue containers stored on each online cpus.
 */
void smmap_page_wq_init(void)
{
    int cpu;
    int ret;
    smmap_page_wq_t *pqinfop;

    use_atomic_only = (max_pages <= 0) ? true : false;

    if (use_atomic_only) return;

    /* Prepare the high priority workqueue with one worker per CPU */
    smmap_pages_wq = alloc_workqueue("smmap_page_wq",
            WQ_HIGHPRI | WQ_MEM_RECLAIM, num_online_cpus());

    /* Initialize per-CPU variables */
    for_each_online_cpu(cpu) {
        pqinfop = &per_cpu(pqinfo, cpu);

        /* Allocate the queue holding the pages and fill it up
           NB: if size is 1, will not be rounded up to 2 (kfifo requires
               power-of-2 sizes) */
        if ((ret = kfifo_alloc(&pqinfop->fifo, max_pages, GFP_KERNEL)) != 0) {
            printk(KERN_NOTICE "Unable to allocate FIFO Queue; ret code %d. "
                   "SMMAP will fallback to atomic pages.\n", ret);
            use_atomic_only = true;
            return;
        }

        atomic_set(&pqinfop->expanding, 1);
        if ((ret = __smmap_page_wq_alloc(pqinfop, true)) < 0) {
            printk(KERN_ALERT "smmap: Unable to allocate pages. Page allocator "
                   "returned with code %d. SMMAP will fallback to "
                   "atomic pages.\n", ret);
            use_atomic_only = true;
        }
    }
}

/**
 * smmap_page_wq_close - deletes the necessary high priority workqueue and
 *                       all the queue containers stored on each online cpus.
 */
void smmap_page_wq_close(void)
{
    int cpu;
    smmap_page_wq_t *pqinfop;

    if (use_atomic_only) return;

    /* Delete workqueue */
    flush_workqueue(smmap_pages_wq);
    destroy_workqueue(smmap_pages_wq);
    /* Cleanup per-cpu variables */
    for_each_online_cpu(cpu) {
        pqinfop = &per_cpu(pqinfo, cpu);

        /* Dellocate the queue holding the pages */
        __smmap_page_wq_cleanup(pqinfop);
        kfifo_free(&pqinfop->fifo);
        atomic_set(&pqinfop->expanding, 0);
    }
}

struct page *smmap_page_wq_retrieve(bool fill_zeros)
{
    struct page *page = NULL;
    smmap_page_wq_t *pqinfop;
    char *vpage;

    /* If requested, fall back to atomic pages only */
    if (use_atomic_only) {
        page = alloc_page(GFP_ATOMIC);
        goto exit;
    }

    pqinfop = &get_cpu_var(pqinfo);
    /* Due to the workqueue design, this should never happen, unless the
       process debugged has the same priority as the kernel worker. */
    if (unlikely(kfifo_get(&pqinfop->fifo, &page) == 0)) {
        page = alloc_page(GFP_ATOMIC);
        SMMAP_STAT_INC(num_atomics);
        DEBUG(DEBUG_L1, "retreiving an atomic page due to lack of available pages");
    }

    /* Check if the number of pages available is enough, if not, post a
       request to increase the number of pages */
    if (kfifo_len(&pqinfop->fifo) <= 0) __smmap_page_wq_post(pqinfop);

    put_cpu_var(pqinfo);

exit:
    if (!page) BUG();

    /* fill the page with zeros */
    if (fill_zeros) {
        vpage = kmap_atomic(page);
        clear_page(vpage);
        kunmap_atomic(vpage);
    }

    return page;
}

int smmap_page_wq_return(smmap_page_t *spp)
{
    if (spp == NULL) return -EINVAL;

    if (smmap_page_has_page(spp)) {
        struct page *pagep = smmap_page_get_page(spp);

        return smmap_page_wq_page_return(&pagep,
            smmap_flag_is_set(spp, SMMAP_PAGE_FLAG_IS_PRESENT));
    }

    return 0;
}

int smmap_page_wq_page_return(struct page **page, bool is_from_proc)
{
    void *addr;
    /* TODO: add logic that allows to reuse pages instead of just freeing them.
             NB: make sure that use_atomic_only is not set otherwise just
             freeing the page is the right approach. */
    if (page == NULL || *page == NULL) return -EINVAL;

    addr = (void *) page_address(*page);
    DEBUG(DEBUG_L2, "freeing page 0x%p", addr);

    /* if the page has count == 1, it means that the this module is the only
       one having ownership of the page and can simply free the page */
    if (page_count(*page) == 1 && page_mapcount(*page) == 0 && !is_from_proc) {
        page_cache_release(*page);
        *page = NULL;
        return 0;
    }

    DEBUG(DEBUG_L2, "keeping page around 0x%p", addr);
    return 0;
}

/**
 * __smmap_page_wq_alloc - Allocate new pages and adds them into the fifo queue
 *
 * @queue: the smmap_page_wq_t container of the fifo queue to be refilled. If
 *         this parameter is set to NULL, the function will retrieve the local
 *         per-CPU queue container.
 * @all: allocate the maximum number of pages. This is used for initialization.
 *
 * Returns 0 on success, or a negative value in case of error.
 */
int __smmap_page_wq_alloc(smmap_page_wq_t *pqinfop, bool all)
{
    int i;
    int ret = 0;
    const struct page *page;
    struct page **pages = NULL;
    bool do_get_cpu = (pqinfop == NULL);
    int new_pages;

    /* Determine the number of pages to add. For this, we need to retrieve
       the size in elements of the kfifo.
       NB: the kfifo is per-CPU hence requires a non-preemptible environment */
    if (all) {
        new_pages = max_pages;
    } else {
        if (do_get_cpu) pqinfop = &get_cpu_var(pqinfo);
        new_pages = max_pages-kfifo_len(&pqinfop->fifo);
        if (do_get_cpu) put_cpu_var(pqinfo);
    }

    if (unlikely(use_atomic_only)) BUG();

    if (new_pages <= 0) {
        ret = -EAGAIN;
        goto err;
    }

    /* Allocate the container for the new pages */
    pages = (struct page **) kmalloc(
            sizeof(struct page *)*new_pages, GFP_KERNEL);
    if (pages == NULL) {
        ret = -ENOMEM;
        goto err;
    }
    memset(pages, 0, sizeof(struct page *)*new_pages);

    /* Allocate all the new pages that need to be added to the queue */
    for (i=0; i<new_pages; ++i) {
        if ((pages[i] = alloc_page(GFP_KERNEL)) == NULL) {
            ret = -ENOMEM;
            goto err;
        }
    }

    /* Add the new pages to the queue */
    if (do_get_cpu) pqinfop = &get_cpu_var(pqinfo);

    for (i=0; i<new_pages; ++i) {
        page = pages[i];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
        kfifo_put(&pqinfop->fifo, &page);
#else
        kfifo_put(&pqinfop->fifo, page);
#endif
    }

    DEBUG(DEBUG_L1, "Added pages to the queue. Current number of elements %u",
        kfifo_len(&pqinfop->fifo));

    goto exit;

err:
    /* Free created pages  */
    if (pages != NULL) {
        for (i=0; i<new_pages; ++i) {
            if (pages[i]) {
                __free_page(pages[i]);
            }
        }
    }

exit:
    /* Free pages container */
    if (pages != NULL) kfree(pages);

    /* Reset the 'expanding' flag */
    atomic_set(&pqinfop->expanding, 0);
    if (do_get_cpu) put_cpu_var(pqinfo);

    return ret;
}

void __smmap_page_wq_cleanup(smmap_page_wq_t *pqinfop)
{
    struct page *p;

    while (kfifo_get(&pqinfop->fifo, &p) == 1)
        smmap_page_wq_page_return(&p, false);

    DEBUG(DEBUG_L1, "Cleaup the page queque; Current size: %d\n",
        kfifo_len(&pqinfop->fifo));
}


/**
 * The callback assumes that only one job at the time is posted in the queue.
 */
static void __smmap_page_wq_alloc_cb(struct work_struct *work)
{
    int ret;

    if (work == NULL) return;

    /* add the pages as requested */
    if ((ret = __smmap_page_wq_alloc(NULL, false)) < 0) {
        printk(KERN_ALERT "smmap: No new pages where allocated. "
            "'%s' returned code %d.\n", __func__, ret);
    }

    kfree(work);
}

/**
 * Post a request to increase the number of free pages in the list.
 */
static void __smmap_page_wq_post(smmap_page_wq_t *pqinfop)
{
    struct work_struct *alloc_work;

    /* determine if a job is already in progress */
    if (atomic_read(&pqinfop->expanding) > 0) {
        DEBUG(DEBUG_L1, "Page allocation already requested");
        return;
    }

    /* Posting the job, set the 'expanding' flag to true*/
    atomic_set(&pqinfop->expanding, 1);

    /* allocate the page allocation work */
    alloc_work = (struct work_struct *) kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
    if (alloc_work == NULL) BUG();

    INIT_WORK((struct work_struct *) alloc_work, __smmap_page_wq_alloc_cb);
    queue_work(smmap_pages_wq, (struct work_struct *) alloc_work);

    DEBUG(DEBUG_L1, "Page allocation job posted");
}
