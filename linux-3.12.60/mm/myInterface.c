// This file is for migrating zswap from 6.4.3 to 3.12.60 


/*********************************
* include
**********************************/
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/frontswap.h>
#include <linux/rbtree.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/mempool.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>

#include <linux/myInterface.h>

#include <linux/list.h>
#include <linux/mm.h>


/*********************************
* compression functions
**********************************/
#define ZSWAP_COMPRESSOR_DEFAULT "lzo"
static char *zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;

static struct crypto_comp * __percpu *zswap_comp_pcpu_tfms;

int zswap_comp_op(enum comp_op op, u8 *src, unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct crypto_comp *tfm;
	int ret;

	tfm = *per_cpu_ptr(zswap_comp_pcpu_tfms, get_cpu());
	switch (op) {
	case ZSWAP_COMPOP_COMPRESS:
		ret = crypto_comp_compress(tfm, src, slen, dst, dlen);
		break;
	case ZSWAP_COMPOP_DECOMPRESS:
		ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);
		break;
	default:
		ret = -EINVAL;
	}

	put_cpu();
	return ret;
}

int zswap_comp_init(void)
{
	if (!crypto_has_comp(zswap_compressor, 0, 0)) {
		pr_info("zswap_comp_init: %s compressor not available\n", zswap_compressor);
		/* fall back to default compressor */
		zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;
		if (!crypto_has_comp(zswap_compressor, 0, 0))
			/* can't even load the default compressor */
			return -ENODEV;
	}
	pr_info("zswap_comp_init: using %s compressor\n", zswap_compressor);

	/* alloc percpu transforms */
	zswap_comp_pcpu_tfms = alloc_percpu(struct crypto_comp *);
	if (!zswap_comp_pcpu_tfms)
		return -ENOMEM;

	// 来自__zswap_cpu_notifier
	struct crypto_comp *tfm = NULL;
	int cpu;
	for_each_present_cpu(cpu) {
		tfm = crypto_alloc_comp(zswap_compressor, 0, 0);
		*per_cpu_ptr(zswap_comp_pcpu_tfms, cpu) = tfm;
	}

	// printk(KERN_INFO "zswap_comp_pcpu_tfms value: %p\n", zswap_comp_pcpu_tfms);   // 改
	// printk(KERN_INFO "tfm value: %p\n", tfm);
	
	return 0;
}

/*********************************
* statistics
**********************************/


/*********************************
* tunables
**********************************/


/*********************************
* data structures
**********************************/


/*********************************
* helpers and fwd declarations
**********************************/

// unsigned long totalram_pages(void) {
//     return totalram_pages;
// }


/*********************************
* zswap entry functions
**********************************/
void obj_cgroup_uncharge_zswap(struct obj_cgroup *objcg, size_t size) {
    return;
}

void obj_cgroup_put(struct obj_cgroup *objcg){
    return;
}


/*********************************
* per-cpu code
**********************************/

struct crypto_acomp *crypto_alloc_acomp_node(const char *alg_name, u32 type, u32 mask, int node)
{
	struct crypto_acomp *cpa;
	cpa = kzalloc(sizeof(*cpa), GFP_KERNEL);
	return cpa;
}

struct acomp_req *acomp_request_alloc(struct crypto_acomp *acomp)
{
	struct acomp_req *req;
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	return req;
}

void crypto_free_acomp(struct crypto_acomp *tfm)
{
	return;
}

void crypto_init_wait(struct crypto_wait *wait)
{
	// init_completion(&wait->completion);
	return;
}

void acomp_request_set_callback(struct acomp_req *req, u32 flgs, crypto_completion_t cmpl, void *data)
{
	return;
}

void crypto_req_done(void *data, int err)
{
	return;
}

void acomp_request_free(struct acomp_req *req)
{
	return;
}

/*********************************
* pool functions
**********************************/
void strscpy(char *dest, const char *src, size_t count) {
    size_t i;

    for (i = 0; i < count && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }

    if (i < count) {
        dest[i] = '\0';
    }
}

struct kmalloced_param {
	struct list_head list;
	char val[];
};
static LIST_HEAD(kmalloced_params);
static DEFINE_SPINLOCK(kmalloced_params_lock);

void maybe_kfree_parameter(void *param)
{
	struct kmalloced_param *p;

	spin_lock(&kmalloced_params_lock);
	list_for_each_entry(p, &kmalloced_params, list) {
		if (p->val == param) {
			list_del(&p->list);
			kfree(p);
			break;
		}
	}
	spin_unlock(&kmalloced_params_lock);
}

void param_free_charp(void *arg)
{
	maybe_kfree_parameter(*((char **)arg));
}


int (*cbm)(unsigned int cpu, struct hlist_node *node);

int cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node)
{
	int err;
	int cpu;
	for_each_present_cpu(cpu) {
		err = cbm(cpu, node);
		if (err) {
			return err;
		}
	}
	return 0;
}

int cpuhp_state_remove_instance(enum cpuhp_state state, struct hlist_node *node)
{
	return 0;
}

/*********************************
* param callbacks
**********************************/

/*********************************
* writeback code
**********************************/
void *memset_l(unsigned long *p, unsigned long v, __kernel_size_t n) {
    if (BITS_PER_LONG == 32)
		return memset32((uint32_t *)p, v, n);
	else
		return memset64((uint64_t *)p, v, n);
}

void *memset32(uint32_t *s, uint32_t v, size_t count)
{
	uint32_t *xs = s;

	while (count--)
		*xs++ = v;
	return s;
}

void *memset64(uint64_t *s, uint64_t v, size_t count)
{
	uint64_t *xs = s;

	while (count--)
		*xs++ = v;
	return s;
}

#define SG_END 0x02UL

/*
void acomp_request_set_params(struct acomp_req *req,
					    struct scatterlist *src,
					    struct scatterlist *dst,
					    unsigned int slen,
					    unsigned int dlen)
{
	// req->src = src;
	// req->dst = dst;
	// req->slen = slen;
	// req->dlen = dlen;

	// req->flags &= ~CRYPTO_ACOMP_ALLOC_OUTPUT;
	// if (!req->dst)
	// 	req->flags |= CRYPTO_ACOMP_ALLOC_OUTPUT;


	// u8 *tmp;
	// tmp = (u8 *)((char *)(uintptr_t)(src->page_link) + src->offset);   // 可能存在bug
	// tmp = (u8 *)((unsigned long)tmp & ~SG_END);

	// req->src = (u8 *)page_address((struct page*)tmp);
	// req->dst = (u8 *)page_address((struct page*)dst->page_link);
	// req->slen = slen;
	// req->dlen = dlen;

	req->src = (u8 *)((char *)(uintptr_t)(src->page_link) + src->offset);   // 可能存在bug
	req->src = (u8 *)((unsigned long)req->src & ~SG_END);
	req->dst = (u8 *)((char *)(uintptr_t)(dst->page_link) + dst->offset);
	req->dst = (u8 *)((unsigned long)req->dst & ~SG_END);
	req->slen = slen;
	req->dlen = dlen;
}

int crypto_acomp_compress(struct acomp_req *req)
{
	u8 *tmpsrc = (u8 *)req->src;
	u8 *tmpdst = (u8 *)req->dst;

	u8 *src = (u8 *)page_address((struct page*)tmpsrc);
	u8 *dst = (u8 *)page_address((struct page*)tmpdst);
	unsigned int slen = req->slen;
	unsigned int *dlen = &req->dlen;
	zswap_comp_op(ZSWAP_COMPOP_COMPRESS, src, slen, dst, dlen);  
	return 0;
}

int crypto_acomp_decompress(struct acomp_req *req)
{
	u8 *tmpsrc = (u8 *)req->src;
	u8 *tmpdst = (u8 *)req->dst;

	u8 *src = (u8 *)page_address((struct page*)tmpsrc);
	u8 *dst = (u8 *)page_address((struct page*)tmpdst);
	unsigned int slen = req->slen;
	unsigned int *dlen = &req->dlen;
	zswap_comp_op(ZSWAP_COMPOP_DECOMPRESS, src, slen, dst, dlen);  
	return 0;
}
*/
void acomp_request_set_params(struct acomp_req *req,
					    struct scatterlist *src,
					    struct scatterlist *dst,
					    unsigned int slen,
					    unsigned int dlen)
{
	u8 *tmpsrc;
	u8 *tmpdst; 
	tmpsrc = (u8 *)((uintptr_t)(src->page_link));
	tmpsrc = (u8 *)((unsigned long)tmpsrc & ~SG_END);
	tmpdst = (u8 *)((uintptr_t)(dst->page_link));
	tmpdst = (u8 *)((unsigned long)tmpdst & ~SG_END);

	req->src = (u8 *)(page_address((struct page*)tmpsrc) + src->offset);
	req->dst = (u8 *)(page_address((struct page*)tmpdst) + dst->offset);

	req->slen = slen;
	req->dlen = dlen;
}

int crypto_acomp_compress(struct acomp_req *req)
{
	u8 *src = req->src;
	u8 *dst = req->dst;
	unsigned int slen = req->slen;
	unsigned int *dlen = &req->dlen;
	zswap_comp_op(ZSWAP_COMPOP_COMPRESS, src, slen, dst, dlen);  
	return 0;
}

int crypto_acomp_decompress(struct acomp_req *req)
{
	u8 *src = req->src;
	u8 *dst = req->dst;
	unsigned int slen = req->slen;
	unsigned int *dlen = &req->dlen;
	zswap_comp_op(ZSWAP_COMPOP_DECOMPRESS, src, slen, dst, dlen);  
	return 0;
}

int crypto_wait_req(int err, struct crypto_wait *wait)
{
	// switch (err) {
	// case -EINPROGRESS:
	// case -EBUSY:
	// 	wait_for_completion(&wait->completion);
	// 	reinit_completion(&wait->completion);
	// 	err = wait->err;
	// 	break;
	// }

	// return err;
	return 0;
}

struct page *__read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated)
{
	struct page *found_page, *new_page = NULL;
	struct address_space *swapper_space = swap_address_space(entry);
	int err;

	*new_page_allocated = false;

	// *retpage = NULL;
	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 */
		found_page = find_get_page(swapper_space, entry.val);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		if (!new_page) {
			new_page = alloc_page(GFP_KERNEL);
			if (!new_page)
				break; /* Out of memory */
		}

		/*
		 * call radix_tree_preload() while we can wait.
		 */
		err = radix_tree_preload(GFP_KERNEL);
		if (err)
			break;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
		err = swapcache_prepare(entry);
		if (err == -EEXIST) { /* seems racy */
			radix_tree_preload_end();
			continue;
		}
		if (err) { /* swp entry is obsolete ? */
			radix_tree_preload_end();
			break;
		}

		/* May fail (-ENOMEM) if radix-tree node allocation failed. */
		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = __add_to_swap_cache(new_page, entry);
		if (likely(!err)) {
			radix_tree_preload_end();
			lru_cache_add_anon(new_page);
			// *retpage = new_page;
			*new_page_allocated = true;
			// return ZSWAP_SWAPCACHE_NEW;
			return new_page;
		}
		radix_tree_preload_end();
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry, NULL);
	} while (err != -ENOMEM);

	if (new_page)
		page_cache_release(new_page);
	if (!found_page)
		return NULL;
	// *retpage = found_page;
	return found_page;
}

struct page *page_folio(struct page* p) {
	return p;
}

/*********************************
* frontswap hooks
**********************************/
struct obj_cgroup *get_obj_cgroup_from_page(struct page *page)
{
	return NULL;
}

bool obj_cgroup_may_zswap(struct obj_cgroup *objcg)
{
	return true;
}

void obj_cgroup_charge_zswap(struct obj_cgroup *objcg, size_t size)
{
    return;
}

void count_objcg_event(struct obj_cgroup *objcg, enum vm_event_item idx)
{
    return;
}



/*********************************
* module init and exit
**********************************/

int cpuhp_setup_state(enum cpuhp_state state,
				    const char *name,
				    int (*startup)(unsigned int cpu),
				    int (*teardown)(unsigned int cpu))
{
	int (*cb)(unsigned int cpu);
	cb = startup;
	int err, cpu;
	for_each_present_cpu(cpu) {
		err = cb(cpu);
		if (err) {
			return err;
		}
	}
	return 0;
}

int cpuhp_setup_state_multi(enum cpuhp_state state,
					  const char *name,
					  int (*startup)(unsigned int cpu,
							 struct hlist_node *node),
					  int (*teardown)(unsigned int cpu,
							  struct hlist_node *node))
{
	cbm = startup;

	// 借用来调用zswap_comp_init
	int result = zswap_comp_init();

	return result;
}

void cpuhp_remove_state(enum cpuhp_state state)
{
	return;
}


/*********************************
* zpool.c
**********************************/
struct zpool {
	struct zpool_driver *driver;
	void *pool;
};

static LIST_HEAD(drivers_head);
static DEFINE_SPINLOCK(drivers_lock);

/**
 * zpool_register_driver() - register a zpool implementation.
 * @driver:	driver to register
 */
void zpool_register_driver(struct zpool_driver *driver)
{
	spin_lock(&drivers_lock);
	atomic_set(&driver->refcount, 0);
	list_add(&driver->list, &drivers_head);
	spin_unlock(&drivers_lock);
}

/**
 * zpool_unregister_driver() - unregister a zpool implementation.
 * @driver:	driver to unregister.
 *
 * Module usage counting is used to prevent using a driver
 * while/after unloading, so if this is called from module
 * exit function, this should never fail; if called from
 * other than the module exit function, and this returns
 * failure, the driver is in use and must remain available.
 */
int zpool_unregister_driver(struct zpool_driver *driver)
{
	int ret = 0, refcount;

	spin_lock(&drivers_lock);
	refcount = atomic_read(&driver->refcount);
	WARN_ON(refcount < 0);
	if (refcount > 0)
		ret = -EBUSY;
	else
		list_del(&driver->list);
	spin_unlock(&drivers_lock);

	return ret;
}

/* this assumes @type is null-terminated. */
static struct zpool_driver *zpool_get_driver(const char *type)
{
	struct zpool_driver *driver;

	spin_lock(&drivers_lock);
	list_for_each_entry(driver, &drivers_head, list) {
		if (!strcmp(driver->type, type)) {
			bool got = try_module_get(driver->owner);

			if (got)
				atomic_inc(&driver->refcount);
			spin_unlock(&drivers_lock);
			return got ? driver : NULL;
		}
	}

	spin_unlock(&drivers_lock);
	return NULL;
}

static void zpool_put_driver(struct zpool_driver *driver)
{
	atomic_dec(&driver->refcount);
	module_put(driver->owner);
}

/**
 * zpool_has_pool() - Check if the pool driver is available
 * @type:	The type of the zpool to check (e.g. zbud, zsmalloc)
 *
 * This checks if the @type pool driver is available.  This will try to load
 * the requested module, if needed, but there is no guarantee the module will
 * still be loaded and available immediately after calling.  If this returns
 * true, the caller should assume the pool is available, but must be prepared
 * to handle the @zpool_create_pool() returning failure.  However if this
 * returns false, the caller should assume the requested pool type is not
 * available; either the requested pool type module does not exist, or could
 * not be loaded, and calling @zpool_create_pool() with the pool type will
 * fail.
 *
 * The @type string must be null-terminated.
 *
 * Returns: true if @type pool is available, false if not
 */
bool zpool_has_pool(char *type)
{
	struct zpool_driver *driver = zpool_get_driver(type);

	if (!driver) {
		request_module("zpool-%s", type);
		driver = zpool_get_driver(type);
	}

	if (!driver)
		return false;

	zpool_put_driver(driver);
	return true;
}

/**
 * zpool_create_pool() - Create a new zpool
 * @type:	The type of the zpool to create (e.g. zbud, zsmalloc)
 * @name:	The name of the zpool (e.g. zram0, zswap)
 * @gfp:	The GFP flags to use when allocating the pool.
 * @ops:	The optional ops callback.
 *
 * This creates a new zpool of the specified type.  The gfp flags will be
 * used when allocating memory, if the implementation supports it.  If the
 * ops param is NULL, then the created zpool will not be evictable.
 *
 * Implementations must guarantee this to be thread-safe.
 *
 * The @type and @name strings must be null-terminated.
 *
 * Returns: New zpool on success, NULL on failure.
 */
struct zpool *zpool_create_pool(const char *type, const char *name, gfp_t gfp,
		const struct zpool_ops *ops)
{
	struct zpool_driver *driver;
	struct zpool *zpool;

	pr_debug("creating pool type %s\n", type);

	driver = zpool_get_driver(type);

	if (!driver) {
		request_module("zpool-%s", type);
		driver = zpool_get_driver(type);
	}

	if (!driver) {
		pr_err("no driver for type %s\n", type);
		return NULL;
	}

	zpool = kmalloc(sizeof(*zpool), gfp);
	if (!zpool) {
		pr_err("couldn't create zpool - out of memory\n");
		zpool_put_driver(driver);
		return NULL;
	}

	zpool->driver = driver;
	zpool->pool = driver->create(name, gfp, ops, zpool);

	if (!zpool->pool) {
		pr_err("couldn't create %s pool\n", type);
		zpool_put_driver(driver);
		kfree(zpool);
		return NULL;
	}

	pr_debug("created pool type %s\n", type);

	return zpool;
}

/**
 * zpool_destroy_pool() - Destroy a zpool
 * @zpool:	The zpool to destroy.
 *
 * Implementations must guarantee this to be thread-safe,
 * however only when destroying different pools.  The same
 * pool should only be destroyed once, and should not be used
 * after it is destroyed.
 *
 * This destroys an existing zpool.  The zpool should not be in use.
 */
void zpool_destroy_pool(struct zpool *zpool)
{
	pr_debug("destroying pool type %s\n", zpool->driver->type);

	zpool->driver->destroy(zpool->pool);
	zpool_put_driver(zpool->driver);
	kfree(zpool);
}

/**
 * zpool_get_type() - Get the type of the zpool
 * @zpool:	The zpool to check
 *
 * This returns the type of the pool.
 *
 * Implementations must guarantee this to be thread-safe.
 *
 * Returns: The type of zpool.
 */
const char *zpool_get_type(struct zpool *zpool)
{
	return zpool->driver->type;
}

/**
 * zpool_malloc_support_movable() - Check if the zpool supports
 *	allocating movable memory
 * @zpool:	The zpool to check
 *
 * This returns if the zpool supports allocating movable memory.
 *
 * Implementations must guarantee this to be thread-safe.
 *
 * Returns: true if the zpool supports allocating movable memory, false if not
 */
bool zpool_malloc_support_movable(struct zpool *zpool)
{
	return zpool->driver->malloc_support_movable;
}

/**
 * zpool_malloc() - Allocate memory
 * @zpool:	The zpool to allocate from.
 * @size:	The amount of memory to allocate.
 * @gfp:	The GFP flags to use when allocating memory.
 * @handle:	Pointer to the handle to set
 *
 * This allocates the requested amount of memory from the pool.
 * The gfp flags will be used when allocating memory, if the
 * implementation supports it.  The provided @handle will be
 * set to the allocated object handle.
 *
 * Implementations must guarantee this to be thread-safe.
 *
 * Returns: 0 on success, negative value on error.
 */
int zpool_malloc(struct zpool *zpool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	return zpool->driver->malloc(zpool->pool, size, gfp, handle);
}

/**
 * zpool_free() - Free previously allocated memory
 * @zpool:	The zpool that allocated the memory.
 * @handle:	The handle to the memory to free.
 *
 * This frees previously allocated memory.  This does not guarantee
 * that the pool will actually free memory, only that the memory
 * in the pool will become available for use by the pool.
 *
 * Implementations must guarantee this to be thread-safe,
 * however only when freeing different handles.  The same
 * handle should only be freed once, and should not be used
 * after freeing.
 */
void zpool_free(struct zpool *zpool, unsigned long handle)
{
	zpool->driver->free(zpool->pool, handle);
}

/**
 * zpool_shrink() - Shrink the pool size
 * @zpool:	The zpool to shrink.
 * @pages:	The number of pages to shrink the pool.
 * @reclaimed:	The number of pages successfully evicted.
 *
 * This attempts to shrink the actual memory size of the pool
 * by evicting currently used handle(s).  If the pool was
 * created with no zpool_ops, or the evict call fails for any
 * of the handles, this will fail.  If non-NULL, the @reclaimed
 * parameter will be set to the number of pages reclaimed,
 * which may be more than the number of pages requested.
 *
 * Implementations must guarantee this to be thread-safe.
 *
 * Returns: 0 on success, negative value on error/failure.
 */
int zpool_shrink(struct zpool *zpool, unsigned int pages,
			unsigned int *reclaimed)
{
	return zpool->driver->shrink ?
	       zpool->driver->shrink(zpool->pool, pages, reclaimed) : -EINVAL;
}

/**
 * zpool_map_handle() - Map a previously allocated handle into memory
 * @zpool:	The zpool that the handle was allocated from
 * @handle:	The handle to map
 * @mapmode:	How the memory should be mapped
 *
 * This maps a previously allocated handle into memory.  The @mapmode
 * param indicates to the implementation how the memory will be
 * used, i.e. read-only, write-only, read-write.  If the
 * implementation does not support it, the memory will be treated
 * as read-write.
 *
 * This may hold locks, disable interrupts, and/or preemption,
 * and the zpool_unmap_handle() must be called to undo those
 * actions.  The code that uses the mapped handle should complete
 * its operations on the mapped handle memory quickly and unmap
 * as soon as possible.  As the implementation may use per-cpu
 * data, multiple handles should not be mapped concurrently on
 * any cpu.
 *
 * Returns: A pointer to the handle's mapped memory area.
 */
void *zpool_map_handle(struct zpool *zpool, unsigned long handle,
			enum zpool_mapmode mapmode)
{
	return zpool->driver->map(zpool->pool, handle, mapmode);
}

/**
 * zpool_unmap_handle() - Unmap a previously mapped handle
 * @zpool:	The zpool that the handle was allocated from
 * @handle:	The handle to unmap
 *
 * This unmaps a previously mapped handle.  Any locks or other
 * actions that the implementation took in zpool_map_handle()
 * will be undone here.  The memory area returned from
 * zpool_map_handle() should no longer be used after this.
 */
void zpool_unmap_handle(struct zpool *zpool, unsigned long handle)
{
	zpool->driver->unmap(zpool->pool, handle);
}

/**
 * zpool_get_total_size() - The total size of the pool
 * @zpool:	The zpool to check
 *
 * This returns the total size in bytes of the pool.
 *
 * Returns: Total size of the zpool in bytes.
 */
u64 zpool_get_total_size(struct zpool *zpool)
{
	return zpool->driver->total_size(zpool->pool);
}

/**
 * zpool_evictable() - Test if zpool is potentially evictable
 * @zpool:	The zpool to test
 *
 * Zpool is only potentially evictable when it's created with struct
 * zpool_ops.evict and its driver implements struct zpool_driver.shrink.
 *
 * However, it doesn't necessarily mean driver will use zpool_ops.evict
 * in its implementation of zpool_driver.shrink. It could do internal
 * defragmentation instead.
 *
 * Returns: true if potentially evictable; false otherwise.
 */
bool zpool_evictable(struct zpool *zpool)
{
	return zpool->driver->shrink;
}

/**
 * zpool_can_sleep_mapped - Test if zpool can sleep when do mapped.
 * @zpool:	The zpool to test
 *
 * Some allocators enter non-preemptible context in ->map() callback (e.g.
 * disable pagefaults) and exit that context in ->unmap(), which limits what
 * we can do with the mapped object. For instance, we cannot wait for
 * asynchronous crypto API to decompress such an object or take mutexes
 * since those will call into the scheduler. This function tells us whether
 * we use such an allocator.
 *
 * Returns: true if zpool can sleep; false otherwise.
 */
bool zpool_can_sleep_mapped(struct zpool *zpool)
{
	return zpool->driver->sleep_mapped;
}





/*********************************
* zbud.c
**********************************/

#define NCHUNKS_ORDER	6

#define CHUNK_SHIFT	(PAGE_SHIFT - NCHUNKS_ORDER)
#define CHUNK_SIZE	(1 << CHUNK_SHIFT)
#define ZHDR_SIZE_ALIGNED CHUNK_SIZE
#define NCHUNKS		((PAGE_SIZE - ZHDR_SIZE_ALIGNED) >> CHUNK_SHIFT)

struct zbud_pool;

/**
 * struct zbud_pool - stores metadata for each zbud pool
 * @lock:	protects all pool fields and first|last_chunk fields of any
 *		zbud page in the pool
 * @unbuddied:	array of lists tracking zbud pages that only contain one buddy;
 *		the lists each zbud page is added to depends on the size of
 *		its free region.
 * @buddied:	list tracking the zbud pages that contain two buddies;
 *		these zbud pages are full
 * @lru:	list tracking the zbud pages in LRU order by most recently
 *		added buddy.
 * @pages_nr:	number of zbud pages in the pool.
 * @zpool:	zpool driver
 * @zpool_ops:	zpool operations structure with an evict callback
 *
 * This structure is allocated at pool creation time and maintains metadata
 * pertaining to a particular zbud pool.
 */
struct zbud_pool {
	spinlock_t lock;
	union {
		/*
		 * Reuse unbuddied[0] as buddied on the ground that
		 * unbuddied[0] is unused.
		 */
		struct list_head buddied;
		struct list_head unbuddied[NCHUNKS];
	};
	struct list_head lru;
	u64 pages_nr;
	struct zpool *zpool;
	const struct zpool_ops *zpool_ops;
};

/*
 * struct zbud_header - zbud page metadata occupying the first chunk of each
 *			zbud page.
 * @buddy:	links the zbud page into the unbuddied/buddied lists in the pool
 * @lru:	links the zbud page into the lru list in the pool
 * @first_chunks:	the size of the first buddy in chunks, 0 if free
 * @last_chunks:	the size of the last buddy in chunks, 0 if free
 */
struct zbud_header {
	struct list_head buddy;
	struct list_head lru;
	unsigned int first_chunks;
	unsigned int last_chunks;
	bool under_reclaim;
};

/*****************
 * Helpers
*****************/
/* Just to make the code easier to read */
enum buddy {
	FIRST,
	LAST
};

/* Converts an allocation size in bytes to size in zbud chunks */
static int size_to_chunks(size_t size)
{
	return (size + CHUNK_SIZE - 1) >> CHUNK_SHIFT;
}

#define for_each_unbuddied_list(_iter, _begin) \
	for ((_iter) = (_begin); (_iter) < NCHUNKS; (_iter)++)

/* Initializes the zbud header of a newly allocated zbud page */
static struct zbud_header *init_zbud_page(struct page *page)
{
	struct zbud_header *zhdr = page_address(page);
	zhdr->first_chunks = 0;
	zhdr->last_chunks = 0;
	INIT_LIST_HEAD(&zhdr->buddy);
	INIT_LIST_HEAD(&zhdr->lru);
	zhdr->under_reclaim = false;
	return zhdr;
}

/* Resets the struct page fields and frees the page */
static void free_zbud_page(struct zbud_header *zhdr)
{
	__free_page(virt_to_page(zhdr));
}

/*
 * Encodes the handle of a particular buddy within a zbud page
 * Pool lock should be held as this function accesses first|last_chunks
 */
static unsigned long encode_handle(struct zbud_header *zhdr, enum buddy bud)
{
	unsigned long handle;

	/*
	 * For now, the encoded handle is actually just the pointer to the data
	 * but this might not always be the case.  A little information hiding.
	 * Add CHUNK_SIZE to the handle if it is the first allocation to jump
	 * over the zbud header in the first chunk.
	 */
	handle = (unsigned long)zhdr;
	if (bud == FIRST)
		/* skip over zbud header */
		handle += ZHDR_SIZE_ALIGNED;
	else /* bud == LAST */
		handle += PAGE_SIZE - (zhdr->last_chunks  << CHUNK_SHIFT);
	return handle;
}

/* Returns the zbud page where a given handle is stored */
static struct zbud_header *handle_to_zbud_header(unsigned long handle)
{
	return (struct zbud_header *)(handle & PAGE_MASK);
}

/* Returns the number of free chunks in a zbud page */
static int num_free_chunks(struct zbud_header *zhdr)
{
	/*
	 * Rather than branch for different situations, just use the fact that
	 * free buddies have a length of zero to simplify everything.
	 */
	return NCHUNKS - zhdr->first_chunks - zhdr->last_chunks;
}

/*****************
 * API Functions
*****************/
/**
 * zbud_create_pool() - create a new zbud pool
 * @gfp:	gfp flags when allocating the zbud pool structure
 *
 * Return: pointer to the new zbud pool or NULL if the metadata allocation
 * failed.
 */
static struct zbud_pool *zbud_create_pool(gfp_t gfp)
{
	struct zbud_pool *pool;
	int i;

	pool = kzalloc(sizeof(struct zbud_pool), gfp);
	if (!pool)
		return NULL;
	spin_lock_init(&pool->lock);
	for_each_unbuddied_list(i, 0)
		INIT_LIST_HEAD(&pool->unbuddied[i]);
	INIT_LIST_HEAD(&pool->buddied);
	INIT_LIST_HEAD(&pool->lru);
	pool->pages_nr = 0;
	return pool;
}

/**
 * zbud_destroy_pool() - destroys an existing zbud pool
 * @pool:	the zbud pool to be destroyed
 *
 * The pool should be emptied before this function is called.
 */
static void zbud_destroy_pool(struct zbud_pool *pool)
{
	kfree(pool);
}

/**
 * zbud_alloc() - allocates a region of a given size
 * @pool:	zbud pool from which to allocate
 * @size:	size in bytes of the desired allocation
 * @gfp:	gfp flags used if the pool needs to grow
 * @handle:	handle of the new allocation
 *
 * This function will attempt to find a free region in the pool large enough to
 * satisfy the allocation request.  A search of the unbuddied lists is
 * performed first. If no suitable free region is found, then a new page is
 * allocated and added to the pool to satisfy the request.
 *
 * gfp should not set __GFP_HIGHMEM as highmem pages cannot be used
 * as zbud pool pages.
 *
 * Return: 0 if success and handle is set, otherwise -EINVAL if the size or
 * gfp arguments are invalid or -ENOMEM if the pool was unable to allocate
 * a new page.
 */
static int zbud_alloc(struct zbud_pool *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	int chunks, i, freechunks;
	struct zbud_header *zhdr = NULL;
	enum buddy bud;
	struct page *page;

	if (!size || (gfp & __GFP_HIGHMEM))
		return -EINVAL;
	if (size > PAGE_SIZE - ZHDR_SIZE_ALIGNED - CHUNK_SIZE)
		return -ENOSPC;
	chunks = size_to_chunks(size);
	spin_lock(&pool->lock);

	/* First, try to find an unbuddied zbud page. */
	for_each_unbuddied_list(i, chunks) {
		if (!list_empty(&pool->unbuddied[i])) {
			zhdr = list_first_entry(&pool->unbuddied[i],
					struct zbud_header, buddy);
			list_del(&zhdr->buddy);
			if (zhdr->first_chunks == 0)
				bud = FIRST;
			else
				bud = LAST;
			goto found;
		}
	}

	/* Couldn't find unbuddied zbud page, create new one */
	spin_unlock(&pool->lock);
	page = alloc_page(gfp);
	if (!page)
		return -ENOMEM;
	spin_lock(&pool->lock);
	pool->pages_nr++;
	zhdr = init_zbud_page(page);
	bud = FIRST;

found:
	if (bud == FIRST)
		zhdr->first_chunks = chunks;
	else
		zhdr->last_chunks = chunks;

	if (zhdr->first_chunks == 0 || zhdr->last_chunks == 0) {
		/* Add to unbuddied list */
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	} else {
		/* Add to buddied list */
		list_add(&zhdr->buddy, &pool->buddied);
	}

	/* Add/move zbud page to beginning of LRU */
	if (!list_empty(&zhdr->lru))
		list_del(&zhdr->lru);
	list_add(&zhdr->lru, &pool->lru);

	*handle = encode_handle(zhdr, bud);
	spin_unlock(&pool->lock);

	return 0;
}

/**
 * zbud_free() - frees the allocation associated with the given handle
 * @pool:	pool in which the allocation resided
 * @handle:	handle associated with the allocation returned by zbud_alloc()
 *
 * In the case that the zbud page in which the allocation resides is under
 * reclaim, as indicated by the PG_reclaim flag being set, this function
 * only sets the first|last_chunks to 0.  The page is actually freed
 * once both buddies are evicted (see zbud_reclaim_page() below).
 */
static void zbud_free(struct zbud_pool *pool, unsigned long handle)
{
	struct zbud_header *zhdr;
	int freechunks;

	spin_lock(&pool->lock);
	zhdr = handle_to_zbud_header(handle);

	/* If first buddy, handle will be page aligned */
	if ((handle - ZHDR_SIZE_ALIGNED) & ~PAGE_MASK)
		zhdr->last_chunks = 0;
	else
		zhdr->first_chunks = 0;

	if (zhdr->under_reclaim) {
		/* zbud page is under reclaim, reclaim will free */
		spin_unlock(&pool->lock);
		return;
	}

	/* Remove from existing buddy list */
	list_del(&zhdr->buddy);

	if (zhdr->first_chunks == 0 && zhdr->last_chunks == 0) {
		/* zbud page is empty, free */
		list_del(&zhdr->lru);
		free_zbud_page(zhdr);
		pool->pages_nr--;
	} else {
		/* Add to unbuddied list */
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	}

	spin_unlock(&pool->lock);
}

/**
 * zbud_reclaim_page() - evicts allocations from a pool page and frees it
 * @pool:	pool from which a page will attempt to be evicted
 * @retries:	number of pages on the LRU list for which eviction will
 *		be attempted before failing
 *
 * zbud reclaim is different from normal system reclaim in that the reclaim is
 * done from the bottom, up.  This is because only the bottom layer, zbud, has
 * information on how the allocations are organized within each zbud page. This
 * has the potential to create interesting locking situations between zbud and
 * the user, however.
 *
 * To avoid these, this is how zbud_reclaim_page() should be called:
 *
 * The user detects a page should be reclaimed and calls zbud_reclaim_page().
 * zbud_reclaim_page() will remove a zbud page from the pool LRU list and call
 * the user-defined eviction handler with the pool and handle as arguments.
 *
 * If the handle can not be evicted, the eviction handler should return
 * non-zero. zbud_reclaim_page() will add the zbud page back to the
 * appropriate list and try the next zbud page on the LRU up to
 * a user defined number of retries.
 *
 * If the handle is successfully evicted, the eviction handler should
 * return 0 _and_ should have called zbud_free() on the handle. zbud_free()
 * contains logic to delay freeing the page if the page is under reclaim,
 * as indicated by the setting of the PG_reclaim flag on the underlying page.
 *
 * If all buddies in the zbud page are successfully evicted, then the
 * zbud page can be freed.
 *
 * Returns: 0 if page is successfully freed, otherwise -EINVAL if there are
 * no pages to evict or an eviction handler is not registered, -EAGAIN if
 * the retry limit was hit.
 */
static int zbud_reclaim_page(struct zbud_pool *pool, unsigned int retries)
{
	int i, ret, freechunks;
	struct zbud_header *zhdr;
	unsigned long first_handle = 0, last_handle = 0;

	spin_lock(&pool->lock);
	if (list_empty(&pool->lru)) {
		spin_unlock(&pool->lock);
		return -EINVAL;
	}
	for (i = 0; i < retries; i++) {
		zhdr = list_last_entry(&pool->lru, struct zbud_header, lru);
		list_del(&zhdr->lru);
		list_del(&zhdr->buddy);
		/* Protect zbud page against free */
		zhdr->under_reclaim = true;
		/*
		 * We need encode the handles before unlocking, since we can
		 * race with free that will set (first|last)_chunks to 0
		 */
		first_handle = 0;
		last_handle = 0;
		if (zhdr->first_chunks)
			first_handle = encode_handle(zhdr, FIRST);
		if (zhdr->last_chunks)
			last_handle = encode_handle(zhdr, LAST);
		spin_unlock(&pool->lock);

		/* Issue the eviction callback(s) */
		if (first_handle) {
			ret = pool->zpool_ops->evict(pool->zpool, first_handle);
			if (ret)
				goto next;
		}
		if (last_handle) {
			ret = pool->zpool_ops->evict(pool->zpool, last_handle);
			if (ret)
				goto next;
		}
next:
		spin_lock(&pool->lock);
		zhdr->under_reclaim = false;
		if (zhdr->first_chunks == 0 && zhdr->last_chunks == 0) {
			/*
			 * Both buddies are now free, free the zbud page and
			 * return success.
			 */
			free_zbud_page(zhdr);
			pool->pages_nr--;
			spin_unlock(&pool->lock);
			return 0;
		} else if (zhdr->first_chunks == 0 ||
				zhdr->last_chunks == 0) {
			/* add to unbuddied list */
			freechunks = num_free_chunks(zhdr);
			list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
		} else {
			/* add to buddied list */
			list_add(&zhdr->buddy, &pool->buddied);
		}

		/* add to beginning of LRU */
		list_add(&zhdr->lru, &pool->lru);
	}
	spin_unlock(&pool->lock);
	return -EAGAIN;
}

/**
 * zbud_map() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be mapped
 *
 * While trivial for zbud, the mapping functions for others allocators
 * implementing this allocation API could have more complex information encoded
 * in the handle and could create temporary mappings to make the data
 * accessible to the user.
 *
 * Returns: a pointer to the mapped allocation
 */
static void *zbud_map(struct zbud_pool *pool, unsigned long handle)
{
	return (void *)(handle);
}

/**
 * zbud_unmap() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be unmapped
 */
static void zbud_unmap(struct zbud_pool *pool, unsigned long handle)
{
}

/**
 * zbud_get_pool_size() - gets the zbud pool size in pages
 * @pool:	pool whose size is being queried
 *
 * Returns: size in pages of the given pool.  The pool lock need not be
 * taken to access pages_nr.
 */
static u64 zbud_get_pool_size(struct zbud_pool *pool)
{
	return pool->pages_nr;
}

/*****************
 * zpool
 ****************/

static void *zbud_zpool_create(const char *name, gfp_t gfp,
			       const struct zpool_ops *zpool_ops,
			       struct zpool *zpool)
{
	struct zbud_pool *pool;

	pool = zbud_create_pool(gfp);
	if (pool) {
		pool->zpool = zpool;
		pool->zpool_ops = zpool_ops;
	}
	return pool;
}

static void zbud_zpool_destroy(void *pool)
{
	zbud_destroy_pool(pool);
}

static int zbud_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	return zbud_alloc(pool, size, gfp, handle);
}
static void zbud_zpool_free(void *pool, unsigned long handle)
{
	zbud_free(pool, handle);
}

static int zbud_zpool_shrink(void *pool, unsigned int pages,
			unsigned int *reclaimed)
{
	unsigned int total = 0;
	int ret = -EINVAL;

	while (total < pages) {
		ret = zbud_reclaim_page(pool, 8);
		if (ret < 0)
			break;
		total++;
	}

	if (reclaimed)
		*reclaimed = total;

	return ret;
}

static void *zbud_zpool_map(void *pool, unsigned long handle,
			enum zpool_mapmode mm)
{
	return zbud_map(pool, handle);
}
static void zbud_zpool_unmap(void *pool, unsigned long handle)
{
	zbud_unmap(pool, handle);
}

static u64 zbud_zpool_total_size(void *pool)
{
	return zbud_get_pool_size(pool) * PAGE_SIZE;
}

static struct zpool_driver zbud_zpool_driver = {
	.type =		"zbud",
	.sleep_mapped = true,
	.owner =	THIS_MODULE,
	.create =	zbud_zpool_create,
	.destroy =	zbud_zpool_destroy,
	.malloc =	zbud_zpool_malloc,
	.free =		zbud_zpool_free,
	.shrink =	zbud_zpool_shrink,
	.map =		zbud_zpool_map,
	.unmap =	zbud_zpool_unmap,
	.total_size =	zbud_zpool_total_size,
};


static int __init init_zbud(void)
{
	/* Make sure the zbud header will fit in one chunk */
	BUILD_BUG_ON(sizeof(struct zbud_header) > ZHDR_SIZE_ALIGNED);
	pr_info("zbud: zbud loaded\n");

	zpool_register_driver(&zbud_zpool_driver);

	return 0;
}

late_initcall(init_zbud);