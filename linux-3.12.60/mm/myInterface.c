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


void obj_cgroup_uncharge_zswap(struct obj_cgroup *objcg, size_t size) {
    return;
}

void obj_cgroup_put(struct obj_cgroup *objcg){
    return;
}



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

	do {
		
		found_page = find_get_page(swapper_space, entry.val);
		if (found_page)
			break;

		
		if (!new_page) {
			new_page = alloc_page(GFP_KERNEL);
			if (!new_page)
				break; /* Out of memory */
		}

		
		err = radix_tree_preload(GFP_KERNEL);
		if (err)
			break;

		
		err = swapcache_prepare(entry);
		if (err == -EEXIST) { 
			radix_tree_preload_end();
			continue;
		}
		if (err) { 
			radix_tree_preload_end();
			break;
		}

		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = __add_to_swap_cache(new_page, entry);
		if (likely(!err)) {
			radix_tree_preload_end();
			lru_cache_add_anon(new_page);
			*new_page_allocated = true;
			return new_page;
		}
		radix_tree_preload_end();
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		
		swapcache_free(entry, NULL);
	} while (err != -ENOMEM);

	if (new_page)
		page_cache_release(new_page);
	if (!found_page)
		return NULL;
	return found_page;
}

struct page *page_folio(struct page* p) {
	return p;
}


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

	int result = zswap_comp_init();

	return result;
}

void cpuhp_remove_state(enum cpuhp_state state)
{
	return;
}


struct zpool {
	struct zpool_driver *driver;
	void *pool;
};

static LIST_HEAD(drivers_head);
static DEFINE_SPINLOCK(drivers_lock);


void zpool_register_driver(struct zpool_driver *driver)
{
	spin_lock(&drivers_lock);
	atomic_set(&driver->refcount, 0);
	list_add(&driver->list, &drivers_head);
	spin_unlock(&drivers_lock);
}

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

void zpool_destroy_pool(struct zpool *zpool)
{
	pr_debug("destroying pool type %s\n", zpool->driver->type);

	zpool->driver->destroy(zpool->pool);
	zpool_put_driver(zpool->driver);
	kfree(zpool);
}


const char *zpool_get_type(struct zpool *zpool)
{
	return zpool->driver->type;
}


bool zpool_malloc_support_movable(struct zpool *zpool)
{
	return zpool->driver->malloc_support_movable;
}


int zpool_malloc(struct zpool *zpool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	return zpool->driver->malloc(zpool->pool, size, gfp, handle);
}


void zpool_free(struct zpool *zpool, unsigned long handle)
{
	zpool->driver->free(zpool->pool, handle);
}


int zpool_shrink(struct zpool *zpool, unsigned int pages,
			unsigned int *reclaimed)
{
	return zpool->driver->shrink ?
	       zpool->driver->shrink(zpool->pool, pages, reclaimed) : -EINVAL;
}


void *zpool_map_handle(struct zpool *zpool, unsigned long handle,
			enum zpool_mapmode mapmode)
{
	return zpool->driver->map(zpool->pool, handle, mapmode);
}


void zpool_unmap_handle(struct zpool *zpool, unsigned long handle)
{
	zpool->driver->unmap(zpool->pool, handle);
}


u64 zpool_get_total_size(struct zpool *zpool)
{
	return zpool->driver->total_size(zpool->pool);
}


bool zpool_evictable(struct zpool *zpool)
{
	return zpool->driver->shrink;
}


bool zpool_can_sleep_mapped(struct zpool *zpool)
{
	return zpool->driver->sleep_mapped;
}





#define NCHUNKS_ORDER	6

#define CHUNK_SHIFT	(PAGE_SHIFT - NCHUNKS_ORDER)
#define CHUNK_SIZE	(1 << CHUNK_SHIFT)
#define ZHDR_SIZE_ALIGNED CHUNK_SIZE
#define NCHUNKS		((PAGE_SIZE - ZHDR_SIZE_ALIGNED) >> CHUNK_SHIFT)

struct zbud_pool;


struct zbud_pool {
	spinlock_t lock;
	union {
		struct list_head buddied;
		struct list_head unbuddied[NCHUNKS];
	};
	struct list_head lru;
	u64 pages_nr;
	struct zpool *zpool;
	const struct zpool_ops *zpool_ops;
};


struct zbud_header {
	struct list_head buddy;
	struct list_head lru;
	unsigned int first_chunks;
	unsigned int last_chunks;
	bool under_reclaim;
};

enum buddy {
	FIRST,
	LAST
};

static int size_to_chunks(size_t size)
{
	return (size + CHUNK_SIZE - 1) >> CHUNK_SHIFT;
}

#define for_each_unbuddied_list(_iter, _begin) \
	for ((_iter) = (_begin); (_iter) < NCHUNKS; (_iter)++)

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

static void free_zbud_page(struct zbud_header *zhdr)
{
	__free_page(virt_to_page(zhdr));
}

static unsigned long encode_handle(struct zbud_header *zhdr, enum buddy bud)
{
	unsigned long handle;

	
	handle = (unsigned long)zhdr;
	if (bud == FIRST)
		handle += ZHDR_SIZE_ALIGNED;
	else 
		handle += PAGE_SIZE - (zhdr->last_chunks  << CHUNK_SHIFT);
	return handle;
}

static struct zbud_header *handle_to_zbud_header(unsigned long handle)
{
	return (struct zbud_header *)(handle & PAGE_MASK);
}

static int num_free_chunks(struct zbud_header *zhdr)
{
	return NCHUNKS - zhdr->first_chunks - zhdr->last_chunks;
}



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

static void zbud_destroy_pool(struct zbud_pool *pool)
{
	kfree(pool);
}


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
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	} else {
		list_add(&zhdr->buddy, &pool->buddied);
	}

	if (!list_empty(&zhdr->lru))
		list_del(&zhdr->lru);
	list_add(&zhdr->lru, &pool->lru);

	*handle = encode_handle(zhdr, bud);
	spin_unlock(&pool->lock);

	return 0;
}


static void zbud_free(struct zbud_pool *pool, unsigned long handle)
{
	struct zbud_header *zhdr;
	int freechunks;

	spin_lock(&pool->lock);
	zhdr = handle_to_zbud_header(handle);

	if ((handle - ZHDR_SIZE_ALIGNED) & ~PAGE_MASK)
		zhdr->last_chunks = 0;
	else
		zhdr->first_chunks = 0;

	if (zhdr->under_reclaim) {
		spin_unlock(&pool->lock);
		return;
	}

	list_del(&zhdr->buddy);

	if (zhdr->first_chunks == 0 && zhdr->last_chunks == 0) {
		list_del(&zhdr->lru);
		free_zbud_page(zhdr);
		pool->pages_nr--;
	} else {
		freechunks = num_free_chunks(zhdr);
		list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
	}

	spin_unlock(&pool->lock);
}


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
		zhdr->under_reclaim = true;
		first_handle = 0;
		last_handle = 0;
		if (zhdr->first_chunks)
			first_handle = encode_handle(zhdr, FIRST);
		if (zhdr->last_chunks)
			last_handle = encode_handle(zhdr, LAST);
		spin_unlock(&pool->lock);

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
		
			free_zbud_page(zhdr);
			pool->pages_nr--;
			spin_unlock(&pool->lock);
			return 0;
		} else if (zhdr->first_chunks == 0 ||
				zhdr->last_chunks == 0) {
			freechunks = num_free_chunks(zhdr);
			list_add(&zhdr->buddy, &pool->unbuddied[freechunks]);
		} else {
			list_add(&zhdr->buddy, &pool->buddied);
		}

		list_add(&zhdr->lru, &pool->lru);
	}
	spin_unlock(&pool->lock);
	return -EAGAIN;
}


static void *zbud_map(struct zbud_pool *pool, unsigned long handle)
{
	return (void *)(handle);
}


static void zbud_unmap(struct zbud_pool *pool, unsigned long handle)
{
}


static u64 zbud_get_pool_size(struct zbud_pool *pool)
{
	return pool->pages_nr;
}


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
	BUILD_BUG_ON(sizeof(struct zbud_header) > ZHDR_SIZE_ALIGNED);
	pr_info("zbud: zbud loaded\n");

	zpool_register_driver(&zbud_zpool_driver);

	return 0;
}

late_initcall(init_zbud);