// This file is for migrating zswap from 6.4.3 to 3.12.60 
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
#include <linux/scatterlist.h> 
#include <linux/list.h>


#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/kernel.h>

/*********************************
* compression functions
**********************************/
enum comp_op {
	ZSWAP_COMPOP_COMPRESS,
	ZSWAP_COMPOP_DECOMPRESS
};

int zswap_comp_op(enum comp_op op, unsigned int *src, unsigned int slen, unsigned int *dst, unsigned int *dlen);

int zswap_comp_init(void);


/*********************************
* tunables
**********************************/

#define CONFIG_ZSWAP_COMPRESSOR_DEFAULT "lzo"
#define CONFIG_ZSWAP_ZPOOL_DEFAULT "zbud"

/*********************************
* data structures
**********************************/
struct crypto_acomp {
	// int (*compress)(struct acomp_req *req);
	// int (*decompress)(struct acomp_req *req);
	// void (*dst_free)(struct scatterlist *dst);
	// unsigned int reqsize;
	// struct crypto_tfm base;
	int nul;
};

struct acomp_req {
	// struct crypto_async_request base;
	// struct scatterlist *src;
	// struct scatterlist *dst;
	// unsigned int slen;
	// unsigned int dlen;
	// u32 flags;
	// void *__ctx[] CRYPTO_MINALIGN_ATTR;
	unsigned long *src;
	unsigned long *dst;
	unsigned int slen;
	unsigned int dlen;
};

struct crypto_wait {
	struct completion completion;   // v2就在该头文件，v1有实现completion
	int err;
};

struct obj_cgroup {
    int nul;          // 表示空
};


/*********************************
* helpers and fwd declarations
**********************************/
// unsigned long totalram_pages(void);
#define totalram_pages() (totalram_pages)


/*********************************
* zswap entry functions
**********************************/
void obj_cgroup_uncharge_zswap(struct obj_cgroup *objcg, size_t size);

void obj_cgroup_put(struct obj_cgroup *objcg);

/*********************************
* per-cpu code
**********************************/

struct crypto_acomp *crypto_alloc_acomp_node(const char *alg_name, u32 type, u32 mask, int node);

struct acomp_req *acomp_request_alloc(struct crypto_acomp *acomp);

void crypto_free_acomp(struct crypto_acomp *tfm);

void crypto_init_wait(struct crypto_wait *wait);

void acomp_request_set_callback(struct acomp_req *req, u32 flgs, crypto_completion_t cmpl, void *data);

void crypto_req_done(void *data, int err);

void acomp_request_free(struct acomp_req *req);

/*********************************
* pool functions
**********************************/

void strscpy(char *dest, const char *src, size_t count);

void maybe_kfree_parameter(void *param);

void param_free_charp(void *arg);

int cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node);

int cpuhp_state_remove_instance(enum cpuhp_state state, struct hlist_node *node);

#define __GFP_KSWAPD_RECLAIM 0

/*********************************
* param callbacks
**********************************/

#define fallthrough do { } while (0)

/*********************************
* writeback code
**********************************/
#define raw_cpu_ptr(ptr)	per_cpu_ptr(ptr, 0)

void *memset_l(unsigned long *p, unsigned long v, __kernel_size_t n);

void *memset32(uint32_t *s, uint32_t v, size_t count);

void *memset64(uint64_t *s, uint64_t v, size_t count);

static inline int crypto_has_acomp(const char *alg_name, u32 type, u32 mask)
{
	// type &= ~CRYPTO_ALG_TYPE_MASK;
	// type |= CRYPTO_ALG_TYPE_ACOMPRESS;
	// mask |= CRYPTO_ALG_TYPE_ACOMPRESS_MASK;

	// return crypto_has_alg(alg_name, type, mask);
	return 1; // 返回1代表存在，返回0代表不存在
    // !暂时一定返回1，最后需要确定他能用哪些alg_name，判断是能用的alg_name则返回1否则返回0
}

void acomp_request_set_params(struct acomp_req *req,
					    struct scatterlist *src,
					    struct scatterlist *dst,
					    unsigned int slen,
					    unsigned int dlen);

int crypto_acomp_compress(struct acomp_req *req);

int crypto_acomp_decompress(struct acomp_req *req);

int crypto_wait_req(int err, struct crypto_wait *wait);

struct page *__read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated);

struct page *page_folio(struct page* p);


#define CONCATENATE(arg1, arg2) CONCATENATE1(arg1, arg2)
#define CONCATENATE1(arg1, arg2) CONCATENATE2(arg1, arg2)
#define CONCATENATE2(arg1, arg2) arg1##arg2

#define SELECT_MACRO(_1,_2,_3,NAME,...) NAME
#define __swap_writepage(...) SELECT_MACRO(__VA_ARGS__, __swap_writepage3, __swap_writepage2, __swap_writepage1)(__VA_ARGS__)

#define __swap_writepage2(arg1, arg2) __swap_writepage(arg1, arg2, end_swap_bio_write)
#define __swap_writepage3(arg1, arg2, arg3) __swap_writepage(arg1, arg2, arg3)

/*********************************
* frontswap hooks
**********************************/
struct obj_cgroup *get_obj_cgroup_from_page(struct page *page);

bool obj_cgroup_may_zswap(struct obj_cgroup *objcg);

void obj_cgroup_charge_zswap(struct obj_cgroup *objcg, size_t size);

void count_objcg_event(struct obj_cgroup *objcg, enum vm_event_item idx);

#define ZSWPIN 1000
#define ZSWPOUT 1001


/*********************************
* module init and exit
**********************************/

// enum cpuhp_state {
// 	CPUHP_MM_ZSWP_POOL_PREPARE
// }
#define CPUHP_MM_ZSWP_POOL_PREPARE 0
#define CPUHP_MM_ZSWP_MEM_PREPARE 0


int cpuhp_setup_state(enum cpuhp_state state,
				    const char *name,
				    int (*startup)(unsigned int cpu),
				    int (*teardown)(unsigned int cpu));

int cpuhp_setup_state_multi(enum cpuhp_state state,
					  const char *name,
					  int (*startup)(unsigned int cpu,
							 struct hlist_node *node),
					  int (*teardown)(unsigned int cpu,
							  struct hlist_node *node));

void cpuhp_remove_state(enum cpuhp_state state);

// zbud.c中用到
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)




/*********************************
* zpool.h
**********************************/
struct zpool;

struct zpool_ops {
	int (*evict)(struct zpool *pool, unsigned long handle);
};

enum zpool_mapmode {
	ZPOOL_MM_RW, /* normal read-write mapping */
	ZPOOL_MM_RO, /* read-only (no copy-out at unmap time) */
	ZPOOL_MM_WO, /* write-only (no copy-in at map time) */

	ZPOOL_MM_DEFAULT = ZPOOL_MM_RW
};

bool zpool_has_pool(char *type);

struct zpool *zpool_create_pool(const char *type, const char *name,
			gfp_t gfp, const struct zpool_ops *ops);

const char *zpool_get_type(struct zpool *pool);

void zpool_destroy_pool(struct zpool *pool);

bool zpool_malloc_support_movable(struct zpool *pool);

int zpool_malloc(struct zpool *pool, size_t size, gfp_t gfp,
			unsigned long *handle);

void zpool_free(struct zpool *pool, unsigned long handle);

int zpool_shrink(struct zpool *pool, unsigned int pages,
			unsigned int *reclaimed);

void *zpool_map_handle(struct zpool *pool, unsigned long handle,
			enum zpool_mapmode mm);

void zpool_unmap_handle(struct zpool *pool, unsigned long handle);

u64 zpool_get_total_size(struct zpool *pool);


struct zpool_driver {
	char *type;
	struct module *owner;
	atomic_t refcount;
	struct list_head list;

	void *(*create)(const char *name,
			gfp_t gfp,
			const struct zpool_ops *ops,
			struct zpool *zpool);
	void (*destroy)(void *pool);

	bool malloc_support_movable;
	int (*malloc)(void *pool, size_t size, gfp_t gfp,
				unsigned long *handle);
	void (*free)(void *pool, unsigned long handle);

	int (*shrink)(void *pool, unsigned int pages,
				unsigned int *reclaimed);

	bool sleep_mapped;
	void *(*map)(void *pool, unsigned long handle,
				enum zpool_mapmode mm);
	void (*unmap)(void *pool, unsigned long handle);

	u64 (*total_size)(void *pool);
};

void zpool_register_driver(struct zpool_driver *driver);

int zpool_unregister_driver(struct zpool_driver *driver);

bool zpool_evictable(struct zpool *pool);
bool zpool_can_sleep_mapped(struct zpool *pool);
