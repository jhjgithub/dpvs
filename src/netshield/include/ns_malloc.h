#ifndef __NS_MALLOC_H__
#define __NS_MALLOC_H__

#if 0
extern atomic_t ns_real_alloc_mem;
extern atomic_t ns_valloc_mem;
extern atomic_t ns_alloc_fail;

//////////////////////////////////////////////////////

#if defined(CONFIG_NUMA) || defined(CONFIG_SLOB)
//#define USE_NUMA 1
#endif

static inline void* _ns_malloc(size_t len, gfp_t gfp)
{
	void* obj;
	
#if defined(USE_NUMA)
	obj = kmalloc_node(len, gfp, numa_node_id());
#else
	obj = kmalloc(len, gfp);
#endif

	//atomic_add(ksize(obj), &ns_real_alloc_mem);

	return obj;
}

static inline void* _ns_malloc_v(size_t len)
{
	void* obj;
	
#if defined(USE_NUMA)
	obj = vmalloc_node(len, numa_node_id());
#else
	obj = vmalloc(len);
#endif

	//atomic_inc(&ns_valloc_mem);

	return obj;
}

static inline void* _ns_malloc_z(size_t len, gfp_t gfp) 
{
	void* obj;
	
#if defined(USE_NUMA)
	obj = kzalloc_node(len, gfp, numa_node_id());
#else
	obj = kzalloc(len, gfp);
#endif

	//atomic_add(ksize(obj), &ns_real_alloc_mem);

	return obj;
}

static inline void* _ns_cache_malloc_z(void *cachep, gfp_t gfp)
{
	void* obj;
	
#if defined(USE_NUMA)
	obj = kmem_cache_alloc_node((struct kmem_cache*)cachep, gfp|__GFP_ZERO, numa_node_id());
#else
	obj = kmem_cache_zalloc((struct kmem_cache*)cachep, gfp);
#endif

	//atomic_add(ksize(obj), &ns_real_alloc_mem);

	return obj;
}

static inline void* _ns_cache_malloc(void *cachep, gfp_t gfp)
{
	void *obj;

#if defined(USE_NUMA)
	obj = kmem_cache_alloc_node(cachep, numa_node_id(), gfp);
#else
	obj = kmem_cache_alloc((struct kmem_cache*)cachep, gfp);
#endif

	//atomic_add(ksize(obj), &ns_real_alloc_mem);

	return obj;
}

static inline void _ns_cache_free(void *cachep, void* objp)
{
	//atomic_sub(ksize((const void *)objp), &ns_real_alloc_mem);
	kmem_cache_free((struct kmem_cache*)cachep, objp);
}

static inline void _ns_free(void* objp)
{
	//atomic_sub(ksize((const void *)objp), &ns_real_alloc_mem);
	kfree(objp);
}

static inline void _ns_free_v(void* objp)
{
	//atomic_dec(&ns_valloc_mem);
	vfree(objp);
}

#define ns_mem_assert(addr,msg,run) \
	if (unlikely(addr==NULL)) { \
		/* atomic_inc(&ns_alloc_fail);*/ \
		ns_err("No Memory: %s",msg); run; \
	}

#define ns_malloc_a(len) 		_ns_malloc(len, GFP_ATOMIC)
#define ns_malloc_k(len) 		_ns_malloc(len, GFP_KERNEL)
#define ns_malloc_v(s) 			_ns_malloc_v(s)
#define ns_malloc_az(len) 		_ns_malloc_z(len, GFP_ATOMIC)
#define ns_malloc_kz(len) 		_ns_malloc_z(len, GFP_KERNEL)

#define ns_cache_malloc_a(c)	_ns_cache_malloc(c, GFP_ATOMIC)
#define ns_cache_malloc_k(c)	_ns_cache_malloc(c, GFP_KERNEL)
#define ns_cache_malloc_az(c)	_ns_cache_malloc_z(c, GFP_ATOMIC)
#define ns_cache_malloc_kz(c)	_ns_cache_malloc_z(c, GFP_KERNEL)

#define ns_free(o)				_ns_free(o)
#define ns_free_v(o)			_ns_free_v(o)
#define ns_cache_free(c,o)		_ns_cache_free(c,o)
#else

#define ns_mem_assert(addr,msg,run) \
	if (unlikely(addr==NULL)) { \
		/* atomic_inc(&ns_alloc_fail);*/ \
		ns_err("No Memory: %s",msg); run; \
	}

#define ns_malloc_a(len) 		rte_malloc(NULL, len, 0)
#define ns_malloc_k(len) 		rte_malloc(NULL, len, 0) 
#define ns_malloc_v(len) 		rte_malloc(NULL, len, 0) 
#define ns_malloc_az(len) 		rte_zmalloc(NULL, len, 0) 
#define ns_malloc_kz(len) 		rte_zmalloc(NULL, len, 0) 

#define ns_cache_malloc_a(len)	rte_malloc(NULL, len, 0) 
#define ns_cache_malloc_k(len)	rte_malloc(NULL, len, 0) 
#define ns_cache_malloc_az(len)	rte_malloc(NULL, len, 0) 
#define ns_cache_malloc_kz(len) rte_malloc(NULL, len, 0) 

#define ns_free(o)				rte_free(o)
#define ns_free_v(o)			rte_free(o)
#define ns_cache_free(c,o)		rte_free(o)
#endif


#endif 
