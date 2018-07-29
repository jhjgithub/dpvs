#ifndef _NS_TYPE_DEFS_H_
#define _NS_TYPE_DEFS_H_

//#include <linux/version.h>

//#include <ipv4.h>
#include <stdint.h>
#include "dpdk.h"
#include "common.h"
//#include "netif.h"
//#include "route.h"
#include <list.h>

///////////////////////////////////////////////////////////////////////////
// kernel과 user mode의 endian mode 정의 호환성을 위해서 사용
///////////////////////////////////////////////////////////////////////////

#if 0
#ifdef __KERNEL__
#include <asm/byteorder.h>
#else
#include <endian.h>
#endif

#if defined(__KERNEL__)
#  if defined(__BIG_ENDIAN)
#define NS_BIG_ENDIAN
#  elif defined(__LITTLE_ENDIAN)
#define NS_LITTLE_ENDIAN
#  else
#    error "Could not determine byte order"
#  endif
#elif defined(__BYTE_ORDER)
#  if __BYTE_ORDER == __BIG_ENDIAN
#define NS_BIG_ENDIAN
#  elif __BYTE_ORDER == __LITTLE_ENDIAN
#define NS_LITTLE_ENDIAN
#  else
#    error "Could not determine byte order"
#  endif
#endif
#endif

///////////////////////////////////////////////////////////////////////////
// Define Hooking ID
///////////////////////////////////////////////////////////////////////////

enum {
	NS_HOOK_PRE_ROUTING 	= 0,
	NS_HOOK_LOCAL_IN 		= 1,
	NS_HOOK_FORWARD 		= 2,
	NS_HOOK_LOCAL_OUT 		= 3,
	NS_HOOK_POST_ROUTING 	= 4,

	NS_HOOK_MAX
};

enum {
	NS_DEL_SESSION 	= 	-1,
	NS_DROP 		= 0,
	NS_ACCEPT 		= 1,
	NS_STOLEN 		= 2,
	NS_REPEAT 		= 3,
	NS_STOP 		= 4,

	NS_MAX
};

enum {
	NS_FALSE 	= 0,
	NS_TRUE 	= 1,
};

enum {
	NS_FAIL 		= -1,
	NS_SUCCESS 	= 0,
	NS_ERROR 		= 1,
};

/// 함수 옵션들의 집합
enum {
	FUNC_FLAG_IPV6 = 0x01,
};
	

///////////////////////////////////////////////////////////////////////////
// kernel과 user의 코드 호환성을 위해서 정의함.
// 또한 32/64 bit의 호환성을 고려함.
///////////////////////////////////////////////////////////////////////////
#if 0
typedef struct hlist_node 	hlist_node_t;
typedef struct hlist_head 	hlist_head_t;
typedef struct list_head 	list_head_t;
typedef struct rcu_head 	rcu_head_t;
typedef struct dst_entry	dstent_t;
typedef struct hh_cache		hh_cache_t;
typedef struct neighbour    neigh_t;
typedef struct xfrm_state 	ipsec_sad_t; // Security Association Database (SAD)
typedef struct xfrm_policy 	ipsec_spd_t; // Security Policy Database (SPD)
typedef struct ctl_table 	ctltab_t;
typedef struct seq_operations seqops_t;
typedef wait_queue_head_t 	wq_head_t;


#define ns_iph(__skb)	ip_hdr(__skb)
#define ns_iph6(__skb) 	ipv6_hdr(__skb)
#define ns_tcph(__skb)	tcp_hdr(__skb)
#define ns_udph(__skb)	udp_hdr(__skb)
#define ns_icmph(__skb)	icmp_hdr(__skb)
#define ns_raw(__skb)	skb_transport_header(__skb)
#define ns_eth(__skb)  	(eth_t*)skb_mac_header(__skb)
#define ns_iplen(__skb)	(__skb->len)
#define ns_task(__skb) 	(ns_task_t*)(&__skb->nstask[0])
#define ns_for_each_netdev(dev) for_each_netdev(&init_net, dev)
#define htonll(x) 		__cpu_to_be64(x)
#define ntohll(x) 		__be64_to_cpu(x)
#define is_same_ether_addr(d,s) !compare_ether_addr(d,s)


typedef struct sk_buff 		skb_t;
typedef	struct net_device 	netdev_t;
typedef spinlock_t 			nslock_t;
typedef struct Qdisc 		qdisc_t;
typedef struct Qdisc_ops 	qdisc_op_t;
typedef struct netdev_queue netdev_queue_t;
typedef struct ctl_table 	ctl_table_t;


///////////////////////////////////////////////////////////////////////////
// kernel과 user mode의 공통 사항
///////////////////////////////////////////////////////////////////////////

typedef struct iphdr		iph_t;
typedef struct ipv6hdr 		iph6_t;
typedef struct tcphdr		tph_t;
typedef struct udphdr		uph_t;
typedef struct icmphdr		ich_t;
typedef struct icmp6hdr 	ich6_t;
typedef struct arphdr 		arh_t;
typedef struct ethhdr 		eth_t;
typedef	struct ipv6_opt_hdr ip6opt_t;
typedef struct timer_list 	timer_list_t;
typedef unsigned long 		ulong_t;
typedef uint8_t 			nid_t; 		///< for WSP Node ID
typedef uint32_t 			ips_rid_t;	///< for IPS Rule ID
typedef uint16_t 			ips_app_gid_t;	///< for IPS Appliction Group ID
typedef uint16_t 			ips_att_gid_t;	///< for IPS Attack Group ID
typedef uint32_t 			ipolicy_id_t;	///< for IPS Policy ID
#endif

#define ns_iph(__skb)	ip4_hdr(__skb)

typedef __int128_t 			int128_t;
typedef __uint128_t 		uint128_t;
typedef uint32_t 			nic_id_t;
typedef struct ipv4_hdr 	iph_t;
typedef struct ipv6_hdr     iph6_t;
typedef struct tcphdr 		tcph_t;
typedef struct udphdr 		udph_t;
typedef struct icmphdr 		icmph_t;
typedef struct list_head  	list_head_t;

typedef uint32_t 			ip4_t; 		///< for IPv4 address
typedef __uint128_t 		ip6_t;
typedef struct rte_mbuf	 	skb_t;
typedef rte_spinlock_t 		spinlock_t;
typedef rte_atomic32_t 	  	atomic_t;
typedef uint8_t 			ns_node_id_t; 	///< for NetShield Node ID

typedef struct hlist_node 	hlist_node_t;
typedef struct hlist_head 	hlist_head_t;
typedef struct list_head 	list_head_t;

#define atomic_t                rte_atomic32_t
#define atomic_read(v)          rte_atomic32_read(v)
#define atomic_set(v, i)        rte_atomic32_set(v, i)

#define atomic_inc(v)           rte_atomic32_add(v, 1)
#define atomic_dec(v)           rte_atomic32_sub(v, 1)

#define atomic_inc_and_test(v)  rte_atomic32_inc_and_test(v)
#define atomic_dec_and_test(v)  rte_atomic32_dec_and_test(v)

#define atomic_inc_return(v)    rte_atomic32_add_return(v, 1)
#define atomic_dec_return(v)    rte_atomic32_sub_return(v, 1)
#define atomic_sub_and_test(i, v) (rte_atomic32_sub_return(v, i) == 0)

///////////////////////////////////////////
// 
/* INFO: LOCK은 반드시 아래와 같은 스티일로 코딩 해야 한다.
*
*  ns_rw_lock_irq() {
*	 something(...)
*  } ns_rw_unlock_irq();
*
*/
// 데이터를 write를 해야 하는 경우 사용
// _irq는 soft-irq(Bottom-Half) 상태에서 사용
#define	ns_rw_trylock_irq(l) rte_spinlock_trylock(l)
#define	ns_rw_lock_irq(l) 	rte_spinlock_lock(l);
#define	ns_rw_unlock_irq(l) rte_spinlock_unlock(l);
#define	ns_rw_lock(l)		rte_spinlock_lock(l);
#define	ns_rw_unlock(l)		rte_spinlock_unlock(l);

// 데이터를 읽기만 하는 경우 사용
#if 0
#define	ns_rd_lock_irq()	rcu_read_lock_bh();
#define	ns_rd_unlock_irq() 	rcu_read_unlock_bh();
#define	ns_rd_lock()		rcu_read_lock();
#define	ns_rd_unlock()		rcu_read_unlock();
#else
#define	ns_rd_lock_irq()	
#define	ns_rd_unlock_irq() 	
#define	ns_rd_lock()		
#define	ns_rd_unlock()		

#endif

#define ns_init_lock(l) 	rte_spinlock_init(l)
#if 0
typedef union _ip6_t {
	uint8_t		a8[16];
	uint16_t	a16[8];
	uint32_t	a32[4];
	uint64_t	a64[2]; 	// 0: high part, 1: low part
} ip6_t;
#endif

#if 0
typedef union {
	ip4_t v4;
	ip6_t v6;
} ip_t;
#else
typedef __uint128_t 		ip_t;
#endif


#ifndef ETH_ALEN
#define ETH_ALEN 			6
#endif

#define NS_TASK_SIZE 256

#endif
