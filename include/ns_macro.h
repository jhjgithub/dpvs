#ifndef __NS_MACRO_H_
#define __NS_MACRO_H_


#define __STR(x) 					#x
#define sizeofa( x ) 				(sizeof(x) / sizeof(x[0]))
#define sizeofm(TYPE, MEMBER) 		sizeof(((TYPE *) 0)->MEMBER)
#define lengthof(TYPE, MEMBER) 		(offsetof(TYPE, MEMBER) + sizeofm(TYPE, MEMBER))
#define MAC(addr) \
	(uint8_t)(((unsigned char *)addr)[0]), \
	(uint8_t)(((unsigned char *)addr)[1]), \
	(uint8_t)(((unsigned char *)addr)[2]), \
	(uint8_t)(((unsigned char *)addr)[3]), \
	(uint8_t)(((unsigned char *)addr)[4]), \
	(uint8_t)(((unsigned char *)addr)[5])
#define IPN(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#if defined(__LITTLE_ENDIAN)
#define IPH(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define IPH(addr) 	IPN(addr)
#else
#error Not defined Endian Mode !
#endif

#ifndef MAC_FMT
#define MAC_FMT 				"%02X:%02X:%02X:%02X:%02X:%02X"
#endif
#define IP_FMT 					"%u.%u.%u.%u"
#define SKEY_FMT				":" IP_FMT ":%d->" IP_FMT ":%d(%d)"
#define IP6_FMT 				"%pI6c"
#define SKEY_FMT6				"[" IP6_FMT "-%d->" IP6_FMT "-%d(%d)]"

#define ISREQ(u) 				(!!(u->flags & TASK_FLAG_REQ))
#define ISRES(u) 				( !(u->flags & TASK_FLAG_REQ))
#define bzero(a, b) 			memset((a), 0, (b))

#define PREFETCH(a,rw,l) 		__builtin_prefetch(a, rw, l)
#define ASSERT_COMPILE(e)		BUILD_BUG_ON(e)
#define IS_DST_LOCAL(_dst) 		(((struct rtable*)_dst)->rt_flags & RTCF_LOCAL)
#define IS_INCLUDE_IP(ip,mask,src) ((ip&mask) == (src&mask))
#define IS_IPV6(__k)			(((__k)->flags & SKF_IPV6)?FUNC_FLAG_IPV6:0)
#define SKEY(_k)				IPH((_k)->src4), (_k)->sp, IPH((_k)->dst4), (_k)->dp, (_k)->proto
#define MAKE_BIT(v)				(!!(v))
#define IS_LOCALOUT(u)			(u->flags & NST_FLAG_HOOK_LOCAL_OUT)
#define IS_DST_VPN(dst)			((dst)->obsolete == -1)

#if 0
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
#define	ns_rw_trylock_irq(l) spin_trylock_bh(l)
#define	ns_rw_lock_irq(l) 	spin_lock_bh(l);
#define	ns_rw_unlock_irq(l) spin_unlock_bh(l);
#define	ns_rw_lock(l)		spin_lock(l);
#define	ns_rw_unlock(l)		spin_unlock(l);

// 데이터를 읽기만 하는 경우 사용
#define	ns_rd_lock_irq()	rcu_read_lock_bh();
#define	ns_rd_unlock_irq() 	rcu_read_unlock_bh();
#define	ns_rd_lock()		rcu_read_lock();
#define	ns_rd_unlock()		rcu_read_unlock();

#define ns_init_lock(l) 	spin_lock_init(l)
///////////////////////////////////////////////////////////

#define IS_SYN_ONLY(t) 		(t->syn && !(t->rst|t->fin|t->ack))
#define IS_ACK_ONLY(t) 		(t->ack && !(t->rst|t->fin|t->syn))
#define IS_SYN_ACK(t) 		(t->syn && t->ack && !(t->rst|t->fin))

#define KER_VER_LT(maj,mid,min) (LINUX_VERSION_CODE <  KERNEL_VERSION(maj,mid,min))
#define KER_VER_LE(maj,mid,min) (LINUX_VERSION_CODE <= KERNEL_VERSION(maj,mid,min))
#define KER_VER_GT(maj,mid,min) (LINUX_VERSION_CODE > KERNEL_VERSION(maj,mid,min))
#endif

#define CMP_MAC_HI(mac1, mac2) 	(*(uint32_t*)mac1 == *(uint32_t*)mac2)
#define CMP_MAC_LO(mac1, mac2) 	(*(uint16_t*)&mac1[4] == *(uint16_t*)&mac2[4])
#define CMP_MAC(mac1, mac2) (CMP_MAC_HI(mac1, mac2) && CMP_MAC_LO(mac1, mac2))
#define CTL_TAB_ITEM(n, d, l, m, c, h) {.procname=n, .data=d, .maxlen=l, .mode=m, .child=c, .proc_handler=h}

#define ns_copy_ipv6(d,s) 		memcpy((d), (s), 16)
#define PROTO(nstask) 			(nstask)->key.proto

#if 0
#define wsnprintf(buf, buflen, maxlen, fmt, args...) \
	do { \
		int32_t __len; \
		__len = snprintf((*(buf)), maxlen-(*(buflen)), fmt, ##args); \
		(*(buf)) += __len; (*(buflen)) += __len; \
	} while(0);
#endif

//#define ns_bug(fmt, args...)	ns_log_print(-1, LOG_LEV_ERR, "NetShield BUG: " NS_FUNC_FMT fmt, NS_FUNC_PARAM, ##args)


#endif
