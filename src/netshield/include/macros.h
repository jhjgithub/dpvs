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

#define PROTO(nstask) 			(nstask)->key.proto




#endif
