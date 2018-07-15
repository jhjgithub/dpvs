#ifndef __DBG_H_
#define __DBG_H_

#include <rte_log.h>

// short file name
#define __FILENAME__ \
	 (strrchr(__FILE__,'/') ? strrchr(__FILE__,'/')+1 : __FILE__ )

#if defined(DEBUG) && defined(CONFIG_DPVS_ENABLE_LOCAL_DEBUG)
#undef RTE_LOG

// redefine RTE_LOG()
#define RTE_LOG(l, t, fmt, ...) \
	rte_log(RTE_LOG_ ## l,  RTE_LOGTYPE_ ## t,\
	# t ": %s(%d): " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__)

#endif

#if 0

#define ns_log(l, t, fmt, ...) \
	rte_log(RTE_LOG_ ## l, RTE_LOGTYPE_USER1,\
	# t ": %s(%d): " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__)

#define dbg(l, fmt, ...) \
	rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1,\
	"%s(%d): " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__)

#define ns_log(l, t, ...) \
	 rte_log(RTE_LOG_ ## l,					\
		 RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)
#endif

struct rte_mbuf;
void _dump_packet(const char *file, int line, struct rte_mbuf* pkt);

#define dump_packet(pkt) \
	_dump_packet(__FILENAME__, __LINE__, pkt)


//////////////////////////////////////////////////////////////////
// debug messages 
// MY_DBG_NAME will be defined in Makefile

#define NS_FUNC_FMT 				"%s(%d): "
#define NS_FUNC_PARAM 			__FUNCTION__,__LINE__

#ifdef CONFIG_NS_DEBUG

extern int32_t dbgctl_compare_level(int32_t file_level, char* func, int32_t f_level);
extern void _dump_hex(const uint8_t *data, int len);
struct ipv4_hdr;
extern void dump_pkt(char* func, int32_t line, struct ipv4_hdr *iph, uint8_t inic);

#define ns_err(fmt, args...) 	rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "NetShield ERR: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)
#define ns_warn(fmt, args...) 	rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_USER1, "NetShield WARN: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)
#define ns_log(fmt, args...)	rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "NetShield INFO: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)

#define OUT_MSG(fmt, args...) 	rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_USER1, "NetShield: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)

#define DBG_NAME(n)				dbg_level_ ## n
#define CMP_LEV(file_l, func_l) dbgctl_compare_level(file_l, (char*)__FUNCTION__, func_l)
#define _DECL_DBG_LEVEL(n, l) 	int32_t DBG_NAME(n) = l
#define DECLARE_DBG_LEVEL(l)	_DECL_DBG_LEVEL(MY_DBG_NAME, l)

#define _DBG(n, l,fmt, args...)	if (CMP_LEV(DBG_NAME(n), l)) {OUT_MSG(fmt, ##args);}
#define DBG(l,fmt, args...) 	_DBG(MY_DBG_NAME, l, fmt, ##args)
#define dbg(l,fmt, args...) 	_DBG(MY_DBG_NAME, l, fmt, ##args)

#define _DUMP_PKT(n,l,iph,inic)	if (CMP_LEV(DBG_NAME(n),l)) {dump_pkt((char*)__FUNCTION__, __LINE__, iph, inic);}
#define DUMP_PKT(l,iph,inic)	_DUMP_PKT(MY_DBG_NAME, l, iph, inic)
#define PRINT_SZ(s) 			OUT_MSG("%s=%d", __STR(s), (int32_t)sizeof(s))
#define _DBG_CODE(n, l, code)  	if (CMP_LEV(DBG_NAME(n),l)) { code;}
#define DBG_CODE(l, code) 		_DBG_CODE(MY_DBG_NAME, l, code)
#define DBG_CODE_START(l) 		DBG_CODE(l,

#define	_DBGKEY(n, l, msg, _kkk) 	\
	if (CMP_LEV(DBG_NAME(n),l)) {	\
		skey_t* _k = _kkk;  			\
		uint32_t _ss = (uint32_t)_k->src; \
		uint32_t _dd = (uint32_t)_k->dst; \
		OUT_MSG(__STR(msg) SKEY_FMT, IPH(_ss), _k->sp, \
		IPH(_dd), _k->dp, _k->proto); \
	}
#define DBGKEY(l, msg, _kk) 	_DBGKEY(MY_DBG_NAME, l, msg, _kk)

#define	_DBGKEY6(n, l, msg, _kkk) 	\
	if (CMP_LEV(DBG_NAME(n),l)) {	\
		skey_t* _k = _kkk; ip6_t _s, _d;\
		_s = _k->src6.v6; \
		_d = _k->dst6.v6; \
		OUT_MSG(__STR(msg) SKEY_FMT6, &_s, _k->sp, &_d, _k->dp, _k->proto); \
	}
#define DBGKEY6(l, msg, _kk) 	_DBGKEY6(MY_DBG_NAME, l, msg, _kk)

#define _DBGKEYH(n, l, msg, k) 		\
	if (CMP_LEV(DBG_NAME(n),l)){	\
		uint32_t* _kk = (uint32_t*)k; \
		OUT_MSG(__STR(msg) " Hex: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x", \
		_kk[0], _kk[1], _kk[2], _kk[3], _kk[4]); \
	}
#define DBGKEYH(l, msg, k) 		_DBGKEYH(MY_DBG_NAME, l, msg, k)

#if 0
#define _DBG_CALLER(n, l,msg) 	\
	if (CMP_LEV(DBG_NAME(n),l)){		\
		char __buf[128]; 		\
		sprintf(__buf, \
		"NetShield: " NS_FUNC_FMT "Caller: %%s: %s \n", \
		NS_FUNC_PARAM, msg); \
		__print_symbol_simple(__buf, (unsigned long) __builtin_return_address(0)) \
	}
#else
#define _DBG_CALLER(n, l,msg) 	\
	if (CMP_LEV(DBG_NAME(n),l)){		\
		char __buf[128]; 		\
		sprintf(__buf, \
		"NetShield: " NS_FUNC_FMT "%s \n", \
		NS_FUNC_PARAM, msg); \
		printf("%s", __buf); \
	}
#endif

#define DBG_CALLER(l) 		_DBG_CALLER(MY_DBG_NAME, l, "")
#define ENT_FUNC(l)			_DBG_CALLER(MY_DBG_NAME, l, "Enter")
#define	FUNC_TEST_MSG(l,fmt, args...)	_DBG(MY_DBG_NAME, l, fmt, ##args)
#define dbg_dump_hex(data, len) _dump_hex(data, len)



#else

#define DECLARE_DBG_LEVEL(x)
#define OUT_MSG(fmt, args... )
#define DBG(l,fmt, args...)
#define dbg(l,fmt, args...)
#define	FUNC_TEST_MSG(l,fmt, args...)
#define DUMP_PKT(l,iph,inic)	
#define PRINT_SZ(s)
#define DBG_CALLER(l)
#define ENT_FUNC(l)
#define DBGKEYH(l, msg, k)
#define DBGKEY(l, msg, k)
#define DBGKEY6(l, msg, _kk)
#define _DBG_CODE(n, l, code) 
#define DBG_CODE(l, code) 		_DBG_CODE(MY_DBG_NAME, l, code)
#define DBG_CODE_START(l) 		DBG_CODE(l,
#define ns_err(fmt, args...) 	ns_log_print(-1, LOG_LEV_ERR, "NetShield ERR: " fmt , ##args)
#define ns_warn(fmt, args...) 	ns_log_print(-1, LOG_LEV_WARN, "NetShield WARN: " fmt , ##args)
#define ns_log(fmt, args...)	ns_log_print(-1, LOG_LEV_INFO, "NetShield INFO: " fmt , ##args)
#define dbg_dump_hex(data, len) do { } while (0)

#endif // CONFIG_NS_DEBUG





#endif














