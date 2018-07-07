#ifndef __DBG_H_
#define __DBG_H_

// short file name
#define __FILENAME__ \
	 (strrchr(__FILE__,'/') \
	  ? strrchr(__FILE__,'/')+1 \
	  : __FILE__ \
	  )

#ifdef DEBUG

// RTE_LOG
#define dpvs_log(l, t, fmt, ...) \
	rte_log(RTE_LOG_ ## l, RTE_LOGTYPE_USER1,\
	# t ": %s(%d): " fmt, __FILENAME__, __LINE__, ## __VA_ARGS__)

#else

#define dpvs_log(l, t, ...) \
	 rte_log(RTE_LOG_ ## l,					\
		 RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#endif

struct rte_mbuf;
void _dump_packet(const char *file, int line, struct rte_mbuf* pkt);

#define dump_packet(pkt) \
	_dump_packet(__FILENAME__, __LINE__, pkt)



#endif
