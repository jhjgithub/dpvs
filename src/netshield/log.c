#include <stdio.h>
#include <stdint.h>
	 #include <stdarg.h>
#include <dpdk.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <session.h>
#include <smgr.h>
#include <action.h>
#include <pmgr.h>
#include <options.h>
#include <cmds.h>
#include <ioctl_session.h>
#include <tcp_state.h>
#include <ioctl.h>
#include <log.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);

//static rte_spinlock_t nslog_module_lock; /* to see if rwlock is better */
//static const struct inet_protocol *inet_prots[INET_MAX_PROTS];

nslog_output_handler_t g_log_handler[NSLOG_FMT_MAX][NSLOG_MOD_MAX] = {

	//[0][0] = {.fldcount=0, .ver=1, .logmod=1, .output=NULL},
	
	
};

///////////////////////////////////////

int32_t nslog_init_text_output(void);

//////////////////////////////////////////////////////
//

nslog_output_handler_t*
nslog_get_handler(uint32_t logfmt)
{
	if (logfmt >= NSLOG_FMT_MAX) {
		return NULL;
	}

	return &g_log_handler[logfmt][0];
}

int32_t nslog_set_handler(uint32_t logfmt, nslog_output_handler_t *handlers, uint32_t cnt)
{
	if (logfmt >= NSLOG_FMT_MAX || cnt < 1) {
		return -1;
	}

	memcpy(&g_log_handler[logfmt][0], handlers, sizeof(nslog_output_handler_t) * cnt);
}


///////////////////////////////////////

int32_t nslog_print(int32_t id, int32_t lev, const char* fmt, ...)
{
	int len;
	char buf[1024];
	char *p = NULL;
	va_list ap;

	/* Determine required size */

	va_start(ap, fmt);
	len = vsnprintf(buf, 1024, fmt, ap);
	va_end(ap);

	printf("%s", buf);

	return 0;
}

int32_t nslog_output_hdr(nslog_output_handler_t *handler, session_t *si)
{
	if (handler == NULL || handler->output == NULL || 
		si == NULL) {
		return -1;
	}

	nslog_hdr_t hdr;

	hdr.tm = time(NULL);
	hdr.level = 1;
	hdr.logid = si->mp_fw.policy ? si->mp_fw.policy->logid:0;

	return handler->output(handler->name,
						  handler->fldcount, 
						  handler->ver,
						  &hdr);
}

int32_t nslog_output_packet(nslog_output_handler_t *handler, session_t *si)
{

	return 0;
}

int32_t nslog_output_session(nslog_output_handler_t *handler, session_t *si)
{

	return 0;
}

int32_t nslog_output_nat(nslog_output_handler_t *handler, session_t *si)
{

	return 0;
}


int32_t nslog_session(session_t *si, uint32_t logtype)
{
	nslog_hdr_t 	loghdr;
	nslog_pkt_t 	logpkt;
	nslog_session_t logses;
	nslog_nat_t 	lognat;

	struct list_head inet_hooks[INET_HOOK_NUMHOOKS];

}


int32_t nslog_init(void)
{

	return 0;
}


void nslog_clean(void)
{


}


#if 0
Modularized Logging Format
2081/8/13

참고:
https://ossec-docs.readthedocs.io/en/latest/log_samples/

1. 특징

-. human readable
-. structed
-. key value style
-. flexiable
-. 버젼 변경에 따른 형식 제공

2. 기능
-. 모든 버전에 대한 출력 schema를 조회 가능
-. 출력 형태 지정
--. text1
--. key:value 형식
--. 구분자: ","
--. 구분자 이스케이프 처리
--. text2
--. value 형식
--. 구분자: ","
--. 구분자 이스케이프 처리

--. json 형식


log = header | module+

header:
-. time
-. ver
-. level
-. logid

firewall module: fw
-. name
-. fldcount
-. version
-. action
-. innic
-. outnic
-. src ip:port
-. dst ip:port
-. proto
-. fwrule id
-. packets
-. bytes
-. duration
-. srczone
-. dstzone
-. severity


nat module: nat
-. name
-. fldcount
-. version
-. nated ip/port

3. logging
-. 로그 오브젝트를 struct로 정의 한다.
-. log output 모듈에서 type에 따라 output을 변환 한다: text, json, xml, html


4. juniper log format
time, filter, action, nic_name, protocol, pkt_len, src, dst

Time      Filter    Action Interface     Protocol  Src Addr      Dest Addr       
13:10:12  pfe       D      rlsq0.902     ICMP      192.0.2.2   192.0.2.1                   
13:10:11  pfe       D      rlsq0.902     ICMP      192.0.2.2   192.0.2.1 
Time of Log: 2004-10-13 10:37:17 PDT, Filter: f, Filter action: accept, Name of interface: fxp0.0Name of protocol: TCP,Packet Length: 50824, Source address: 203.0.113.108:829, Destination address: 192.168.70.66:513



#endif
