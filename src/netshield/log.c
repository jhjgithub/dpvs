#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <dpdk.h>
#include <syslog.h>

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
#include <utils.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);

nslog_output_handler_t *g_log_handler[NSLOG_FMT_MAX] = {
};

nslog_conf_t g_nslog_conf = {
	//.flags = NSLOG_FLAG_TXTOUT_WITHOUT_KEY,
	.flags = 0,
	.outfmt = NSLOG_FMT_TEXT,
	//.outfmt = NSLOG_FMT_JSON,
	.timefmt= "%Y-%m-%d %H:%M:%S",
	.txtout_deli = '|',
};

char *nslog_state_name[NSLOG_STAT_MAX] = {
	"OPEN",
	"CLOSE",
	"INFO",	
	"EXCEPTION",
};

///////////////////////////////////////

int32_t nslog_txtout_init(void);
int32_t nslog_jsonout_init(void);

//////////////////////////////////////////////////////
//

nslog_output_handler_t*
nslog_get_handler(uint32_t logfmt)
{
	if (logfmt >= NSLOG_FMT_MAX) {
		return NULL;
	}

	return g_log_handler[logfmt];
}

int32_t nslog_set_handler(uint32_t logfmt, nslog_output_handler_t *handler)
{
	if (logfmt >= NSLOG_FMT_MAX) {
		return -1;
	}

	g_log_handler[logfmt] = handler;

	return 0;
}


///////////////////////////////////////

int32_t nslog_print(int32_t id, int32_t lev, const char* fmt, ...)
{
	//int len;
	//char *p = NULL;
	char buf[1024];
	va_list ap;

	/* Determine required size */

	va_start(ap, fmt);
	vsnprintf(buf, 1024, fmt, ap);
	va_end(ap);

	printf("%s", buf);

	return 0;
}

void nslog_syslog(int loglevel, char *msg)
{
	syslog(LOG_INFO|LOG_DAEMON, "%s", msg);
}


int32_t nslog_put_char(nslog_buf_t *outbuf, char c)
{
	*outbuf->buf = c;

	outbuf->buf ++;
	outbuf->len --;

	return outbuf->len;
}

int32_t nslog_put_string(nslog_buf_t *outbuf, char *str, int len)
{
	memcpy(outbuf->buf, str, len);

	outbuf->buf += len;
	outbuf->len -= len;

	return outbuf->len;
}

int32_t nslog_output_time1(struct timeval *tv, char *tbuf, int tbuf_len)
{
	char usec[8];
	struct tm *tm;
	size_t len;
	int rc;

	//int millisec = loghdr->tv.tv_usec/1000;

	tm = localtime(&tv->tv_sec);
	len = strftime(tbuf, tbuf_len, g_nslog_conf.timefmt, tm);
	tbuf += len;

	rc = snprintf(usec, 8, ".%lu", tv->tv_usec);
	memcpy(tbuf, usec, rc);
	tbuf[rc] = '\0';
	
	//strcat(tbuf, usec);

	return 0;
}

int32_t nslog_convert_time_string(time_t *tv, char *tbuf, int tbuf_len)
{
	struct tm *tm;
	size_t len;
	int rc;

	//int millisec = loghdr->tv.tv_usec/1000;

	tm = localtime(tv);
	len = strftime(tbuf, tbuf_len, g_nslog_conf.timefmt, tm);
	tbuf += len;

	return 0;
}

int32_t nslog_convert_duration(time_t dur, char *tbuf, int tbuf_len)
{
	uint32_t day = dur / 86400;
	dur = dur % 86400;

	uint32_t hrs = dur / 3600;
	dur = dur % 3600;

	uint32_t mins = dur / 60;
	uint32_t sec = dur % 60;

	return snprintf(tbuf, tbuf_len, "%u:%u:%u:%u", day, hrs, mins, sec);
}

char *nslog_get_state_name(uint32_t state)
{
	if (state >= NSLOG_STAT_MAX) {
		return "Unknown";
	}

	return nslog_state_name[state];
}

char *nslog_get_action_name(uint64_t act)
{
	char *a;

	if (act & ACT_ALLOW) {
		a = "ALLOW";
	}
	else if (act & ACT_DROP) {
		a = "DROP";
	}
	else {
		a = "UNKNOWN";
	}

	return a;
}


int32_t nslog_output_ipv4(nslog_buf_t *outbuf, ip_t ip)
{
	int len = snprintf(outbuf->buf, outbuf->len, "%pI4", (uint32_t*)&ip);

	outbuf->buf ++;
	outbuf->len --;

	return outbuf->len;
}


/////////////////////////////

int32_t nslog_output_hdr(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *sess)
{
	if (handler == NULL || sess == NULL) {
		return -1;
	}

	nslog_hdr_t loghdr;
	memset(&loghdr, 0, sizeof(loghdr));

	//gettimeofday(&loghdr.tv, NULL);
	loghdr.tv = time(NULL);
	loghdr.level = 0;
	loghdr.logid = sess->mp_fw.policy ? sess->mp_fw.policy->logid:0;

	// call txtout_hdr(), jsonout_hdr()
	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_HDR];
	
	if (mod->output != NULL) {
		return mod->output(outbuf, mod, &loghdr);
	}

	return outbuf->len;
}

int32_t nslog_output_packet(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *sess)
{
	if (handler == NULL || sess == NULL) {
		return -1;
	}

	nslog_pkt_t logpkt;
	skey_t *key;

	key = &sess->skey;
	memset(&logpkt, 0, sizeof(logpkt));

	if (1|| key->inic == IFACE_IDX_MAX) {
		//logpkt.innic[0] = 0;
		strcpy(logpkt.innic, "none");
	}
	else {
		ns_get_nic_name_by_idx(key->inic, logpkt.innic, NSLOG_NIC_NAME_LEN);
	}

	if (1|| key->onic == IFACE_IDX_MAX) {
		//logpkt.outnic[0] = 0;
		strcpy(logpkt.outnic, "none");
	}
	else {
		ns_get_nic_name_by_idx(key->onic, logpkt.outnic, NSLOG_NIC_NAME_LEN);
	}

	logpkt.act = sess->action;
	strcpy(logpkt.inzone, "nozone");
	strcpy(logpkt.outzone, "nozone");
	logpkt.src = key->src;
	logpkt.dst = key->dst;
	logpkt.sport = key->sp;
	logpkt.dport = key->dp;
	logpkt.proto = key->proto;

	// call txtout_packet(), jsonout_packet()
	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_PKT];

	if (mod->output != NULL) {
		return mod->output(outbuf, mod, &logpkt);
	}

	return outbuf->len;
}

static void timeval_diff(timeval_t *result, timeval_t *start , timeval_t *stop)
{
	if ((stop->tv_usec - start->tv_usec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_usec = stop->tv_usec - start->tv_usec + 1000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_usec = stop->tv_usec - start->tv_usec;
	}
}

int32_t nslog_output_session(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *sess, uint32_t logstate)
{
	if (handler == NULL || sess == NULL) {
		return -1;
	}

	nslog_session_t logses;

	memset(&logses, 0, sizeof(logses));

	logses.sid = sess->sid;
	// XXX: test
	logses.sid = LLONG_MAX;
	logses.state = logstate;
	
	logses.opentime = sess->born_time;
	//gettimeofday(&logses.opentime, NULL);
	//logses.opentime.tv_sec --;
	//gettimeofday(&logses.closetime, NULL);
	logses.closetime = time(NULL);

	//timeval_diff(&logses.duration, &logses.opentime, &logses.closetime);
	logses.duration = logses.closetime - logses.opentime;

	logses.fwruleid = sess->mp_fw.policy ? sess->mp_fw.policy->rule_id:0;
	
	// FIXME:
	logses.traffic[0].packets = 100;
	logses.traffic[0].bytes = LLONG_MAX;

	logses.traffic[1].packets = 200;
	logses.traffic[1].bytes = LLONG_MAX-9999;

	// call txtout_session()
	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_SESSION];

	if (mod->output != NULL) {
		return mod->output(outbuf, mod, &logses);
	}

	return outbuf->len;
}

int32_t nslog_output_nat(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *sess, uint64_t nattype)
{
	if (handler == NULL || sess == NULL) {
		return -1;
	}

	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_NAT];
	if (mod->output == NULL) {
		return outbuf->len;
	}

	nslog_nat_t lognat;
	memset(&lognat, 0, sizeof(lognat));

	lognat.nattype = nattype;
	memcpy(&lognat.ip, &sess->natinfo.ip[0], sizeof(ip_t) * 2);
	memcpy(&lognat.port, &sess->natinfo.port[0], sizeof(uint16_t) * 2);
	lognat.natruleid = sess->mp_nat.policy ? sess->mp_nat.policy->rule_id:0;

	// call txtout_nat()
	mod->output(outbuf, mod, &lognat);

	return outbuf->len;
}

/////////////////////////////////////////////////


int32_t nslog_session(session_t *sess, uint32_t logstate)
{
	nslog_buf_t outbuf;
	char buf[1024];
	int rc;
	uint32_t outfmt = g_nslog_conf.outfmt;
	
	outbuf.buf = buf;
	outbuf.len = 1024;

	nslog_output_handler_t *h = nslog_get_handler(outfmt);
	if (h == NULL) {
		printf("Cannot find handler: %d \n", outfmt);
		goto ERR;
	}

	if (h->initialize && (rc=h->initialize(&outbuf)) < 0) {
		goto ERR;
	}

	rc = nslog_output_hdr(&outbuf, h, sess);
	if (rc < 1) {
		goto ERR;
	}

	rc = nslog_output_packet(&outbuf, h, sess);
	if (rc < 1) {
		goto ERR;
	}

	rc = nslog_output_session(&outbuf, h, sess, logstate);
	if (rc < 1) {
		goto ERR;
	}

	sess->action = ACT_SNAT;

	uint64_t nattype = sess->action & ACT_NAT;
	if (nattype) {
		rc = nslog_output_nat(&outbuf, h, sess, nattype);
		if (rc < 1) {
			goto ERR;
		}
	}

	if (h->finalize && (rc=h->finalize(&outbuf)) < 0) {
		goto ERR;
	}

	nslog_syslog(LOG_SYSLOG, buf);

	return 0;
ERR:

	printf("error : %d \n", rc);

	return -1;
}


int32_t nslog_init(void)
{
	openlog("NetShield", LOG_PID | LOG_NDELAY, 0);

	nslog_txtout_init();
	nslog_jsonout_init();


	session_t sess;

	memset(&sess, 0, sizeof(sess));

	nslog_session(&sess, NSLOG_STAT_OPEN);

	return 0;
}


void nslog_clean(void)
{
	closelog();

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

	jsonout_put_mod_start(outbuf, modinfo->name);

	rc = jsonout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}
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
