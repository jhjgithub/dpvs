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

int32_t nslog_output_hdr(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *ses)
{
	if (handler == NULL || ses == NULL) {
		return -1;
	}

	nslog_hdr_t loghdr;
	memset(&loghdr, 0, sizeof(loghdr));

	//gettimeofday(&loghdr.tv, NULL);
	loghdr.tv = time(NULL);
	loghdr.level = 0;
	loghdr.logid = ses->mp_fw.policy ? ses->mp_fw.policy->logid:0;

	// call txtout_hdr(), jsonout_hdr()
	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_HDR];
	
	if (mod->output != NULL) {
		return mod->output(outbuf, mod, &loghdr);
	}

	return outbuf->len;
}

int32_t nslog_output_packet(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *ses)
{
	if (handler == NULL || ses == NULL) {
		return -1;
	}

	nslog_pkt_t logpkt;
	skey_t *key;

	key = &ses->skey;
	memset(&logpkt, 0, sizeof(logpkt));

	if (key->inic == IFACE_IDX_MAX) {
		strcpy(logpkt.innic, "none");
	}
	else {
		ns_get_nic_name_by_idx(key->inic, logpkt.innic, NSLOG_NIC_NAME_LEN);
	}

	if (key->onic == IFACE_IDX_MAX) {
		strcpy(logpkt.outnic, "none");
	}
	else {
		ns_get_nic_name_by_idx(key->onic, logpkt.outnic, NSLOG_NIC_NAME_LEN);
	}

	logpkt.act = ses->action;
	strcpy(logpkt.inzone, "none");
	strcpy(logpkt.outzone, "none");
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
	} 
	else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_usec = stop->tv_usec - start->tv_usec;
	}
}

int32_t nslog_output_session(nslog_buf_t *outbuf, nslog_output_handler_t *handler, 
							 session_t *ses, uint32_t logstate)
{
	if (handler == NULL || ses == NULL) {
		return -1;
	}

	nslog_session_t logses;

	memset(&logses, 0, sizeof(logses));

	logses.sid = ses->sid;
	// XXX: test
	logses.sid = LLONG_MAX;
	logses.state = logstate;
	
	logses.opentime = ses->born_time + GET_OPT_VALUE(start_time) - BASE_START_TIME;
	//gettimeofday(&logses.opentime, NULL);
	//logses.opentime.tv_sec --;

	struct timeval tv;
	gettimeofday(&tv, NULL);
	logses.closetime = tv.tv_sec;

	//timeval_diff(&logses.duration, &logses.opentime, &logses.closetime);
	logses.duration = logses.closetime - logses.opentime;

	logses.fwruleid = ses->mp_fw.policy ? ses->mp_fw.policy->rule_id:0;
	
	memcpy(&logses.pktcnt, ses->pktcnt, sizeof(pkt_cnt_t) * 3);

	// call txtout_session()
	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_SESSION];

	if (mod->output != NULL) {
		return mod->output(outbuf, mod, &logses);
	}

	return outbuf->len;
}

int32_t nslog_output_nat(nslog_buf_t *outbuf, nslog_output_handler_t *handler, session_t *ses, uint64_t nattype)
{
	if (handler == NULL || ses == NULL) {
		return -1;
	}

	nslog_modinfo_t *mod = &handler->modinfo[NSLOG_MOD_NAT];
	if (mod->output == NULL) {
		return outbuf->len;
	}

	nslog_nat_t lognat;
	memset(&lognat, 0, sizeof(lognat));

	lognat.nattype = nattype;
	memcpy(&lognat.ip, &ses->natinfo.ip[0], sizeof(ip_t) * 2);
	memcpy(&lognat.port, &ses->natinfo.port[0], sizeof(uint16_t) * 2);
	lognat.natruleid = ses->mp_nat.policy ? ses->mp_nat.policy->rule_id:0;

	// call txtout_nat()
	mod->output(outbuf, mod, &lognat);

	return outbuf->len;
}

/////////////////////////////////////////////////

int32_t nslog_syslog(uint32_t level, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, 1024, fmt, ap);
	va_end(ap);

	// dbg
	//printf("%s", buf);
	syslog(level|NSLOG_TYPE_OTHERS, "%s", buf);

	return 0;
}

int32_t nslog_session(session_t *ses, uint32_t logstate)
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

	rc = nslog_output_hdr(&outbuf, h, ses);
	if (rc < 1) {
		goto ERR;
	}

	rc = nslog_output_packet(&outbuf, h, ses);
	if (rc < 1) {
		goto ERR;
	}

	rc = nslog_output_session(&outbuf, h, ses, logstate);
	if (rc < 1) {
		goto ERR;
	}

	uint64_t nattype = ses->action & ACT_NAT;
	if (nattype) {
		rc = nslog_output_nat(&outbuf, h, ses, nattype);
		if (rc < 1) {
			goto ERR;
		}
	}

	if (h->finalize && (rc=h->finalize(&outbuf)) < 0) {
		goto ERR;
	}

	syslog(LOG_INFO|NSLOG_TYPE_SESSION, "%s", buf);

	return 0;
ERR:

	return -1;
}

int32_t nslog_init(void)
{
	openlog("NetShield", LOG_PID | LOG_NDELAY, 0);

	nslog_txtout_init();
	nslog_jsonout_init();

	return 0;
}


void nslog_clean(void)
{
	closelog();

}

///////////////////////////////////

static nscmd_module_t mod_log = {
	CMD_ITEM(log, LOG, NULL, nslog_init, nslog_clean, NULL)
};

static void __attribute__ ((constructor)) nslog_register(void)
{
	nscmd_register(NSCMD_IDX(log), &mod_log);
}


