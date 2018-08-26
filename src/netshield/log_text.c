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
#include <log_fldname.h>
#include <utils.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);


//////////////////////////////////////////////////////
//

extern nslog_conf_t g_nslog_conf;
extern char *nslog_state_name;

//////////////////////////////////////

static void txtout_expand_escapes(char* dest, const char* src) 
{
	char c;

	while ((c = *(src++))) {
		switch(c) {
#if 0
		case '=': 
			*(dest++) = '\\';
			*(dest++) = c;
			break;
#endif
		case '|': 
			*(dest++) = '\\';
			*(dest++) = c;
			break;
		default:
			*(dest++) = c;
		}
	}

	*dest = '\0';
}

static int32_t txtout_put_field(nslog_buf_t *outbuf, char *fldname, char *fmt, ...)
{
	int len;

	if (outbuf->len < 1) {
		return 0;
	}

	if (!(g_nslog_conf.flags & NSLOG_FLAG_TXTOUT_WITHOUT_KEY)) {
		len = strlen(fldname);

		if (len >= outbuf->len) {
			return 0;
		}

		memcpy(outbuf->buf, fldname, len);
		outbuf->buf += len;
		outbuf->len -= len;

		nslog_put_char(outbuf, '=');
	}

	va_list ap;
	va_start(ap, fmt);
	len = vsnprintf(outbuf->buf, outbuf->len, fmt, ap);
	va_start(ap, fmt);

	outbuf->buf += len;
	outbuf->len -= len;

	nslog_put_char(outbuf, g_nslog_conf.txtout_deli);
	*outbuf->buf = '\0';

	return outbuf->len;
}

static int32_t txtout_put_string_field(nslog_buf_t *outbuf, char *fldname, char *data, int escaped)
{
	int len;
	char *dest;

	if (outbuf->len < 1) {
		return 0;
	}

	if (escaped == 1) {
		len = strlen(data);
		dest = malloc(len);

		if (dest == NULL) {
			return -1;
		}
	}
	else {
		dest = data;
	}

	txtout_expand_escapes(dest, data);
	txtout_put_field(outbuf, fldname, "%s", dest);

	if (data != dest) {
		free(dest);
	}

	return outbuf->len;
}

static int32_t txtout_put_ipv4_field(nslog_buf_t *outbuf, char *fldname, ip_t ip)
{
	int len;
	uint32_t v4;

	if (outbuf->len < 1) {
		return 0;
	}

	v4 = (uint32_t)ip;

	txtout_put_field(outbuf, fldname, "%u.%u.%u.%u", IPH(v4));

	//nslog_output_ipv4(nslog_buf_t *outbuf, ip_t ip)

	return outbuf->len;
}

static int32_t txtout_common(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo)
{
#if 0
	char *fmt_no_key = "%s%c%d%c%d";
	char *fmt_with_key = "mod=%s%cfldcnt=%d%cver=%d";
	char *fmt;
	int len;

	if (g_nslog_conf.flags & NSLOG_FLAG_TXTOUT_WITHOUT_KEY) {
		fmt = fmt_no_key;
	}
	else {
		fmt = fmt_with_key;
	}

	len = snprintf(outbuf->buf, outbuf->len, fmt, 
				   name, 
				   g_nslog_conf.txtout_deli,
				   fldcount, 
				   g_nslog_conf.txtout_deli,
				   ver);

	outbuf->buf += len;
	outbuf->len -= len;

	return outbuf->len;
#else
	txtout_put_field(outbuf, FN_MODULE, "%s", modinfo->name);
	txtout_put_field(outbuf, FN_FLDCNT, "%d", modinfo->fldcount);
	txtout_put_field(outbuf, FN_VER, "%d", modinfo->ver);

	return outbuf->len;
#endif
}

static int32_t txtout_hdr(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_hdr_t *loghdr = (nslog_hdr_t*)logobj;

	char tbuf[64];
	int rc;

	nslog_convert_time_string(&loghdr->tv, tbuf, 64);

#if 0
	char *fmt_no_key = "|%s|%d|%d";
	char *fmt_with_key = "|time=%s|logid=%d|level=%d";
	char *fmt = NULL;

	rc = txtout_common(&outbuf, name, fldcount, ver);
	if (rc < 1) {
		return 0;
	}

	if (g_nslog_conf.flags & NSLOG_FLAG_TXTOUT_WITHOUT_KEY) {
		fmt = fmt_no_key;
	}
	else {
		fmt = fmt_with_key;
	}


	len = snprintf(outbuf.buf, outbuf.len, fmt, tbuf, loghdr->logid, loghdr->level);
	outbuf.len -= len;
#else
	rc = txtout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	txtout_put_field(outbuf, FN_TIME, "%s", tbuf);
	txtout_put_field(outbuf, FN_LOGID, "%d", loghdr->logid);
	txtout_put_field(outbuf, FN_LEVEL, "%d", loghdr->level);
#endif

	return outbuf->len;
}

static int32_t txtout_packet(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_pkt_t *logpkt = (nslog_pkt_t*)logobj;
	int rc;
	char *a;

	rc = txtout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	a = nslog_get_action_name(logpkt->act);

	txtout_put_field(outbuf, FN_ACT, "%s", a);
	txtout_put_field(outbuf, FN_INNIC, "%s", logpkt->innic);
	txtout_put_field(outbuf, FN_OUTNIC, "%s", logpkt->outnic);
	txtout_put_field(outbuf, FN_INZONE, "%s", logpkt->inzone);
	txtout_put_field(outbuf, FN_OUTZONE, "%s", logpkt->outzone);
	
	txtout_put_ipv4_field(outbuf, FN_SRCIP, logpkt->src);
	txtout_put_field(outbuf, FN_SPORT, "%u", logpkt->sport);
	txtout_put_ipv4_field(outbuf, FN_DSTIP, logpkt->dst);
	txtout_put_field(outbuf, FN_DPORT, "%u", logpkt->dport);

	desc_proto_t* d = ns_get_protocol_desc(logpkt->proto);
	txtout_put_field(outbuf, FN_PROTO, "%s", d->name);

	return outbuf->len;
}

static int32_t txtout_session(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_session_t *logses = (nslog_session_t*)logobj;
	int rc;

	rc = txtout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	txtout_put_field(outbuf, FN_SID, "%llu", logses->sid);
	char *s = nslog_get_state_name(logses->state);
	txtout_put_field(outbuf, FN_STATE, "%s", s);

	char tbuf[64];

	nslog_convert_time_string(&logses->opentime, tbuf, 64);
	txtout_put_field(outbuf, FN_OTIME, "%s", tbuf);

	nslog_convert_time_string(&logses->closetime, tbuf, 64);
	txtout_put_field(outbuf, FN_CTIME, "%s", tbuf);
	
	nslog_convert_duration(logses->duration, tbuf, 64);
	txtout_put_field(outbuf, FN_DUR, "%s", tbuf);

	txtout_put_field(outbuf, FN_FWRID, "%u", logses->fwruleid);
	txtout_put_field(outbuf, FN_PKT_CS, "%llu", logses->pktcnt[0].packets);
	txtout_put_field(outbuf, FN_BYT_CS, "%llu", logses->pktcnt[0].bytes);
	txtout_put_field(outbuf, FN_PKT_SC , "%llu", logses->pktcnt[1].packets);
	txtout_put_field(outbuf, FN_BYT_SC, "%llu", logses->pktcnt[1].bytes);

	return outbuf->len;
}

static int32_t txtout_nat(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_nat_t *lognat = (nslog_nat_t*)logobj;
	int rc;
	char *p;

	rc = txtout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	if (lognat->nattype & ACT_SNAT) {
		txtout_put_field(outbuf, FN_NATTYPE, "%s", "SNAT");
		txtout_put_ipv4_field(outbuf, FN_NAT_IP, lognat->ip[0]);
		txtout_put_field(outbuf, FN_NAT_PORT, "%u", lognat->port[0]);
		txtout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else if (lognat->nattype & ACT_DNAT) {
		txtout_put_field(outbuf, FN_NATTYPE, "%s", "DNAT");
		txtout_put_ipv4_field(outbuf, FN_NAT_IP, lognat->ip[1]);
		txtout_put_field(outbuf, FN_NAT_PORT, "%u", lognat->port[1]);
		txtout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else if (lognat->nattype & ACT_BNAT) {
		txtout_put_field(outbuf, FN_NATTYPE, "%s", "BNAT");
		txtout_put_ipv4_field(outbuf, FN_SNAT_IP, lognat->ip[0]);
		txtout_put_field(outbuf, FN_SNAT_PORT, "%u", lognat->port[0]);

		txtout_put_ipv4_field(outbuf, FN_DNAT_IP, lognat->ip[1]);
		txtout_put_field(outbuf, FN_DNAT_PORT, "%u", lognat->port[1]);
		txtout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else {
		return 0;
	}
		
	return outbuf->len;
}

static int32_t txtout_finalize(nslog_buf_t *outbuf)
{
	char *p = outbuf->buf - 1;

	if (*p == g_nslog_conf.txtout_deli) {
		outbuf->buf--;
		*outbuf->buf = '\0';
	}

	return 0;
}

nslog_output_handler_t g_txtout_handler = {
	.initialize = NULL,
	.finalize = txtout_finalize,

	.modinfo[NSLOG_MOD_HDR] = {	
		.name = {'H', 'D', 'R', '\0'},
		.fldcount = 2,
		.ver = 1,
		.logmod = NSLOG_MOD_HDR,
		.output = txtout_hdr
	},

	.modinfo[NSLOG_MOD_PKT] = {	
		.name = {'P', 'K', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_PKT,
		.output = txtout_packet
	},

	.modinfo[NSLOG_MOD_SESSION] = {	
		.name = {'S', 'E', 'S', 'S', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_SESSION,
		.output = txtout_session
	},

	.modinfo[NSLOG_MOD_NAT] = {	
		.name = {'N', 'A', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_NAT,
		.output = txtout_nat
	},
};

int32_t nslog_txtout_init(void)
{
	nslog_set_handler(NSLOG_FMT_TEXT, &g_txtout_handler);

	return 0;
}

