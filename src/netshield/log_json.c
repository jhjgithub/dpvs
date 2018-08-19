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

#define jsonout_put_field(b, fldname, fmt, ...)       _jsonout_put_field(b, "%s:"fmt",",   fldname, __VA_ARGS__)
#define jsonout_put_last_field(b, fldname, fmt, ...)  _jsonout_put_field(b, "%s:"fmt "},", fldname, __VA_ARGS__)

//////////////////////////////////////////////////////
//

extern nslog_conf_t g_nslog_conf;

//////////////////////////////////////

static void jsonout_expand_escapes(char* dest, const char* src) 
{
	char c;

	while ((c = *(src++))) {
		switch(c) {
		case '"': 
			*(dest++) = '\\';
			*(dest++) = c;
			break;
#if 0
		case ',': 
			*(dest++) = '\\';
			*(dest++) = c;
			break;
#endif
		default:
			*(dest++) = c;
		}
	}

	*dest = '\0';
}

static int32_t jsonout_put_string_field(nslog_buf_t *outbuf, char *fldname, char *data, int escaped)
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

		jsonout_expand_escapes(dest, data);
	}
	else {
		dest = data;
	}

	len = snprintf(outbuf->buf, outbuf->len, "%s:\"%s\"", fldname, dest);

	outbuf->buf += len;
	outbuf->len -= len;

	if (data != dest) {
		free(dest);
	}

	return outbuf->len;
}

static int32_t _jsonout_put_field(nslog_buf_t *outbuf, char *fmt, ...)
{
	int len;

	if (outbuf->len < 1) {
		return 0;
	}

	va_list ap;
	va_start(ap, fmt);
	len = vsnprintf(outbuf->buf, outbuf->len, fmt, ap);
	va_start(ap, fmt);

	outbuf->buf += len;
	outbuf->len -= len;

	return outbuf->len;
}

static int32_t jsonout_put_mod_start(nslog_buf_t *outbuf, char *name) 
{
	int len;

	len = snprintf(outbuf->buf, outbuf->len, "%s:{", name);
	outbuf->buf += len;
	outbuf->len -= len;

	return outbuf->len;
}

static int32_t jsonout_put_mod_close(nslog_buf_t *outbuf)
{
	nslog_put_char(outbuf, '}');
	//nslog_put_char(outbuf, ',');

	return outbuf->len;
}

static int32_t jsonout_common(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo)
{
	jsonout_put_field(outbuf, FN_FLDCNT, "%d", modinfo->fldcount);
	jsonout_put_field(outbuf, FN_VER,"%d", modinfo->ver);

	return outbuf->len;
}

static int32_t jsonout_put_ipv4_field(nslog_buf_t *outbuf, char *fldname, ip_t ip)
{
	int len;
	uint32_t v4;

	if (outbuf->len < 1) {
		return 0;
	}

	v4 = (uint32_t)ip;

	jsonout_put_field(outbuf, fldname, "%u.%u.%u.%u", IPH(v4));

	return outbuf->len;
}

static int32_t jsonout_hdr(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_hdr_t *loghdr = (nslog_hdr_t*)logobj;

	char tbuf[64];
	int rc;

	jsonout_put_mod_start(outbuf, modinfo->name);

	nslog_convert_time_string(&loghdr->tv, tbuf, 64);

	rc = jsonout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	jsonout_put_field(outbuf, FN_TIME, "\"%s\"", tbuf);
	jsonout_put_field(outbuf, FN_LOGID, "%u", loghdr->logid);
	jsonout_put_last_field(outbuf, FN_LEVEL, "%u", loghdr->level);

	return outbuf->len;
}

static int32_t jsonout_packet(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_pkt_t *logpkt = (nslog_pkt_t*)logobj;
	int rc;

	jsonout_put_mod_start(outbuf, modinfo->name);

	rc = jsonout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	char *a;
	a = nslog_get_action_name(logpkt->act);

	jsonout_put_field(outbuf, FN_ACT, "%s", a);

	jsonout_put_field(outbuf, FN_INNIC, "%s", logpkt->innic);
	jsonout_put_field(outbuf, FN_OUTNIC, "%s", logpkt->outnic);
	
	jsonout_put_field(outbuf, FN_INZONE, "%s", logpkt->inzone);
	jsonout_put_field(outbuf, FN_OUTZONE, "%s", logpkt->outzone);

	jsonout_put_ipv4_field(outbuf, FN_SRCIP, logpkt->src);
	jsonout_put_field(outbuf, FN_SPORT, "%u", logpkt->sport);
	jsonout_put_ipv4_field(outbuf, FN_DSTIP, logpkt->dst);
	jsonout_put_field(outbuf, FN_DPORT, "%u", logpkt->dport);

	desc_proto_t* d = ns_get_protocol_desc(logpkt->proto);
	jsonout_put_last_field(outbuf, FN_PROTO, "%s", d->name);

	return outbuf->len;
}

static int32_t jsonout_session(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_session_t *logses = (nslog_session_t*)logobj;
	int rc;

	jsonout_put_mod_start(outbuf, modinfo->name);

	rc = jsonout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	jsonout_put_field(outbuf, FN_SID, "%llu", logses->sid);
	char *s = nslog_get_state_name(logses->state);
	jsonout_put_field(outbuf, FN_STATE, "%s", s);

	char tbuf[64];

	nslog_convert_time_string(&logses->opentime, tbuf, 64);
	jsonout_put_field(outbuf, FN_OTIME, "\"%s\"", tbuf);

	nslog_convert_time_string(&logses->closetime, tbuf, 64);
	jsonout_put_field(outbuf, FN_CTIME, "\"%s\"", tbuf);
	
	nslog_convert_duration(logses->duration, tbuf, 64);
	jsonout_put_field(outbuf, FN_DUR, "\"%s\"", tbuf);

	jsonout_put_field(outbuf, FN_FWRID, "%u", logses->fwruleid);
	jsonout_put_field(outbuf, FN_PKT_CS, "%llu", logses->traffic[NSLOG_DIR_CS].packets);
	jsonout_put_field(outbuf, FN_BYT_CS, "%llu", logses->traffic[NSLOG_DIR_CS].bytes);
	jsonout_put_field(outbuf, FN_PKT_SC, "%llu", logses->traffic[NSLOG_DIR_SC].packets);
	jsonout_put_last_field(outbuf, FN_BYT_SC, "%llu", logses->traffic[NSLOG_DIR_SC].bytes);

	return outbuf->len;
}

static int32_t jsonout_nat(nslog_buf_t *outbuf, nslog_modinfo_t *modinfo, void *logobj)
{
	nslog_nat_t *lognat = (nslog_nat_t*)logobj;
	int rc;
	char *p;

	jsonout_put_mod_start(outbuf, modinfo->name);

	rc = jsonout_common(outbuf, modinfo);
	if (rc < 1) {
		return 0;
	}

	if (lognat->nattype & ACT_SNAT) {
		jsonout_put_field(outbuf, FN_NATTYPE, "%s", "SNAT");
		jsonout_put_ipv4_field(outbuf, FN_NAT_IP, lognat->ip[0]);
		jsonout_put_field(outbuf, FN_NAT_PORT, "%u", lognat->port[0]);
		jsonout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else if (lognat->nattype & ACT_DNAT) {
		jsonout_put_field(outbuf, FN_NATTYPE, "%s", "DNAT");
		jsonout_put_ipv4_field(outbuf, FN_NAT_IP, lognat->ip[1]);
		jsonout_put_field(outbuf, FN_NAT_PORT, "%u", lognat->port[1]);
		jsonout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else if (lognat->nattype & ACT_BNAT) {
		jsonout_put_field(outbuf, FN_NATTYPE, "%s", "BNAT");
		jsonout_put_ipv4_field(outbuf, FN_SNAT_IP, lognat->ip[0]);
		jsonout_put_field(outbuf, FN_SNAT_PORT, "%u", lognat->port[0]);

		jsonout_put_ipv4_field(outbuf, FN_DNAT_IP, lognat->ip[1]);
		jsonout_put_field(outbuf, FN_DNAT_PORT, "%u", lognat->port[1]);
		jsonout_put_field(outbuf, FN_NATRID, "%u", lognat->natruleid);
	}
	else {
		return 0;
	}

	return outbuf->len;
}

static int32_t jsonout_initialize(nslog_buf_t *outbuf)
{
	nslog_put_char(outbuf, '{');

	return 0;
}
static int32_t jsonout_finalize(nslog_buf_t *outbuf)
{
	char *p = outbuf->buf - 1;

	if (*p == ',') {
		outbuf->buf--;
	}

	nslog_put_string(outbuf, "}\0", 2);
	//nslog_put_char(outbuf, '\0');

	return 0;
}

nslog_output_handler_t g_jsonout_handler = {
	.initialize = jsonout_initialize,
	.finalize = jsonout_finalize,

	.modinfo[NSLOG_MOD_HDR] = {	
		.name = {'H', 'D', 'R', '\0'},
		.fldcount = 2,
		.ver = 1,
		.logmod = NSLOG_MOD_HDR,
		.output = jsonout_hdr
	},

	.modinfo[NSLOG_MOD_PKT] = {	
		.name = {'P', 'K', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_PKT,
		.output = jsonout_packet
	},

	.modinfo[NSLOG_MOD_SESSION] = {	
		.name = {'S', 'E', 'S', 'S', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_SESSION,
		.output = jsonout_session
	},

	.modinfo[NSLOG_MOD_NAT] = {	
		.name = {'N', 'A', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_NAT,
		.output = jsonout_nat
	},
};

int32_t nslog_jsonout_init(void)
{
	nslog_set_handler(NSLOG_FMT_JSON, &g_jsonout_handler);

	return 0;
}

