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


//////////////////////////////////////////////////////
//

typedef struct nslog_text_output_conf_s {
	uint32_t flags;
	char 	 deli;
} nslog_text_output_conf_t;

#define TEXTOUT_NO_KEY 0x01

nslog_text_output_conf_t g_textout_conf = {
	.flags = TEXTOUT_NO_KEY,
	.deli = '|',
};

typedef struct outbuf_s {
	char 		*buf;
	int32_t  	len;
	int32_t 	first;
} outbuf_t;

int32_t tout_field(outbuf_t *outbuf, char *fldname, char *fmt, ...)
{
	if (outbuf->len < 1) {
		return 0;
	}

	if (outbuf->first) {
		outbuf->first = 0;
	}
	else {
		*outbuf->buf = g_textout_conf.deli;
		outbuf->buf ++;
		outbuf->len --;
	}

	int len;
	if (!(g_textout_conf.flags & TEXTOUT_NO_KEY)) {
		len = strlen(fldname);
		if (len >= outbuf->len) {
			return 0;
		}

		memcpy(outbuf->buf, fldname, len);
		outbuf->buf += len;
		*outbuf->buf = '=';
		outbuf->len -= len;
		outbuf->len --;
	}

	va_list ap;
	va_start(ap, fmt);
	len = snprintf(outbuf->buf, outbuf->len, fmt, ap);
	va_start(ap, fmt);

	outbuf->len -= len;

	return outbuf->len;
}

static int32_t text_output_common(outbuf_t *outbuf, char *name, uint32_t fldcount, uint32_t ver)
{
#if 0
	char *fmt_no_key = "%s%c%d%c%d";
	char *fmt_with_key = "name=%s%cfldcnt=%d%cver=%d";
	char *fmt;
	int len;

	if (g_textout_conf.flags & TEXTOUT_NO_KEY) {
		fmt = fmt_no_key;
	}
	else {
		fmt = fmt_with_key;
	}

	len = snprintf(outbuf->buf, outbuf->len, fmt, 
				   name, 
				   g_textout_conf.deli,
				   fldcount, 
				   g_textout_conf.deli,
				   ver);

	outbuf->len -= len;

	return outbuf->len;
#else
	tout_field(outbuf, "name", "%s", name);
	tout_field(outbuf, "fldcnt", "%u", fldcount);
	tout_field(outbuf, "ver", "%u", ver);
#endif
}

static int32_t text_output_hdr(char *name, uint32_t fldcount, uint32_t ver, void *logobj)
{
	nslog_hdr_t *loghdr = (nslog_hdr_t*)logobj;

	char tbuf[64];
	struct tm *tm;
	int len=0,rc;
	char buf[1024];
	char *fmt_no_key = "%s|%d|%d";
	char *fmt_with_key = "time=%s|logid=%d|level=%d";
	char *fmt = NULL;

	tm = localtime(&loghdr->tm);
	strftime(tbuf, 64, "%Y-%m-%d %H:%M:%S.000", tm);

	if (g_textout_conf.flags & TEXTOUT_NO_KEY) {
		fmt = fmt_no_key;
	}
	else {
		fmt = fmt_with_key;
	}
	
#if 0
	outbuf_t outbuf;
	outbuf.buf = buf;
	outbuf.tlen = 1024;
	outbuf.clen = 0;

	rc = text_output_common(&outbuf, name, fldcount, ver);
	if (rc < 1) {
		return 0;
	}

	len = snprintf(&outbuf.buf[outbuf.clen], outbuf.tlen-outbuf.clen, 
				   fmt, tbuf, loghdr->logid, loghdr->level);
	outbuf.clen += len;
#endif

	printf ("%s\n", buf);

	return 0;
}

static int32_t text_output_packet(char *name, uint32_t fldcount, uint32_t ver, void *logobj)
{
	nslog_pkt_t *logpkt = (nslog_pkt_t*)logobj;

	return 0;
}

static int32_t text_output_session(char *name, uint32_t fldcount, uint32_t ver, void *logobj)
{
	nslog_session_t *logses = (nslog_session_t*)logobj;

	return 0;
}

static int32_t text_output_nat(char *name, uint32_t fldcount, uint32_t ver, void *logobj)
{
	nslog_nat_t *lognat = (nslog_nat_t*)logobj;

	return 0;
}

nslog_output_handler_t g_text_output[NSLOG_MOD_MAX] = {
	{	
		.name = {'H', 'D', 'R', '\0'},
		.fldcount = 2,
		.ver = 1,
		.logmod = NSLOG_MOD_HDR,
		.output = text_output_hdr
	},
	{	
		.name = {'P', 'K', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_PKT,
		.output = text_output_packet
	},
	{	
		.name = {'S', 'E', 'S', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_SESSION,
		.output = text_output_session
	},
	{	
		.name = {'N', 'A', 'T', '\0'},
		.fldcount = 3,
		.ver = 1,
		.logmod = NSLOG_MOD_NAT,
		.output = text_output_nat
	},
};

int32_t nslog_init_text_output(void)
{
	int asize = sizeofa(g_text_output);
	nslog_set_handler(NSLOG_FMT_TEXT, g_text_output, asize);

	return 0;
}
