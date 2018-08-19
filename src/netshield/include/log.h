#ifndef __NS_LOG_H__
#define __NS_LOG_H__


#define NSLOG_MOD_NAME_LEN 32
#define NSLOG_NIC_NAME_LEN 16
#define NSLOG_ZONE_NAME_LEN 64

struct nslog_buf_s;
struct nslog_modinfo_s;

typedef struct list_head list_head_t;
typedef int32_t (*nslog_output)(struct nslog_buf_s *outbuf, struct nslog_modinfo_s *minfo, void *logobj);
typedef int32_t (*nslog_initialize)(struct nslog_buf_s *outbuf);
typedef int32_t (*nslog_finalize)(struct nslog_buf_s *outbuf);
//typedef int32_t (*nslog_output_schema)(void** out, size_t *outlen);

enum {
	NSLOG_STAT_OPEN = 0,
	NSLOG_STAT_CLOSE,
	NSLOG_STAT_INFO,
	NSLOG_STAT_EXCEPTION,

	NSLOG_STAT_MAX
};


// format of output
enum {
	NSLOG_FMT_TEXT = 0,
	NSLOG_FMT_JSON,

	NSLOG_FMT_MAX
};

// module of LOG
enum {
	NSLOG_MOD_HDR = 0,
	NSLOG_MOD_PKT,
	NSLOG_MOD_SESSION,
	NSLOG_MOD_NAT,

	NSLOG_MOD_MAX
};

typedef struct nslog_buf_s {
	char  	*buf;
	int32_t len;
} nslog_buf_t;

typedef struct nslog_modinfo_s {
	uint32_t 			logmod;
	char 				name[NSLOG_MOD_NAME_LEN];
	uint32_t 			fldcount;
	uint32_t 			ver;
	nslog_output 		output;
} nslog_modinfo_t;

typedef struct nslog_output_handler_s {
	nslog_modinfo_t 	modinfo[NSLOG_MOD_MAX];
	nslog_initialize 	initialize;
	nslog_finalize 		finalize;
	//nslog_output_schema	output_schema;
} nslog_output_handler_t;

#define NSLOG_FLAG_TXTOUT_WITHOUT_KEY 0x01
typedef struct nslog_conf_s {
	uint32_t flags;
	uint32_t outfmt;
	char  	 *timefmt;
	char 	 txtout_deli;
} nslog_conf_t;

//////////////////////////////
// log = header |  body+
// body = packet | session | nat*
// 반드시 구조체 멤버의 순서대로 출력 한다.

// log header
typedef struct nslog_hdr_s {
	//nslog_modinfo_t modinfo;

	time_t 		tv;
	uint32_t 	logid;
	uint32_t 	level;
} nslog_hdr_t;

// packet log
typedef struct nslog_pkt_s {
	uint64_t 	act;
	char 		innic[NSLOG_NIC_NAME_LEN];
	char 		outnic[NSLOG_NIC_NAME_LEN];
	char 		inzone[NSLOG_ZONE_NAME_LEN];
	char 		outzone[NSLOG_ZONE_NAME_LEN];
	ip_t 		src;
	ip_t 		dst;
	uint16_t 	sport;
	uint16_t 	dport;
	uint8_t 	proto;
	uint8_t 	dummy[3];
} nslog_pkt_t;

typedef struct nslog_traffic_s {
	uint64_t 	packets;
	uint128_t 	bytes;
} nslog_traffic_t;

enum {
	NSLOG_DIR_CS = 0,
	NSLOG_DIR_SC,
	NSLOG_DIR_MAX
};

typedef struct nslog_session_s {
	uint64_t 	sid;
	uint32_t 	state;
	time_t 		opentime;
	time_t 		closetime;
	time_t 		duration; 
	uint32_t 	fwruleid;
	nslog_traffic_t traffic[NSLOG_DIR_MAX]; // 0: c->s, 1: s->c
} nslog_session_t;

typedef struct nslog_nat_s {
	uint64_t 	nattype;
	ip_t 		ip[2];
	uint16_t 	port[2];
	uint32_t 	natruleid;
} nslog_nat_t;


/////////////////////////////////////////
//

nslog_output_handler_t* nslog_get_handler(uint32_t logfmt);
int32_t nslog_print(int32_t id, int32_t lev, const char* fmt, ...);
int32_t nslog_set_handler(uint32_t logfmt, nslog_output_handler_t *handler);
int32_t nslog_put_char(nslog_buf_t *outbuf, char c);
int32_t nslog_put_string(nslog_buf_t *outbuf, char *str, int len);
int32_t nslog_convert_time_string(time_t *tv, char *tbuf, int tbuf_len);
int32_t nslog_convert_duration(time_t dur, char *tbuf, int tbuf_len);
int32_t nslog_output_ipv4(nslog_buf_t *outbuf, ip_t ip);
char 	*nslog_get_state_name(uint32_t state);
char 	*nslog_get_action_name(uint64_t act);
void 	nslog_syslog(int facility, char *msg);

////////////////////

#endif
