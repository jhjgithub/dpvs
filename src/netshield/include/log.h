#ifndef __NS_LOG_H__
#define __NS_LOG_H__


#define NSLOG_MOD_NAME_LEN 32
#define NSLOG_NIC_NAME_LEN 16
#define NSLOG_ZONE_NAME_LEN 64

typedef struct list_head list_head_t;
typedef int32_t (*nslog_output)(char *name, uint32_t fldcount, uint32_t ver, void *logobj);
//typedef int32_t (*nslog_output_schema)(void** out, size_t *outlen);


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

typedef struct nslog_output_handler_s {
	char 				name[NSLOG_MOD_NAME_LEN];
	uint32_t 			fldcount;
	uint32_t 			ver;
	uint32_t 			logmod;
	nslog_output 		output;
	//nslog_output_schema	output_schema;
} nslog_output_handler_t;

#if 0
// module info
typedef struct nslog_modinfo_s {
	struct list_head 	anchor;

	char 				name[NSLOG_MOD_NAME_LEN];
	uint32_t 			fldcount;
	uint32_t 			ver;
} nslog_modinfo_t;
#endif

//////////////////////////////
// log = header |  body+
// body = packet | session | nat*
// 반드시 구조체 멤버의 순서대로 출력 한다.

// log header
typedef struct nslog_hdr_s {
	//nslog_modinfo_t modinfo;

	time_t 		tm;
	uint32_t 	logid;
	uint32_t 	level;
} nslog_hdr_t;

// packet log
typedef struct nslog_pkt_s {
	//nslog_modinfo_t modinfo;

	uint64_t 	act;
	char 		innic[NSLOG_NIC_NAME_LEN];
	char 		outnic[NSLOG_NIC_NAME_LEN];
	char 		srczone[NSLOG_ZONE_NAME_LEN];
	char 		dstzone[NSLOG_ZONE_NAME_LEN];
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
	//nslog_modinfo_t modinfo;

	uint64_t 	sid;
	uint32_t 	state;
	uint32_t 	opentime;
	uint32_t 	closetime;
	uint32_t 	duration; 		// in seconds
	uint32_t 	fwruleid;
	nslog_traffic_t traffic[NSLOG_DIR_MAX]; // 0: c->s, 1: s->c
} nslog_session_t;

typedef struct nslog_nat_s {
	//nslog_modinfo_t modinfo;

	ip_t 		src;
	ip_t 		dst;
	uint16_t 	sport;
	uint16_t 	dport;
	uint32_t 	natruleid;
} nslog_nat_t;


/////////////////////////////////////////
//

int32_t nslog_print(int32_t id, int32_t lev, const char* fmt, ...);
nslog_output_handler_t* nslog_get_handler(uint32_t logfmt);
int32_t nslog_set_handler(uint32_t logfmt, nslog_output_handler_t *handlers, uint32_t cnt);

////////////////////

#endif
