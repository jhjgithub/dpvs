#include <stdio.h>
#include <stdint.h>

#if 0
#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <version.h>
#include <ns_malloc.h>
#include <ns_sysctl.h>
#include <smgr.h>
#endif

#include <options.h>
#include "ns_typedefs.h"
#include "macros.h"
#include "ns_dbg.h"


//////////////////////////////////////////////////////

//#define PROC_MIN_MAX	&proc_dointvec_minmax
//#define PROC_LONG 		&proc_doulongvec_minmax
#define PROC_MIN_MAX	NULL
#define PROC_LONG 		NULL

#if 0
#define ATOMIC_SCNT_ALL 		1
#define ATOMIC_SCNT_MINE 		2
#define ATOMIC_SCNT_REMOTE 		3
#define ATOMIC_SCNT_LOCAL 		4
#define ATOMIC_SCNT_MAGIC 		5
#define ATOMIC_CURRENT_TIME 	6
#endif


DECLARE_DBG_LEVEL(2);

//extern smgr_t		*g_smgr; 

//////////////////////////////////////////////////////


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

/*** *INDENT-OFF* ***/
option_t ns_options [] = {
    // 1. Define modules
    // ----- name               value       min     max     mode        proc_handler
    OPT_ITEM(all_allow_log,     0,          0,      1,      O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(all_drop_log,      0,          0,      1,      O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(all_drop_log_skip_by_seq,1,    0,      1,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(info_log_interval, 60,         0,      86400,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(nat_arp_proxy,		1,          0,      1,  	O_W,        PROC_MIN_MAX),
    // 기능 항목 끝

    // 2. Define options
    OPT_ITEM(age_interval,      1,          1,      100,    O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_btime,          30,         1,      86400,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_log,            1,          0,      2,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_log_param,      100,        5,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(frag_pkt_drop_cnt, 0,          0,      0,      O_R,        PROC_MIN_MAX),

    OPT_ITEM(session_bucket_power,19,       15,     26,     O_W,        PROC_MIN_MAX),
    OPT_ITEM(session_state, 	0,          0,      0,      O_R,        NULL),
    OPT_ITEM(session_max,       0,          0,      60000000,O_W,       PROC_MIN_MAX),
    OPT_ITEM(session_max_warn,  95,        80,      99,     O_W,        PROC_MIN_MAX),

    OPT_ITEM(start_time,        0,          0,      0,      O_R,        PROC_MIN_MAX),

    OPT_ITEM(timeout_udp,       100,        0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_udp_reply, 10,         0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_icmp,      1,          0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_icmp_reply,3,          1,      300,    O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_unknown,   30,         0,      100000, O_W|O_U,    PROC_MIN_MAX),

    // for TCP protocol
    OPT_ITEM(drop_tcp_oow,      0,          0,      1,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_tcp,       3600,       0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_syn_sent,  120,        1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_syn_rcv,   60,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_fin_wait,  120,        1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_close_wait,60,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_last_ack,  30,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_time_wait, 10,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_close,     10,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_max_retrans,300,       1,      65535,  O_W,        PROC_MIN_MAX),

	[OPT_MAX] = {.name=NULL}

};
/*** *INDENT-ON* ***/

