#include <stdio.h>
#include <stdint.h>

#include <ns_typedefs.h>
#include <options.h>
#include <macros.h>
#include <ns_dbg.h>
#include <smgr.h>
#include <utils.h>
#include <ioctl.h>
#include <nls.h>


//////////////////////////////////////////////////////


DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

/*** *INDENT-OFF* ***/
opt_item_t g_ns_opts [] = {
    // 1. Define modules
    // ----- name               value       min     max     mode   
    OPT_ITEM(all_allow_log,     0,          0,      1,      O_W|O_U),
    OPT_ITEM(all_drop_log,      0,          0,      1,      O_W|O_U),
    OPT_ITEM(all_drop_log_skip_by_seq,1,    0,      1,      O_W),
    OPT_ITEM(info_log_interval, 60,         0,      86400,  O_W),
    OPT_ITEM(nat_arp_proxy,		1,          0,      1,  	O_W),
    // 기능 항목 끝

    // 2. Define options
    OPT_ITEM(age_interval,      1,          1,      100,    O_W),
    OPT_ITEM(bl_btime,          30,         1,      86400,  O_W),
    OPT_ITEM(bl_log,            1,          0,      2,      O_W),
    OPT_ITEM(bl_log_param,      100,        5,      65535,  O_W),
    OPT_ITEM(frag_pkt_drop_cnt, 0,          0,      0,      O_R),

    OPT_ITEM(session_bucket_power,19,       15,     26,     O_W),
    OPT_ITEM(session_cnt,       0,          0,      0, 		O_R),
    OPT_ITEM(session_cnt_mine,  0,          0,      0,      O_R),
    OPT_ITEM(session_cnt_remote,0,          0,      0,      O_R),
    OPT_ITEM(session_cnt_local, 0,          0,      0,      O_R),
    OPT_ITEM(session_state, 	0,          0,      0,      O_R),
    OPT_ITEM(session_max,       0,          0,      60000000,O_W),
    OPT_ITEM(session_max_warn,  95,        80,      99,     O_W),

    OPT_ITEM(start_time,        0,          0,      0,      O_R),

    OPT_ITEM(timeout_udp,       100,        0,      100000, O_W|O_U),
    OPT_ITEM(timeout_udp_reply, 10,         0,      100000, O_W|O_U),
    OPT_ITEM(timeout_icmp,      10,         0,      100000, O_W|O_U),
    OPT_ITEM(timeout_icmp_reply,3,          1,      300,    O_W|O_U),
    OPT_ITEM(timeout_unknown,   30,         0,      100000, O_W|O_U),

    // for TCP protocol
    OPT_ITEM(drop_tcp_oow,      0,          0,      1,      O_W),
    OPT_ITEM(timeout_tcp,       3600,       0,      100000, O_W|O_U),
    OPT_ITEM(timeout_syn_sent,  120,        1,      65535,  O_W),
    OPT_ITEM(timeout_syn_rcv,   60,         1,      65535,  O_W),
    OPT_ITEM(timeout_fin_wait,  120,        1,      65535,  O_W),
    OPT_ITEM(timeout_close_wait,60,         1,      65535,  O_W),
    OPT_ITEM(timeout_last_ack,  30,         1,      65535,  O_W),
    OPT_ITEM(timeout_time_wait, 10,         1,      65535,  O_W),
    OPT_ITEM(timeout_close,     10,         1,      65535,  O_W),
    OPT_ITEM(timeout_max_retrans,300,       1,      65535,  O_W),

};
/*** *INDENT-ON* ***/

opt_item_t* opt_get_table_entry(uint32_t optidx)
{
	if (optidx >= OPT_MAX) {
		return NULL;
	}

	return &g_ns_opts[optidx];
}

ulong_t opt_get_val(uint32_t optidx)
{
	opt_item_t* o;

	// for special type of data
	switch(optidx) {
	case OPT_IDX(session_cnt):
		(int32_t)smgr_get_session_count();

	default:
		break;
	}

	o = opt_get_table_entry(optidx);
	if (o == NULL) {
		return 0;
	}

	if (o->mode & O_A) {
		return (ulong_t)atomic_read((atomic_t*)o->val);
	}
	
	return o->val;
}

void opt_set_val(uint32_t optidx, ulong_t val)
{
	opt_item_t* o;

	o = opt_get_table_entry(optidx);
	if (o == NULL) {
		return;
	}

	if (!(o->mode & O_W)) {
		return;
	}

	if (o->mode & O_A) {
		return atomic_set((atomic_t*)o->val, (int32_t)val);
	}
	
	o->val = val;
}

int32_t opt_show_table(ioctl_data_t *iodata)
{
	ulong_t val;
	char mode[32];
	int opt_sz, i;
	opt_item_t *o;
	int l, buflen;
	char buf[1024];;

	opt_sz = sizeofa(g_ns_opts);
	buflen = sizeof(buf);

	// title
	l = snprintf(buf, buflen, "%-3s %-24s %-5s %-10s %-7s %-10s %-16s %-16s %s\n",
				 "Idx", "Name", "Mode", "Val", "Min", "Max", "List", "Group", "Desc");

	if (copy_expand(iodata, buf, l, 1024)) {
		return -1;
	}

	for (i=0; i<OPT_MAX; i++) {
		val = opt_get_val(i);
		o = opt_get_table_entry(i);

		sprintf(mode, "%s%s",
				(o->mode & O_U)?"U":"",
				(o->mode & (O_R|O_A))?"RO":"RW");

		l = snprintf(buf, buflen, "%-3d %-24s %-5s %-10lu %-7lu %-10lu %-16s %-16s %s\n",
					o->msg_id,
					o->name,
					mode,
					val,
					o->min,
					o->max,
					nls_get_value_list(o->msg_id),
					nls_get_group(o->msg_id),
					nls_get_msg(o->msg_id)
					);

		if (copy_expand(iodata, buf, l, 1024)) {
			return -1;
		}
	}

	return 0;
}

uint32_t opt_get_index(char *name) 
{
	uint32_t i;
	opt_item_t *o;

	for (i=0; i<OPT_MAX; i++) {
		o = opt_get_table_entry(i);

		if (strcmp(name, o->name) == 0) {
			return i;
		}
	}

}

