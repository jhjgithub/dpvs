#ifndef __OPTIONS_H__
#define __OPTIONS_H__

struct ioctl_data_s;

#define MODE_RW 		0644
#define MODE_RO 		0444

#define O_N 			0x00000000
#define O_W				0x00000001 		// read/write
#define O_R 			0x00000002 		// read only
#define O_A 			0x00000004 		// atomic read only
#define O_U				0x00000010 		// user accessable

#if 0
struct opt_item_s;
typedef unsigned long (*cb_opt_set_val)(struct opt_item_s *item, unsigned long);
typedef unsigned long (*cb_opt_get_val)(struct opt_item_s *item);
#endif

typedef struct opt_item_s {
	char		*name;
	ulong_t  	val;
	ulong_t		min;
	ulong_t		max;
	uint32_t	mode;
	uint32_t 	msg_id;
	//cb_opt_get_val get_val;
	//cb_opt_set_val set_val;
} opt_item_t;

#define OPT_IDX(x)				OPT_IDX_##x
#define OPT_IDX(x)				OPT_IDX_##x
#define OPT_ITEM(n,v,m,x,mo)  	[OPT_IDX(n)] = {\
	.name=__STR(n),\
	.val=v,\
	.min=m,\
	.max=x,\
	.mode=mo,\
	.msg_id=OPT_IDX(n),\
}

#if 0
#define GET_OPT_VALUE(x)	 (g_ns_opts[OPT_IDX(x)].val)
#define SET_OPT_VALUE(x, v)	 (g_ns_opts[OPT_IDX(x)].val = v)
#define GET_OPT_MAX_VALUE(x) (g_ns_opts[OPT_IDX(x)].max)
#else
#define GET_OPT_VALUE(x)	 opt_get_val(OPT_IDX(x))
#define SET_OPT_VALUE(x, v)	 opt_set_val(OPT_IDX(x), v)
//#define GET_OPT_MAX_VALUE(x) (g_ns_opts[OPT_IDX(x)].max)
#endif

// option 항목이 추가 되는 경우 추가 한다.
enum opt_idx {
	OPT_IDX(all_allow_log),
	OPT_IDX(all_drop_log),
	OPT_IDX(all_drop_log_skip_by_seq),
	OPT_IDX(info_log_interval),
	OPT_IDX(nat_arp_proxy),
	OPT_IDX(nls),

	//
	OPT_IDX(age_interval),
	OPT_IDX(bl_btime),
	OPT_IDX(bl_log),
	OPT_IDX(bl_log_param),
	//OPT_IDX(current_time),
	OPT_IDX(frag_pkt_drop_cnt),

	OPT_IDX(session_bucket_power),
	OPT_IDX(session_cnt),
	OPT_IDX(session_cnt_mine),
	OPT_IDX(session_cnt_remote),
	OPT_IDX(session_cnt_local),
	//OPT_IDX(session_magic),
	OPT_IDX(session_state),
	OPT_IDX(session_max),
	OPT_IDX(session_max_warn),
	OPT_IDX(start_time),

	//OPT_IDX(version),


	OPT_IDX(timeout_udp),   
	OPT_IDX(timeout_udp_reply),   
	OPT_IDX(timeout_icmp),   
	OPT_IDX(timeout_icmp_reply), 
	OPT_IDX(timeout_unknown),   

	OPT_IDX(drop_tcp_oow),   
	OPT_IDX(timeout_tcp),   
	OPT_IDX(timeout_syn_sent),   
	OPT_IDX(timeout_syn_rcv),    
	OPT_IDX(timeout_fin_wait),  
	OPT_IDX(timeout_close_wait), 
	OPT_IDX(timeout_last_ack),   
	OPT_IDX(timeout_time_wait),  
	OPT_IDX(timeout_close),      
	OPT_IDX(timeout_max_retrans),

	OPT_MAX

};

////////////////////////////////////

int32_t opt_show_table(struct ioctl_data_s *iodata);
ulong_t opt_get_val(uint32_t optidx);
void 	opt_set_val(uint32_t optidx, ulong_t val);
uint32_t opt_get_index(char *name);

#endif
