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


typedef struct {
	char		*name;
	unsigned long val;
	uint32_t	min;
	uint32_t	max;
	uint32_t	mode;
	void 		*hproc;
	uint32_t 	msg_id;
} option_t;

extern option_t g_ns_opts[];

#define OPT_IDX(x)				OPT_IDX_##x
#define OPT_IDX(x)				OPT_IDX_##x
#define OPT_ITEM(n,v,m,x,mo,h)  	[OPT_IDX(n)] = {\
	.name=__STR(n),\
	.val=v,\
	.min=m,\
	.max=x,\
	.mode=mo,\
	.hproc=h,\
	.msg_id=OPT_IDX(n),\
}

//#define GET_OPT_VALUE_BY_IDX(x)	 	(g_ns_opts[x].val)
//#define SET_OPT_VALUE_BY_IDX(x, v)	 (g_ns_opts[x].val = v)

#define GET_OPT_VALUE(x)	 (g_ns_opts[OPT_IDX(x)].val)
#define SET_OPT_VALUE(x, v)	 (g_ns_opts[OPT_IDX(x)].val = v)
#define GET_OPT_MAX_VALUE(x) (g_ns_opts[OPT_IDX(x)].max)

// option 항목이 추가 되는 경우 추가 한다.
enum opt_idx {
	OPT_MIN = 0,

	OPT_IDX(all_allow_log),
	OPT_IDX(all_drop_log),
	OPT_IDX(all_drop_log_skip_by_seq),
	OPT_IDX(info_log_interval),
	OPT_IDX(nat_arp_proxy),

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
int32_t opt_get_val(uint32_t optidx);
void opt_set_val(uint32_t optidx, int32_t val);
uint32_t opt_get_index(char *name);

#endif
