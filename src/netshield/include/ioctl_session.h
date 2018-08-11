#ifndef __IOCTL_SESSION_H__
#define __IOCTL_SESSION_H__


typedef struct ioctl_session_s {
	skey_t 		skey;	
	uint32_t 	sid;
	uint32_t	flags;
	uint64_t	action; 
	uint32_t	born_time;

	int32_t 	timeout;
	uint32_t 	drop_pkts;	
	//tcpst_t		tcpst; 

	uint32_t 	fwpolicy_id;
	uint32_t 	natpolicy_id;

} ioctl_session_t;

typedef struct ioctl_get_sess_s {
	uint32_t start_idx;
	uint32_t num_sess; 	// in: max session, out: stored session

	char data[0];
} ioctl_get_sess_t;



#endif
