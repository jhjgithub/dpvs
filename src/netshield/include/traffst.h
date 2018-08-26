#ifndef TRAFFIC_STATISTIC_H__
#define TRAFFIC_STATISTIC_H__

// 트래픽 통계 모


// tcp flag별 패킷 카운트 : 32bit
typedef struct _stat_tcpf{
	uint32_t	syn; 		// syn + not ack
	uint32_t	syn_ack; 	// syn + ack 
	uint32_t	fin;
	uint32_t	rst;
	uint32_t	ack; 		// ack + all not syn
	uint32_t	psh;
	uint32_t	urg;
	uint32_t	null;
} st_tcpf_t;

#define MAX_SZ_ORDER 	6
#define ST_PORT_RANGE 	65536

typedef struct _st_item_t {
	// total
	uint64_t	byts;			// total bytes
	uint32_t	pkts;			// total packets
	uint32_t	sc;				// Session Count of the all(firewall, nat, ipsec ...)
	uint32_t	sc_nat;			// Session Count of the NAT
	uint32_t 	psz[MAX_SZ_ORDER];// count each packet size

	// per second : 누적중인 값
	uint32_t	bps; 			// byte 단위로 누적
	uint32_t	pps;
	uint32_t 	cps;
	uint32_t 	cps_nat;
	uint32_t 	sps[MAX_SZ_ORDER]; 	// 패킷 사이즈별 카운트

	// last per second : 사용가능 한 값
	uint32_t	last_bps; 			// byte 단위로 누적
	uint32_t	last_pps;
	uint32_t 	last_cps;
	uint32_t  	last_cps_nat;
	uint32_t 	last_sps[MAX_SZ_ORDER];

} st_item_t;	

typedef struct _st_port_t {
	uint64_t 	byts;
	uint32_t 	pkts;
	uint32_t 	sc; 			// session count
#if 0
// 메모리 사용량으로 인해서 전체 패킷 수만 누적 한다.
// PPS까지 저장 하는 경우 약 3.5MB 사용함
	uint32_t 	bps;
	uint32_t 	pps;

	uint32_t 	last_bps;
	uint32_t 	last_pps;
#endif
} st_port_t;

///////////////////////////////////////////////
// 1. 바이트/패킷수/세션수/nat 세션수/패킷 사이즈별 패킷수
// 2. TCP/UDP/ICMP/Other/All
// 3. 전체 누적/ 시간 단위당 누적 / 마지막 시간 당위당 누적 
// 4. TCP flag 별 패킷수(전체/시간당위당/ 미지막 시간 단위당)
// 5. 포트별 바이트/패킷수 누적
// TODO:
// 	-. src host 별 통계 정보
//	-. dst host 별 통계 정보

typedef struct _wise_stat {

	// per protocol
	st_item_t	tcp;
	st_item_t	udp;
	st_item_t	icmp;
	st_item_t	oth;
	st_item_t 	all;

	// pkt count per tcp flag
	st_tcpf_t	tcpf[3];		// [0]: total, 
								// [1]: per second data, 누적중인 데이터
								// [2]: last pps data, 	사용가능 한 값.

	st_port_t 	port_tcp[ST_PORT_RANGE];
	st_port_t 	port_udp[ST_PORT_RANGE];

} wstat_t;


/* -------------------------------- */
/*         Prototype 선언 영역      */
/* -------------------------------- */
/* extern 함수는 doxygen에서 제외   */
///@cond DOXGEN_EXCLUDE_THIS

int32_t wst_init(void);
void 	wst_clean(void);
int32_t wst_ageing(void);
int32_t wst_main(wt_t*, int32_t );
void 	wst_inc_sc(si_t* si);
void 	wst_dec_sc(si_t* si);
int32_t wst_get_sc(void);
void 	wst_inc_drop_info(wt_t* wt, fwr_t* rule);

///@endcond



#endif
