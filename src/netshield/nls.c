#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <dpdk.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <nls.h>
#if 0
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
#include <utils.h>
#endif


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

// National Laguages Support: KOR, ENG

/* *INDENT-OFF* */
nls_msg_t kor [NLS_ID_MAX] = {
	// Option Table NLS MSG

	// 1. 기능 항목 (On/Off)
	NLS_OPT_ITEM(all_allow_log,		방화벽, OFF/ON, 모든 허용 패킷 로그 저장),
	NLS_OPT_ITEM(all_drop_log,		방화벽, OFF/ON, 모든 차단 패킷 로그 저장),
	NLS_OPT_ITEM(all_drop_log_skip_by_seq, 방화벽, OFF/ON, TCP SEQ가 동일한 차단 패킷 로그 저장 안함),
	NLS_OPT_ITEM(info_log_interval, 방화벽, OFF/간격, 중간 세션 로그 저장 최소 간격(초, 0:저장안함, 최소값:10)),
	//NLS_OPT_ITEM(bl,				none, none, 차단목록),
	//NLS_OPT_ITEM(frag,   			none, none, 단편화 패킷 재조합),
	NLS_OPT_ITEM(nat_arp_proxy,		none, none, NAT IP ARP Proxy),
	NLS_OPT_ITEM(nls,				none, none, 다국어 지원 (0:KOR, 1:ENG, 2:JP, 3:CH)),

	NLS_OPT_ITEM(age_interval,		none, none, 에이징 간격),
	NLS_OPT_ITEM(bl_btime,			none, none, 차단목록 차단 시간:초),
	NLS_OPT_ITEM(bl_log,			none, none, 차단목록 차단 로그 종류 (1:Per PKT, 2:Per SEC)),
	NLS_OPT_ITEM(bl_log_param,		none, none, 차단목록 차단 파라미터),
	NLS_OPT_ITEM(frag_pkt_drop_cnt,	none, none, 단편화 패킷 차단 수),
	//NLS_OPT_ITEM(frag_pkt_min_len,	none, none, 단편화 패킷 차단 최소 길이 (0:OFF)),

	NLS_OPT_ITEM(start_time,		none, none, 현재 시간),

	NLS_OPT_ITEM(timeout_udp,		none, none, UDP Timeout),
	NLS_OPT_ITEM(timeout_udp_reply,	none, none, UDP Reply Timeout),
	NLS_OPT_ITEM(timeout_icmp,		none, none, ICMP Timeout),
	NLS_OPT_ITEM(timeout_icmp_reply,none, none, ICMP Reply Timeout),
	NLS_OPT_ITEM(timeout_unknown,	none, none, Unknown Protocol Timeout),

	NLS_OPT_ITEM(drop_tcp_oow,		none, none, TCP Out of Window 패킷 차단),
	NLS_OPT_ITEM(timeout_tcp,		none, none, TCP Timeout),
	NLS_OPT_ITEM(timeout_syn_sent,	none, none, SYN SENT Timeout),
	NLS_OPT_ITEM(timeout_syn_rcv,	none, none, SYN RECV Timeout),
	NLS_OPT_ITEM(timeout_fin_wait,	none, none, FIN WAIT Timeout),
	NLS_OPT_ITEM(timeout_close_wait,none, none, CLOSE WAIT Timeout),
	NLS_OPT_ITEM(timeout_last_ack,	none, none, LAST ACK Timeout),
	NLS_OPT_ITEM(timeout_time_wait,	none, none, TIME WAIT Timeout),
	NLS_OPT_ITEM(timeout_close,		none, none, CLOSE Timeout),
	NLS_OPT_ITEM(timeout_max_retrans, none, none, MAX RETRANS Timeout),

#if 0
	NLS_OPT_ITEM(nls,				none, none, 다국어 지원 (0:KOR, 1:ENG, 2:JP, 3:CH)),
	NLS_OPT_ITEM(ilb,				none, none, InterLink를 통한 LB),
	NLS_OPT_ITEM(panomaly,			none, none, 프로토콜 오용 차단),
	NLS_OPT_ITEM(psd,				none, none, 포트스캔 탐지),
	NLS_OPT_ITEM(pkt_limit,			none, none, BPS/PPS 제어),
	NLS_OPT_ITEM(fast_route,		none, none, 라우팅 캐시를 이용한 라우팅),
	NLS_OPT_ITEM(rtd,				none, none, 실시간 DDOS 탐지),
	NLS_OPT_ITEM(rt_type_zero,		none, none, type zero routing header),
	NLS_OPT_ITEM(ses_clear,			none, none, 방화벽 정책 적용시 세션 삭제 (0:OFF, 1:AUTO: 2:ALL, 3:NAT)),
	NLS_OPT_ITEM(strict_land_attack,none, none, 엄격한 Land Attack 방어),
	NLS_OPT_ITEM(syn_only,			none, none, TCP일 경우 SYN 패킷에 의해서만 세션 생성),
	NLS_OPT_ITEM(syn_proxy,			none, none, SYN Proxy 사용),
	NLS_OPT_ITEM(tcp_assem,			none, none, 재조합된 TCP 패킷의 IPS 탐지 지원),
	NLS_OPT_ITEM(tcp_mss_hack,		none, none, TCP MSS Hack),
	NLS_OPT_ITEM(tg,				none, none, TrustGuard DDOS 차단),
	NLS_OPT_ITEM(url,				none, none, URL Filter),
	NLS_OPT_ITEM(wst,				none, none, 통계 데이터 생성),
	NLS_OPT_ITEM(webmail,			none, none, 웹메일 Filter),
	NLS_OPT_ITEM(dsync,				none, none, 데이터 동기화),
	NLS_OPT_ITEM(rcc,				none, none, 라우팅 캐시 컨트롤),
	NLS_OPT_ITEM(drop_page,			none, none, 차단페이지 사용),

	// 2. 값 설정 항목
	NLS_OPT_ITEM(ahot_cnt,			none, none, 인증 상태 조회),
	NLS_OPT_ITEM(bl_btime,			none, none, 차단목록 차단 시간:초),
	NLS_OPT_ITEM(bl_log,			none, none, 차단목록 차단 로그 종류 (1:Per PKT, 2:Per SEC)),
	NLS_OPT_ITEM(bl_log_param,		none, none, 차단목록 차단 파라미터),
	NLS_OPT_ITEM(current_time,		none, none, 현재 시간),
	NLS_OPT_ITEM(frag_pkt_drop_cnt,	none, none, 단편화 패킷 차단 수),

	NLS_OPT_ITEM(cpulb,				none, none, Enable CPU Loadbalancer),
	NLS_OPT_ITEM(cpulb_weight,		none, none, CPU Weight), 
	NLS_OPT_ITEM(cpulb_nic,		    none, none, NIC list for CPU LB),
	NLS_OPT_ITEM(cpulb_nic_qno,	    none, none, Setup Active Queue),
	NLS_OPT_ITEM(cpulb_info,	    none, none, CPU LB Info),

#ifdef ENABLE_ESP_TEST
	NLS_OPT_ITEM(esp,				none, none, ESP),
	NLS_OPT_ITEM(esp_drop,			none, none, ESP Drop Count),
#endif

	NLS_OPT_ITEM(hsf_lev_nud,		none, none, 노출 레벨),
	NLS_OPT_ITEM(hsf_lev_sex,		none, none, 성행위 레벨),
	NLS_OPT_ITEM(hsf_lev_vio,		none, none, 폭력 레벨),
	NLS_OPT_ITEM(hsf_lev_lan,		none, none, 언어 레벨),
	NLS_OPT_ITEM(hsf_lev_ill,		none, none, 불법 레벨),
	NLS_OPT_ITEM(hsf_lev_hrm,		none, none, 음주 레벨),
	NLS_OPT_ITEM(hsf_lev_juv,		none, none, 청소년 차단),
	NLS_OPT_ITEM(hsf_ses_size_min,	none, none, 유해사이트 세션 최소 크기),
	NLS_OPT_ITEM(hsf_ses_size_max,	none, none, 유해사이트 세션 최대 크기),
	NLS_OPT_ITEM(hsf_all_chk_pics,	none, none, 모든 패킷에 PICS 검사),
	NLS_OPT_ITEM(hsf_remove_gzip,	none, none, gzip 옵션 제거),
	NLS_OPT_ITEM(hsf_content_type_chk, none, none, Content-Type 검사),

	NLS_OPT_ITEM(ips_use_policy,	none, none, IPS 정책 사용),

	NLS_OPT_ITEM(l2fw_macip_cnt,	none, none, 탐지된 MAC/IP 목록 수),
	NLS_OPT_ITEM(l2fw_flood_interval, none, none, ARP Flooding 탐지 주기(초)),
	NLS_OPT_ITEM(l2fw_flood_count,	none, none, ARP Flooding 탐지 임계치(패킷수)),
	NLS_OPT_ITEM(l2fw_max_per_host_count, none, none, 호스트별 1초당 ARP 패킷 최대 허용 횟수),
	NLS_OPT_ITEM(l2fw_nic_list,  	none, none, 감시 인터페이스),
	NLS_OPT_ITEM(l2fw_log_interval, none, none, 로그 저장 주기(초)),
	NLS_OPT_ITEM(l2fw_flood_status, none, none, ARP Flooding 상태),
	NLS_OPT_ITEM(l2fw_flood_pkt_cnt, none, none, ARP Flooding 주기동안 수신한 ARP 패킷 수),

	NLS_OPT_ITEM(mangle_show, 		none, none, 패킷 데이터 변경 항목 보기),
	NLS_OPT_ITEM(mem_usage,			none, none, 메모리 사용량 조회),
	NLS_OPT_ITEM(nat_free_port,		none, none, NAT Port 사용량 조회),
	NLS_OPT_ITEM(arp_filter,		none, OFF/ON, 자신의 인터페이스에 할당된 IP에 대해서만 ARP 응답),
	NLS_OPT_ITEM(arp_static,		none, OFF/ON, ARP 테이블에 PERMANENT로 등록(성능측정시에만 사용)),
	NLS_OPT_ITEM(route_mode,		none, none, 라우팅 운영 모드 (0:Flow Base, 1:Source Base, 2:Packet Base)),
	NLS_OPT_ITEM(softlockup_time,	none, none, Deadlock Detection Time),
	NLS_OPT_ITEM(pkt_save_interval,	none, none, 프로토콜 오용 패킷 저장 간격),
	NLS_OPT_ITEM(rcc_update_arp,	none, none, ARP Entry 갱신),

	NLS_OPT_ITEM(sem_max_bucket,	none, none, 세션 버킷 수),
	NLS_OPT_ITEM(session_cnt,		none, none, 현재 세션 수 조회),
	NLS_OPT_ITEM(session_cnt_mine,	none, none, 자신의 세션 수 조회),
	NLS_OPT_ITEM(session_cnt_remote,none, none, 원격지 세션 수 조회),
	NLS_OPT_ITEM(session_cnt_local,	none, none, 로컬 세션 수 조회),
	NLS_OPT_ITEM(session_state,		none, none, 세션 상태),
	NLS_OPT_ITEM(session_max,		none, none, 최대 세션 수),
	NLS_OPT_ITEM(session_magic,		none, none, 임시 세션수),
	NLS_OPT_ITEM(session_reroute_all,none,none, 세션의 라우팅 캐쉬 삭제),
	NLS_OPT_ITEM(session_max_warn,	none, none, 최대 세션 경고 비율(%)),

	NLS_OPT_ITEM(show_os_version,	none, none, 원래의 OS 버젼정보 출력),

	NLS_OPT_ITEM(sme,		    	none, none, SME (0:ACSM, 1:MREG)),
	NLS_OPT_ITEM(sme_version,	   	none, none, SME Version),
	NLS_OPT_ITEM(sme_max_match,		none, none, 최대 패턴 매칭 수),
	NLS_OPT_ITEM(sme_sg_min_len,	none, none, IPS 패턴 최소 길이),
	NLS_OPT_ITEM(sme_state_flush,	none, none, 패턴 매칭 통계 정보 초기화),
	NLS_OPT_ITEM(sme_uri_decode,	none, none, HTTP URI Decode 사용),
	NLS_OPT_ITEM(sme_offset_log,	none, none, 패턴 탐지 옵셋 로그 출력),

	NLS_OPT_ITEM(syn_proxy_timeout,	none, none, SYN Proxy 동작 시간),
	NLS_OPT_ITEM(syn_proxy_max_pps,	none, none, SYN Proxy에서 최대 허용 패킷 수),
	NLS_OPT_ITEM(tcp_max_assemble,	none, none, 최대 TCP 재조합 수),
	NLS_OPT_ITEM(tcp_max_asbuf,		none, none, TCP 재조합 최대 크기 ),
			                    
	NLS_OPT_ITEM(dsync_cmd,         none, none, DSYNC 명령어),
	NLS_OPT_ITEM(dsync_show_conf,   none, none, DSYNC 설정 조회),
	NLS_OPT_ITEM(dsync_show_state,	none, none, DSYNC 상태 조회),
	NLS_OPT_ITEM(dsync_node_cnt,	none, none, 노드 수 조회),
	NLS_OPT_ITEM(dsync_hb,	        none, none, HB 전송),

	NLS_OPT_ITEM(ilb_show_conf,     none, none, iLink LB 설정 조회),

	NLS_OPT_ITEM(version,			none, none, WISE Version),
			                    
#endif

	// end of option nls

	// normal nls

	// end of normal nls

};

#if 0
nls_msg_t eng[NLS_ID_MAX] = {
	// Option Table NLS MSG

	//
	NLS_OPT_ITEM(ahot,				none, none, Enable Authentication of TCP),
	NLS_OPT_ITEM(ahot_host,			none, none, Enable Authentication of TCP by Host),
	NLS_OPT_ITEM(all_allow_log,		FW, none, Enable Logging all allowed packets),
	NLS_OPT_ITEM(all_drop_log,		FW, none, Enable Logging all dropped packets),
	NLS_OPT_ITEM(all_drop_log_skip_by_seq, none, none, Do not save log of same TCP SEQ),
	NLS_OPT_ITEM(info_log_interval, FW, OFF/interval, Minimum interval of intermediate session log (sec, 0:no log, minimum:10)),
	NLS_OPT_ITEM(bl,				none, none, Enable Blacklist),
	NLS_OPT_ITEM(dns,				none, none, Enable DNS Monitor),
	NLS_OPT_ITEM(frag,	            none, none, Enable Reassembling Fragmentation pkt),
	NLS_OPT_ITEM(frag_pkt_min_len,	none, none, Enable Checking Fragmentation Length),
	NLS_OPT_ITEM(hsf,				none, none, Enable Harm Site Filter),
	NLS_OPT_ITEM(hostauth,			none, none, Enable Host Authentication),
	NLS_OPT_ITEM(ips,				none, none, Enable IPS),
	NLS_OPT_ITEM(ipv6,				none, none, Enable IPv6 Firewall),
	NLS_OPT_ITEM(l2fw,	      		none, none, Enable L2 Firewall),
	NLS_OPT_ITEM(l2fw_flt,     		none, none, L2 Firewall Operation Mode),
	NLS_OPT_ITEM(l2fw_flood,		L2FW, OFF/ON, ARP Flooding Prevention),
	NLS_OPT_ITEM(l2fw_spoof,		L2FW, OFF/ON, MAC/IP Conflict Prevention),
	NLS_OPT_ITEM(mangle,			none, none, Mangle packet),
	NLS_OPT_ITEM(mon_nic,			none, none, Enable Monitoring NIC),
	NLS_OPT_ITEM(mllb,				none, none, Enable Multiline LoadBalancing),
	NLS_OPT_ITEM(nat_arp_proxy,		none, none, Enable ARP proxy for NAT IP),
	NLS_OPT_ITEM(nls,				none, none, Nataional Langulage Set (0:KOR, 1:ENG, 2:JP, 3:CH)),
	NLS_OPT_ITEM(ilb,				none, none, LB through InterLink),
	NLS_OPT_ITEM(panomaly,			none, none, Enable Protocol Anomaly),
	NLS_OPT_ITEM(psd,				none, none, Enable Portscan Detection),
	NLS_OPT_ITEM(pkt_limit,			none, none, Enable BPS/PPS check),
	NLS_OPT_ITEM(fast_route,		none, none, Enable Fast routing),
	NLS_OPT_ITEM(rtd,				none, none, Enable RealTime DDOS Detection),
	NLS_OPT_ITEM(rt_type_zero,		none, none, type zero routing header),
	NLS_OPT_ITEM(ses_clear,			none, none, 방화벽 정책 적용시 세션 삭제 (0:OFF, 1:AUTO, 2:ALL, 3:NAT)),
	NLS_OPT_ITEM(strict_land_attack,none, none, 엄격한 Land Attack 방어),
	NLS_OPT_ITEM(syn_only,			none, none, Enable Creating TCP session with a only syn flag),
	NLS_OPT_ITEM(syn_proxy,			none, none, Enable SYN Proxy),
	NLS_OPT_ITEM(tcp_assem,			none, none, Enable TCP Rassembling),
	NLS_OPT_ITEM(tcp_mss_hack,		none, none, Enable TCP MSS Hack),
	NLS_OPT_ITEM(tg,				none, none, Enable TrustGuard DDOS Prevent),
	NLS_OPT_ITEM(url,				none, none, Enable URL Filter),
	NLS_OPT_ITEM(wst,				none, none, Enable WISE Statistics),
	NLS_OPT_ITEM(webmail,			none, none, Enable Web Mail Filter),
	NLS_OPT_ITEM(dsync,				none, none, Enable Data Sync),
	NLS_OPT_ITEM(rcc,				none, none, Enable Routing Cache Control),
	NLS_OPT_ITEM(drop_page,			none, none, Enable Drop page),

	//
	NLS_OPT_ITEM(ahot_cnt,			none, none, Show Current AHOT Node Count),
	NLS_OPT_ITEM(age_interval,		none, none, Interval to age wise components),
	NLS_OPT_ITEM(bl_btime,			none, none, Blocking time(seconds) of Blacklist),
	NLS_OPT_ITEM(bl_log,			none, none, Class of the Drop Log in Blacklist (1:Per PKT, 2:Per SEC)),
	NLS_OPT_ITEM(bl_log_param,		none, none, Blacklist Drop Log Parameter),
	NLS_OPT_ITEM(current_time,		none, none, Current System Time),
	NLS_OPT_ITEM(frag_pkt_drop_cnt,	none, none, Drop Count of Fragmentation Pkt),

	NLS_OPT_ITEM(cpulb,				none, none, Enable CPU Loadbalancer),
	NLS_OPT_ITEM(cpulb_weight,		none, none, CPU Weight), 
	NLS_OPT_ITEM(cpulb_nic,		    none, none, NIC list for CPU LB),
	NLS_OPT_ITEM(cpulb_nic_qno,	    none, none, Setup Active Queue),
	NLS_OPT_ITEM(cpulb_info,    	none, none, CPU LB Info),

#ifdef ENABLE_ESP_TEST
	NLS_OPT_ITEM(esp,				none, none, Enable ESP ),
	NLS_OPT_ITEM(esp_drop,			none, none, ESP Drop Count),
#endif

	NLS_OPT_ITEM(hsf_lev_nud,		none, none, 노출 레벨),
	NLS_OPT_ITEM(hsf_lev_sex,		none, none, 성행위 레벨),
	NLS_OPT_ITEM(hsf_lev_vio,		none, none, 폭력 레벨),
	NLS_OPT_ITEM(hsf_lev_lan,		none, none, 언어 레벨),
	NLS_OPT_ITEM(hsf_lev_ill,		none, none, 불법 레벨),
	NLS_OPT_ITEM(hsf_lev_hrm,		none, none, 음주 레벨),
	NLS_OPT_ITEM(hsf_lev_juv,		none, none, 청소년 차단),
	NLS_OPT_ITEM(hsf_ses_size_min,	none, none, 유해사이트 세션 최소 크기),
	NLS_OPT_ITEM(hsf_ses_size_max,	none, none, 유해사이트 세션 최대 크기),
	NLS_OPT_ITEM(hsf_all_chk_pics,	none, none, 모든 패킷에 PICS 검사),
	NLS_OPT_ITEM(hsf_remove_gzip,	none, none, gzip 옵션 제거),
	NLS_OPT_ITEM(hsf_content_type_chk, none, none, Check Content-Type),

	NLS_OPT_ITEM(ips_use_policy,	none, none, Enable IPS Policy),

	NLS_OPT_ITEM(l2fw_macip_cnt,	none, none, IP/MAC list count),
	NLS_OPT_ITEM(l2fw_flood_interval,none, none, ARP Flooding detection interval(Sec)),
	NLS_OPT_ITEM(l2fw_flood_count,	none, none, ARP Flooding detection threshold(patckt count)),
	NLS_OPT_ITEM(l2fw_max_per_host_count, none, none, 호스트별 1초당 ARP 패킷 최대 허용 횟수),
	NLS_OPT_ITEM(l2fw_nic_list,  	none, none, Monitoring interface),
	NLS_OPT_ITEM(l2fw_log_interval, none, none, Log save interval(Sec)),
	NLS_OPT_ITEM(l2fw_flood_status,	none, none, ARP Flooding status),
	NLS_OPT_ITEM(l2fw_flood_pkt_cnt,none, none, ARP Flooding 주기동안 수신한 ARP 패킷 수),

	NLS_OPT_ITEM(mangle_show,		none, none, 패킷 데이터 변경 항목 보기),
	NLS_OPT_ITEM(mem_usage,			none, none, Show NAT Port usage),
	NLS_OPT_ITEM(nat_free_port,		none, none, NAT Port 사용량 조회),
	NLS_OPT_ITEM(arp_filter,		none, OFF/ON, 자신의 인터페이스에 할당된 IP에 대해서만 ARP 응답),
	NLS_OPT_ITEM(arp_static,		none, OFF/ON, PERMANENT ARP entry in ARP table(only for performanc test)),
	NLS_OPT_ITEM(route_mode,		none, none, Routing Mode (0:Flow Base, 1:Source Base, 2:Packet Base)),
	NLS_OPT_ITEM(softlockup_time,	none, none, Deadlock Detection Time),
	NLS_OPT_ITEM(pkt_save_interval,	none, none, Packet save Interval for Protocol Anomaly),
	NLS_OPT_ITEM(rcc_update_arp,	none, none, Enable Updating ARP Entry),

	NLS_OPT_ITEM(sem_max_bucket,	none, none, Bucket size of the session),
	NLS_OPT_ITEM(session_cnt,		none, none, Show Session Count of all),
	NLS_OPT_ITEM(session_cnt_mine,	none, none, Show Session Count of mine),
	NLS_OPT_ITEM(session_cnt_remote,none, none, Show Session Count of remote),
	NLS_OPT_ITEM(session_cnt_local,	none, none, Show Session Count of local),
	NLS_OPT_ITEM(session_state,		none, none, Show session state),
	NLS_OPT_ITEM(session_max,		none, none, Max Count of Session),
	NLS_OPT_ITEM(session_magic,		none, none, Count of temporary session),
	NLS_OPT_ITEM(session_reroute_all,none,none, Flush route cache of the sessions),
	NLS_OPT_ITEM(session_max_warn,	none, none, 최대 세션 경고 비율(%)),

	NLS_OPT_ITEM(show_os_version,   none, none, Show orignal OS Version),

	NLS_OPT_ITEM(sme,		    	none, none, SME (0:ACSM, 1:MREG)),
	NLS_OPT_ITEM(sme_version,	   	none, none, SME Version),
	NLS_OPT_ITEM(sme_max_match,		none, none, Max matched Count of SME),
	NLS_OPT_ITEM(sme_sg_min_len,	none, none, Min Length of Signature),
	NLS_OPT_ITEM(sme_state_flush,	none, none, Flush Statistics of SME),
	NLS_OPT_ITEM(sme_uri_decode,	none, none, HTTP URI Decode 사용),
	NLS_OPT_ITEM(sme_offset_log,	none, none, Log signature matching offset),

	NLS_OPT_ITEM(syn_proxy_timeout,	none, none, SYN Proxy 동작 시간),
	NLS_OPT_ITEM(syn_proxy_max_pps,	none, none, SYN Proxy에서 최대 허용 패킷 수),
	NLS_OPT_ITEM(start_time,		none, none, Starting Time of the WISE),
	NLS_OPT_ITEM(tcp_max_assemble,	none, none, Max TCP Assemble Count),
	NLS_OPT_ITEM(tcp_max_asbuf,		none, none, Max TCP Assemble Buffer size),

	NLS_OPT_ITEM(dsync_cmd,         none, none, Inject CMD into DSYNC),
	NLS_OPT_ITEM(dsync_show_conf,   none, none, Show DSYNC Config),
	NLS_OPT_ITEM(dsync_show_state,	none, none, Show DSYNC state),
	NLS_OPT_ITEM(dsync_node_cnt,	none, none, Show Joined Node Count),
	NLS_OPT_ITEM(dsync_hb,	        none, none, Send HB Message),

	NLS_OPT_ITEM(ilb_show_conf,     none, none, Show iLink LB Config),

	NLS_OPT_ITEM(version,			none, none, WISE Version),
			                    
	NLS_OPT_ITEM(timeout_udp,		none, none, UDP Timeout),
	NLS_OPT_ITEM(timeout_udp_reply,	none, none, UDP Reply Timeout),
	NLS_OPT_ITEM(timeout_icmp,		none, none, ICMP ECHO REQ Timeout),
	NLS_OPT_ITEM(timeout_icmp_reply,none, none, ICMP Reply Timeout),
	NLS_OPT_ITEM(timeout_unknown,	none, none, Unknown protocol Timeout),

	NLS_OPT_ITEM(drop_tcp_oow,		none, none, Drop TCP Out of Window),
	NLS_OPT_ITEM(timeout_tcp,		none, none, TCP EST Timeout),
	NLS_OPT_ITEM(timeout_syn_sent,	none, none, SYN SENT Timeout),
	NLS_OPT_ITEM(timeout_syn_rcv,	none, none, SYN RECV Timeout),
	NLS_OPT_ITEM(timeout_fin_wait,	none, none, FIN WAIT Timeout),
	NLS_OPT_ITEM(timeout_close_wait,none, none, CLOSE WAIT Timeout),
	NLS_OPT_ITEM(timeout_last_ack,	none, none, LAST ACK Timeout),
	NLS_OPT_ITEM(timeout_time_wait,	none, none, TIME WAIT Timeout),
	NLS_OPT_ITEM(timeout_close,		none, none, CLOSE Timeout),
	NLS_OPT_ITEM(timeout_max_retrans, none, none, MAX RETRANS Timeout),

	// end of option nls

	// normal nls

	// end of normal nls
};

/* *INDENT-ON* */





/////////////////////////////////////////////
#endif

nls_msg_t *all_nls[] = {
	kor,
	//eng,

	NULL
};




//////////////////////////////////////////////

char* nls_get_msg(uint32_t id)
{
	nls_msg_t *nls;
	uint32_t idx = GET_OPT_VALUE(nls);

	if (idx >= (sizeof(all_nls)/sizeof(nls_msg_t*)))
		idx = 0;

	nls = all_nls[idx];

	return nls[id].msg;
}

char* nls_get_group(uint32_t id)
{
	nls_msg_t *nls;
	uint32_t idx = GET_OPT_VALUE(nls);

	if (idx >= (sizeof(all_nls)/sizeof(nls_msg_t*)))
		idx = 0;

	nls = all_nls[idx];

	return nls[id].group;
}

char* nls_get_value_list(uint32_t id)
{
	nls_msg_t *nls;
	uint32_t idx = GET_OPT_VALUE(nls);

	if (idx >= (sizeof(all_nls)/sizeof(nls_msg_t*)))
		idx = 0;

	nls = all_nls[idx];

	return nls[id].val_list;
}

