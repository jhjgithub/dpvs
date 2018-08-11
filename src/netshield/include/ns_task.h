#ifndef __NETSHIELD_TASK_H__
#define __NETSHIELD_TASK_H__

// type of ns_task_t.flags
#define TASK_FLAG_ICMPERR			0x00000001
#define TASK_FLAG_REQ				0x00000002
#define TASK_FLAG_NEW_SESS			0x00000004
#define TASK_FLAG_TCP_ASSEMBLE		0x00000008
#define TASK_FLAG_SYNP_OK 			0x00000010 // syn proxy에서 검증이 완료된 패킷임
#define TASK_FLAG_MAGIC_SESS		0x00000020 // matched the magic session
#define TASK_FLAG_HOOK_LOCAL_OUT    0x00000100 
#define TASK_FLAG_HOOK_POST_ROUTING 0x00000200 
#define TASK_FLAG_IN_THREAD         0x00000400 // Thread에서 실행중이다.
#define TASK_FLAG_SIMPKT          	0x00000800 // simulated packet

#define IS_IN_THREAD(nstask)       (nstask->flags & TASK_FLAG_IN_THREAD)


#include <ipv4.h>
#include <skey.h>

struct session_s;
struct rte_mbuf;

typedef int (*OKFN)(struct rte_mbuf *mbuf);

////////////////////////////////////////

// 실행될 명령어가 스택 구조로 저장 되어 있다.
#define MAX_CMDS		22		// byte alignment


typedef struct _cmd_queue {
	int8_t		head;			// 다음에 실행 될 command idx
	int8_t		tail;			// 다음에 추가될 idx
	uint8_t		stack[MAX_CMDS];
} __attribute__((packed, aligned(4))) nscmd_t;  // 24 bytes

/////////////////////////////////////////////////////

// 패킷을 처리 하는 동안 사용 되는 구조체
typedef struct ns_task_s {
	uint8_t		ip_hlen;	// ip header length
	uint8_t		l4_hlen; 	// l4 header length (tcp/udp/icmp)
	uint16_t	iopt; 		// IP header options, don't move because of byte alignment
	uint16_t	ip_dlen;	// ip data length
	uint16_t	l4_dlen;	// l4 data length
	
	char		*l4_data;	// l4 data pointer; 
	// 24

	nscmd_t		cmd; 	// 24
	skey_t 		skey; 	// 44

	uint32_t	flags;  // 4

	mpolicy_t 	mp_fw; 	// 16
	mpolicy_t 	mp_nat; // 16

	struct session_s *si;// 8
	int 		hook;
    void 		*in_port;
	void 		*out_port;
	OKFN		cb_okfn; 	 // 8

	//void		*smeres;
	char 		topt[12]; 	// topt_t

}__attribute__((packed, aligned(4)))  ns_task_t;

//#define NS_TASK_SIZE 		256  	// 임시로 크게 정의한다.
//#define NS_TASK_SIZE 		120 	// IPv4:92byte, IPv6:120 bytes

//#define NS_TASK_SIZE 256


/////////////////////////////////////////////

static inline void* ns_get_task(skb_t *skb)
{
	if (skb->priv_size == 0)
		return NULL;

	return RTE_PTR_ADD(skb, sizeof(struct rte_mbuf));
}

static inline skb_t* ns_get_skb(void *task)
{
	return (skb_t*)RTE_PTR_SUB(task, sizeof(struct rte_mbuf));
}

static inline iph_t* ns_get_ip_hdr(void *task)
{
	skb_t *skb = ns_get_skb(task);
	return ip4_hdr(skb);
}

static inline void* ns_get_transport_hdr(ns_task_t *nstask)
{
	skb_t *skb = ns_get_skb(nstask);
	return rte_pktmbuf_mtod_offset(skb, void *, nstask->ip_hlen);

    // return mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    // return rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
}

#endif
