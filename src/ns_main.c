#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "ipv4_frag.h"
#include "neigh.h"
#include "icmp.h"
#include "ns_type_defs.h"
#include "ns_dbg.h"
#include "netshield.h"
#include "ns_task.h"
#include "ns_cmds.h"


uint32_t netshield_running = 0;

DECLARE_DBG_LEVEL(9);

//////////////////////////////////////////////////////

int netshield_main(ns_task_t *nstask);

/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

void netshield_enable(void)
{
	//struct timeval tv;

	//do_gettimeofday(&tv);

	netshield_running = 1;
	//SET_OPT_VALUE(start_time, (uint32_t)tv.tv_sec);
}

void netshield_disable(void)
{
	netshield_running = 0;
}

// INET_HOOK()
int nshook_main(void *priv, struct rte_mbuf *mbuf, const struct inet_hook_state *state)
{
	int ret = INET_DROP;
	ns_task_t *nstask = ns_get_task(mbuf);

	nstask->hook = state->hook;
	nstask->cb_okfn = state->okfn;
	nstask->in_port = state->in_port;
	nstask->out_port = state->out_port;

	switch (state->hook) {
	case INET_HOOK_PRE_ROUTING:
		dbg(3, "Do PRE_ROUTING Hook");
		ret = netshield_main(nstask);
		break;

	case INET_HOOK_LOCAL_OUT:
		dbg(3, "Do LOCAL_OUT Hook");
		ret = netshield_main(nstask);
		break;

	case INET_HOOK_POST_ROUTING:
		dbg(3, "Do POST_ROUTING Hook");
		ret = INET_ACCEPT;
		break;

	default:
		ret = INET_ACCEPT;
		break;
	}

	return ret;
}

struct inet_hook_ops nshook_ops[] = {
	{
		.hook = nshook_main,
		.hooknum = INET_HOOK_PRE_ROUTING,
		.priv = NULL,
		.priority = 100,
	},
	{
		.hook = nshook_main,
		.hooknum = INET_HOOK_LOCAL_OUT,
		.priv = NULL,
		.priority = 100,
	},
};

//////////////////////////////////////////

int netshield_init(void)
{
	int ret;

	ret = ipv4_register_hooks(nshook_ops, 2);

	if (ret == EDPVS_OK) {
		ns_log("Init NetShield success");
	}
	else {
		ns_warn("Init NetShield failed: ret=%d", ret);
	}

	return EDPVS_OK;
}

int netshield_term(void)
{
	int ret;

	ns_log("Stop Netshield");

	ret = ipv4_unregister_hooks(nshook_ops, 2);

	return EDPVS_OK;
}

int netshield_main(ns_task_t *nstask)
{
	iph_t *iph;
	int ret = NS_DROP;
	skb_t *skb;

	skb = ns_get_skb(nstask);
	iph = ip4_hdr(skb);

	nscmd_setup_cmds(nstask, iph->next_proto_id);
	ret = nscmd_run_cmds(nstask);

END_MAIN:

	dbg(6, "All processing for Security is done: %s(return:%d)",
		ret == NS_DROP ? "Droped" : "Allowed", ret);

	dbg(6, "=====> End NetShield <=====");

	return ret;
}
