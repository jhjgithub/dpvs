#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "ipv4_frag.h"
#include "neigh.h"
#include "icmp.h"
#include "dbg.h"
#include "netshield.h"

int nshook_pre_route(void *priv, struct rte_mbuf *mbuf, const struct inet_hook_state *state)
{
	dpvs_log(DEBUG, NETSHIELD, "Do Preroute Hook \n");
	return INET_ACCEPT;
}

int nshook_local_out(void *priv, struct rte_mbuf *mbuf, const struct inet_hook_state *state)
{
	dpvs_log(DEBUG, NETSHIELD, "Do Localout Hook \n");
	return INET_ACCEPT;
}

struct inet_hook_ops nshook_ops[] = {
	{
	.hook = nshook_pre_route,
	.hooknum = INET_HOOK_PRE_ROUTING,
	.priv = NULL,
	.priority = 100,
	},
	{
	.hook = nshook_local_out,
	.hooknum = INET_HOOK_LOCAL_OUT,
	.priv = NULL,
	.priority = 100,
	},
};

int netshield_init(void)
{
	int ret;
	
	ret = ipv4_register_hooks(nshook_ops, 2);

	if (ret == EDPVS_OK) {
		dpvs_log(INFO, NETSHIELD, "Init NetShield success \n");
	}
	else {
		dpvs_log(DEBUG, NETSHIELD, "Init NetShield failed: ret=%d \n", ret);
	}

	return EDPVS_OK;
}

int netshield_term(void)
{
	int ret;

	dpvs_log(DEBUG, NETSHIELD, "Stop Netshield \n");

	ret = ipv4_unregister_hooks(nshook_ops, 2);

	return EDPVS_OK;
}

