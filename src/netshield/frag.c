#include <stdio.h>
#include <dpdk.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <session.h>

#if 0
#include <net/protocol.h>
#include <include_os.h>
#include <typedefs.h>
#include <ns_task.h>
#include <ns_macro.h>
#endif

//#include <commands.h>
//#include <log.h>
//#include <extern.h>
//#include <version.h>
//#include <misc.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


///////////////////////////////////////////////////////////
// for IPv4

int32_t frag4_main(ns_task_t *nstask)
{
	skb_t *skb;
	iph_t *iph;

	// 패킷은 조합 되어서 완성된 패킷으로 반환 된다.
	// 이 부분 이후 부터는 frag 패킷이 전혀 없다.
	dbg(4, "Check fragment packet");

	skb = ns_get_skb(nstask);
	iph = ip4_hdr(skb);

	if (!ip4_is_frag(iph)) {
		return NS_ACCEPT;
	}

	int rc;

	rc = ip4_defrag(skb, IP_DEFRAG_PRE_ROUTING);

    switch (rc) {
    case EDPVS_OK:
		return NS_ACCEPT;
    case EDPVS_INPROGRESS: /* collecting fragments */
    default: /* error happened */
		return NS_STOLEN;
    }
}
