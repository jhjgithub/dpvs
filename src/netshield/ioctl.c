#include <stdio.h>
#include <string.h>

#include <dpdk.h>
#include <ctrl.h>
#include <ns_typedefs.h>
#include <macros.h>
//#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <ioctl.h>
#include <pmgr.h>


DECLARE_DBG_LEVEL(5);


static int ns_sockopt_get(sockoptid_t opt, const void *conf, size_t size, void **out, size_t *outsize)
{

	return 0;
}

static int ns_sockopt_set(sockoptid_t cmdid, const void *conf, size_t size) 
{
	uint8_t *buf  = (char*)conf;
	int rc = 0;

	dbg(0, "cmdid=%d, len=%lu", cmdid, size);

	switch (cmdid) {
	case NSIOCTL_SET_SEC_POLICY:
		rc = pmgr_apply_policy((uint8_t*)conf, size);
		break;

	}

	return rc;
}

static struct dpvs_sockopts route_sockopts = {
    .version        = SOCKOPT_VERSION,

    .set_opt_min    = NSIOCTL_SET_MIN,
    .set_opt_max    = NSIOCTL_SET_MAX,
    .set            = ns_sockopt_set,

    .get_opt_min    = NSIOCTL_GET_MIN,
    .get_opt_max    = NSIOCTL_GET_MAX,
    .get            = ns_sockopt_get,
};

int nsioctl_init(void)
{
	int err;

    if ((err = sockopt_register(&route_sockopts)) != EDPVS_OK)
        return err;

}

int nsioctl_term(void)
{
	int err;

    if ((err = sockopt_unregister(&route_sockopts)) != EDPVS_OK)
        return err;
}
