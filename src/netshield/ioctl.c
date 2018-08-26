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
#include <options.h>
#include <ioctl_session.h>


DECLARE_DBG_LEVEL(2);

int32_t smgr_show_session_info(ioctl_data_t *iodata);
int32_t arpp_show_natip(ioctl_data_t *iodata);

//////////////////////////////////////

static int ns_get_opt_string_val(uint32_t optidx, ioctl_data_t *iodata)
{
	int rc = 0;

	switch (optidx) {
	case 0:
		rc = opt_show_table(iodata);
		if (rc != 0 && iodata->out) {
			free(iodata->out);
		}
		break;

	default:
		rc = -1;
	}

	return rc;
}

static int ns_get_opt_value(ioctl_data_t *iodata)
{
	int rc = 0;
	uint32_t optidx;
	optval_t *optval = (optval_t *)iodata->in;

	if (optval->flags & OPTVAL_FLAG_INDEX) {
		optidx = optval->optidx;
	}
	else if (optval->flags & OPTVAL_FLAG_NAME) {
		optidx = opt_get_index(optval->name);
	}
	else {
		return -1;
	}

	dbg(6, "optidx=%u", optidx);

	if (optidx >= OPT_MAX) {
		return -1;
	}

	if (optval->flags & OPTVAL_FLAG_INT) {
		int *data;
		data = rte_calloc_socket(NULL, 1, sizeof(int), 0, rte_socket_id());
		if (data == NULL) {
			return -1;
		}

		iodata->outsize = sizeof(int);
		iodata->out = (void*)data;
		*data = opt_get_val(optidx);
	}
	else if (optval->flags & OPTVAL_FLAG_STRING) {
		rc = ns_get_opt_string_val(optidx, iodata);
	}
	else {
		rc = -1;
	}

	return rc;
}

#if 0
static int ns_get_iface_idx(char *iface_name, size_t insize, void **out, size_t *outsize)
{
	int rc = 0;
	uint32_t iface_idx = 0;

	if (iface_name == NULL || insize < 1) {
		return -1;
	}

	struct netif_port *port = netif_port_get_by_name(iface_name);

	if (port == NULL) {
		return -1;
	}

	int *data;
	data = rte_calloc_socket(NULL, 1, sizeof(int), 0, rte_socket_id());
	if (data == NULL) {
		return -1;
	}

	*outsize = sizeof(int);
	*data = port->id;
	*out = data;

	return rc;
}
#endif

int ns_set_opt_value(ioctl_data_t *iodata)
{
	int rc = 0;
	uint32_t optidx;
	optval_t *optval = (optval_t*)iodata->in;

	if (optval->flags & OPTVAL_FLAG_INDEX) {
		optidx = optval->optidx;
	}
	else if (optval->flags & OPTVAL_FLAG_NAME) {
		optidx = opt_get_index(optval->name);
	}
	else {
		return -1;
	}

	dbg(6, "optidx=%u", optidx);

	if (optidx >= OPT_MAX) {
		return -1;
	}

	if (optval->flags & OPTVAL_FLAG_INT) {
		opt_set_val(optidx, optval->val);
	}
	else if (optval->flags & OPTVAL_FLAG_STRING) {
		char *data = optval->data;
		
		data[optval->len-1];

		dbg(0, "optidx=%d, len=%d, data=%s", optidx, optval->len, data);
	}
	else {
		rc = -1;
	}

	return 0;
}

static int ns_sockopt_get(sockoptid_t cmdid, const void *in, size_t insize, void **out, size_t *outsize)
{
	uint8_t *buf  = (char*)in;
	int rc = 0;
	uint32_t optidx = 0;
	ioctl_data_t iodata;

	memset(&iodata, 0, sizeof(ioctl_data_t));

	dbg(5, "cmdid=%d, insize=%lu", cmdid, insize);

	iodata.in = in;
	iodata.insize = insize;

	switch (cmdid) {
	case NSIOCTL_GET_OPT_VALUE:
		if (insize < sizeof(optval_t)) {
			return -1;
		}

		rc = ns_get_opt_value(&iodata);
		break;

	case NSIOCTL_GET_SESSION:
		if (in == NULL || insize != sizeof(ioctl_get_sess_t)) {
			return -1;
		}

		rc = smgr_show_session_info(&iodata);
		break;
	
#if 0
	case NSIOCTL_GET_IFACE_IDX:
		rc = ns_get_iface_idx((char*)in, insize, out, outsize);
		break;
#endif

	case NSIOCTL_GET_NATIP_INFO:
		rc = arpp_show_natip(&iodata);
		break;
	}

	if (rc == 0) {
		*out = (void*)iodata.out;
		*outsize = iodata.outsize;
	}
	else if (iodata.out) {
		free(iodata.out);
	}

	return rc;
}

static int ns_sockopt_set(sockoptid_t cmdid, const void *in, size_t insize) 
{
	int rc = 0;
	ioctl_data_t iodata;

	memset(&iodata, 0, sizeof(ioctl_data_t));

	dbg(6, "cmdid=%d, insize=%lu", cmdid, insize);

	iodata.in = in;
	iodata.insize = insize;

	switch (cmdid) {
	case NSIOCTL_SET_SEC_POLICY:
		rc = pmgr_apply_policy(&iodata);
		break;

	case NSIOCTL_SET_OPT_VALUE:
		if (insize < sizeof(optval_t)) {
			return -1;
		}
	
		rc = ns_set_opt_value(&iodata);
		break;

	default:
		rc = -1;
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
