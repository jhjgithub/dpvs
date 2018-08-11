#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <conf/netif.h>
#include <ns_typedefs.h>
#include <ioctl_policy.h>
#include <sec_policy.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>
#include <ioctl.h>
#include <nat.h>
#include <action.h>
#include <options.h>

//#include <rule_trace.h>
//#include <hypersplit.h>
#include <rfg.h>

#include "sockopt.h"
#include <io.h>

#define IP_FMT                  "%u.%u.%u.%u"
#if defined(__LITTLE_ENDIAN)
#define IPH(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define IPH(addr)   IPN(addr)
#else
#error Not defined Endian Mode !
#endif

////////////////////////////////////////

int nsctl_send_to_daemon(sec_policy_t *secp, int num, const char *hsfile, nat_policy_t *np, int nnum)
{
	int len, slen, nlen;
	ioctl_policyset_t *ps;
	struct stat st;
	uint8_t *buf, *p;

	// calc the length of buf
	stat(hsfile, &st);

	slen = num * sizeof(sec_policy_t);
	nlen = 0;
	if (nnum) {
		nlen = nnum * sizeof(nat_policy_t);
	}

	len = sizeof(ioctl_policyset_t);
	len += st.st_size;
	len += slen;
	len += nlen;

	// alloc buf
	buf = malloc(len);
	if (buf == NULL) {
		return -1;
	}

	// save data into the buf
	ps = (ioctl_policyset_t*)buf;
	
	ps->sz_hs = st.st_size;
	ps->num_fw_policy = num;
	ps->num_nat_policy = nnum;

	p = (uint8_t*)ps->data;

	int fd = open (hsfile ,O_RDONLY);
	if (fd == -1){
		goto ERR;
	}

	//load_hypersplit(f);
	
	// copy hyersplit
	int readn = read(fd, p, st.st_size);
	if (readn != st.st_size) {
		goto ERR;
	}

	p += st.st_size;
	close(fd);
	printf("copy hs: %lu \n", st.st_size);

	// copy sec policy
	memcpy(p, secp, slen);
	p += slen;
	printf("copy sec policy: %d \n", slen);

	int cmd = NSIOCTL_SET_SEC_POLICY;

	if (nlen) {
		// copy nat policy
		memcpy(p, np, nlen);
		p += nlen;
		printf("copy nat policy: %d \n", nlen);
	}

	printf("Send data: len=%d \n", len);
	dpvs_setsockopt(cmd, buf, len);

	free(buf);

	return 0;

ERR:
	if (buf) {
		free(buf);
	}

	if (fd != -1) {
		close(fd);
	}

	return -1;
}

int nsctl_get_session(void)
{
	ioctl_get_sess_t s, *cs;
	int ret = 0;
	//int l, i;
	uint32_t sess_cnt = 0;
	size_t cs_cnt;

	ret = nsctl_get_option_int(OPT_IDX(session_cnt), (int*)&sess_cnt);

	// get the first 100 sessions
	s.start_idx = 0;
	s.num_sess = 100;
	cs = NULL;
	ret = dpvs_getsockopt(NSIOCTL_GET_SESSION, &s, sizeof(s), (void**)&cs, &cs_cnt);

	if (ret == 0 && cs_cnt > 0) {
		printf("# of Session: %u \n", cs->num_sess);
		ioctl_session_t *s, *sess = (ioctl_session_t*)&cs->data;

		for (int i = 0; i < cs->num_sess; i++) {
			s = &sess[i];

			printf("%3d:" IP_FMT ":%u -> " IP_FMT ":%u(%u) sid=%u, born=%u, timeout=%d \n",
				   i+1,
				   IPH(s->skey.src), s->skey.sp,
				   IPH(s->skey.dst), s->skey.dp, s->skey.proto,
				   s->sid,
				   s->born_time,
				   s->timeout
				  );
		}
	}

	if (cs) {
		free(cs);
	}

	return ret;
}

// return value:
// >  0: iface index
// <= 0: error
int nsctl_get_iface_idx(char *iface_name, int *value)
{
	int rc;
	size_t len = 0;
    netif_nic_ext_get_t *ext_get = NULL;

    rc = dpvs_getsockopt(SOCKOPT_NETIF_GET_PORT_EXT_INFO, 
						 iface_name, 
						 strlen(iface_name), 
						 (void **)&ext_get, &len);

    if (rc != EDPVS_OK || !ext_get || !len) {
        return rc;
	}

	*value = ext_get->port_id;
	free(ext_get);

	return rc;
}

#if 0
int nsctl_get_option_value(uint32_t cmd, const void *in, size_t inlen, void **out, size_t *outlen)
{
	return dpvs_getsockopt(cmd, in, inlen, out, outlen);
}
#endif

int nsctl_get_option_int(uint32_t optidx, int *value)
{
	int rc;
	uint32_t cmd = NSIOCTL_GET_OPT_VALUE;
	optval_t ov;

	size_t outlen=0;
	int *val;

	ov.flags = OPTVAL_FLAG_INDEX | OPTVAL_FLAG_INT;
	ov.optidx = optidx;

	rc = dpvs_getsockopt(cmd, (void*)&ov, sizeof(ov), (void**)&val, &outlen);

	if (rc == ESOCKOPT_OK && val && value) {
		*value = *val;
	}

	if (val) {
		free(val);
	}

	return rc;
}

int nsctl_get_option_int_by_name(char *name, int *value)
{
	int rc, len;
	uint32_t cmd = NSIOCTL_GET_OPT_VALUE;
	optval_t ov;

	size_t outlen=0;
	int *val;

	len = strlen(name);
	if (len > 31) {
		return -1;
	}

	ov.flags = OPTVAL_FLAG_NAME | OPTVAL_FLAG_INT;
	strcpy(ov.name, name);

	rc = dpvs_getsockopt(cmd, (void*)&ov, sizeof(ov), (void**)&val, &outlen);

	if (rc == ESOCKOPT_OK && val && value) {
		*value = *val;
	}

	if (val) {
		free(val);
	}

	return rc;
}

int nsctl_get_sting_data(int cmd, char **buf, size_t *len)
{
	return dpvs_getsockopt(cmd, NULL, 0, (void**)buf, len);
}

int nsctl_set_option_int(uint32_t optidx, int value)
{
	int rc;
	uint32_t cmd = NSIOCTL_SET_OPT_VALUE;
	optval_t ov;

	ov.flags = OPTVAL_FLAG_INDEX | OPTVAL_FLAG_INT;
	ov.optidx = optidx;
	ov.val = value;

	rc = dpvs_setsockopt(cmd, (void*)&ov, sizeof(ov));

	return rc;
}

int nsctl_set_option_int_by_name(char *name, int value)
{
	int rc, len;
	uint32_t cmd = NSIOCTL_SET_OPT_VALUE;
	optval_t ov;

	len = strlen(name);
	if (len > 31) {
		return -1;
	}

	ov.flags = OPTVAL_FLAG_NAME | OPTVAL_FLAG_INT;
	strcpy(ov.name, name);
	ov.val = value;

	rc = dpvs_setsockopt(cmd, (void*)&ov, sizeof(ov));

	return rc;
}

// optidx: 
//   0: option table
// > 0: option idx
int nsctl_get_option_string(uint32_t optidx, char **buf, size_t *len)
{
	int rc;
	uint32_t cmd = NSIOCTL_GET_OPT_VALUE;
	optval_t ov;

	ov.flags = OPTVAL_FLAG_INDEX | OPTVAL_FLAG_STRING;
	ov.optidx = optidx;

	rc = dpvs_getsockopt(cmd, &ov, sizeof(ov), (void**)buf, len);
	
	return rc;
}

int nsctl_get_option_table(char **buf, size_t *len)
{
	return nsctl_get_option_string(0, buf, len);
}

