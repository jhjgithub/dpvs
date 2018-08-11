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
#include <json-c/json.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>

#define _BSD_SOURCE
#include <arpa/inet.h>

#include <ns_typedefs.h>
#include <ioctl_policy.h>
#include <sec_policy.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>
#include <nat.h>
#include <action.h>

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>
#include <parse_policy_json.h>
#include <io.h>

#define IFACE_IDX_MAX 	UCHAR_MAX

// https://json-c.github.io/json-c/json-c-0.10/doc/html/json__object_8h.html

typedef  struct json_object jobj_t;

void parse_ip_range(range128_t *r, jobj_t *j)
{
	jobj_t *i1 = NULL, *i2 = NULL;
	char *p1 = NULL, *p2 = NULL;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		p1 = (char *)json_object_get_string(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		p2 = (char *)json_object_get_string(i2);
	}

	r->min = p1 ? ntohl(inet_addr(p1)) : 0;
	r->max = p2 ? ntohl(inet_addr(p2)) : 0;
	if (r->max == 0) {
		r->max = (uint32_t)(~0);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint32_range(range32_t *r, jobj_t *j)
{
	jobj_t *i1 = NULL, *i2 = NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint32_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint32_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint16_range(range16_t *r, jobj_t *j)
{
	jobj_t *i1 = NULL, *i2 = NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint16_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint16_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint8_range(range8_t *r, jobj_t *j)
{
	jobj_t *i1 = NULL, *i2 = NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint8_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint8_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_action(sec_policy_t *secp, jobj_t *j)
{
	char *p = NULL;

	p = (char *)json_object_get_string(j);

	if (strcmp(p, "allow") == 0) {
		secp->action |= ACT_ALLOW;
	}
	else if (strcmp(p, "drop") == 0) {
		secp->action |= ACT_DROP;
	}
	else if (strcmp(p, "snat") == 0) {
		secp->action |= ACT_SNAT;
	}
}

void parse_state(sec_policy_t *secp, jobj_t *j)
{
	char *p;

	p = (char *)json_object_get_string(j);

	if (strcmp(p, "enable") == 0) {
	}
	else {
		secp->action |= ACT_DISABLE;
	}
}

int parse_nat_type(nat_policy_t *natp, jobj_t *j)
{
	char *p;

	p = (char *)json_object_get_string(j);

	if (strcmp(p, "snat_napt") == 0) {
		natp->flags |= NATF_SNAT_NAPT;
	}
	else if (strcmp(p, "snat_masking") == 0) {
		natp->flags |= NATF_SNAT_MASKING;
	}
	else if (strcmp(p, "snat_hash") == 0) {
		natp->flags |= NATF_SNAT_HASH;
	}
	else if (strcmp(p, "dnat_redir") == 0) {
		natp->flags |= NATF_DNAT_RDIR;
	}
	else if (strcmp(p, "dnat_local_redir") == 0) {
		natp->flags |= NATF_DNAT_LRDIR;
	}
	else {
		printf("Unknown NAT type: %s \n", p);
		return -1;
	}

	return 0;
}

int parse_nat_option(nat_policy_t *natp, jobj_t *jopt)
{
	char *p;

	int arr_len = json_object_array_length(jopt);

	if (arr_len < 1) {
		return 0;
	}

	for (int i = 0; i < arr_len; i++) {
		jobj_t *j;

		j = json_object_array_get_idx(jopt, i);

		if (j == NULL) {
			continue;
		}

		p = (char *)json_object_get_string(j);

		if (strcmp(p, "arp_proxy") == 0) {
			natp->flags |= NATF_ARP_PROXY;
		}
		else if (strcmp(p, "dynamic_ip") == 0) {
			natp->flags |= NATF_DYNAMIC_IP;
		}
		else {
			printf("Unknown NAT option: %s \n", p);
		}
	}

	return 0;
}

uint32_t parse_nic_index(jobj_t *j_nic)
{
	uint32_t ifidx = IFACE_IDX_MAX;
	int rc;

	char *ifname = (char *)json_object_get_string(j_nic);

	if (ifname && strcmp(ifname, "any") != 0) {
		rc = nsctl_get_iface_idx(ifname, (int*)&ifidx);

		if (rc != 0) {
			ifidx = IFACE_IDX_MAX;
		}
	}

	return ifidx;
}

void parse_nic_range(range32_t *r, jobj_t *j)
{
	jobj_t *i1 = NULL, *i2 = NULL;

	r->min = 0;
	r->max = IFACE_IDX_MAX;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = parse_nic_index(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = parse_nic_index(i2);
	}

	// XXX: min 값을 조정하지 않으면 hypersplit build시 에러 발생
	if (r->min == IFACE_IDX_MAX) {
		r->min = 0;
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

int parse_nat(jobj_t *j_nat, nat_policy_t *n)
{
	jobj_t *j;
	int ret;

	memset(n, 0, sizeof(nat_policy_t));

	if (!json_object_object_get_ex(j_nat, "type", &j)) {
		goto ERR;
	}
	ret = parse_nat_type(n, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (!json_object_object_get_ex(j_nat, "option", &j)) {
		goto ERR;
	}
	ret = parse_nat_option(n, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (json_object_object_get_ex(j_nat, "nic", &j)) {
		n->iface_idx = parse_nic_index(j);
	}
	//json_object_put(j);

	if (!json_object_object_get_ex(j_nat, "nat_ip", &j)) {
		goto ERR;
	}
	parse_ip_range((range128_t *)&n->nip, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (!json_object_object_get_ex(j_nat, "nat_port", &j)) {
		goto ERR;
	}
	parse_uint16_range((range16_t *)&n->nport, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	return 0;

ERR:
	return -1;
}

void parse_nat_policy(sec_policy_t *secp, jobj_t *j, nat_policy_t *np, int *used_np)
{
	jobj_t *j_nat;

	if (json_object_object_get_ex(j, "snat", &j_nat)) {
		if (parse_nat(j_nat, &np[*used_np]) == 0) {
			*used_np = 0x01;
		}

		//json_object_put(j_nat);
	}

	if (json_object_object_get_ex(j, "dnat", &j_nat)) {
		if (parse_nat(j_nat, &np[*used_np]) == 0) {
			*used_np = *used_np | 0x02;
		}

		//json_object_put(j_nat);
	}
}

int parse_firewall_policy(sec_policy_t *secp, jobj_t *j_fwp, nat_policy_t *np, int *used_np)
{
	jobj_t *j;
	char *p;

	if (!json_object_object_get_ex(j_fwp, "desc", &j)) {
		return -1;
	}

	p = (char *)json_object_get_string(j);
	if (p) {
		strncpy(secp->desc, p, 63);
	}
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "src_ip", &j)) {
		return -1;
	}
	parse_ip_range(&secp->range.src, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "dst_ip", &j)) {
		return -1;
	}
	parse_ip_range(&secp->range.dst, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "src_port", &j)) {
		return -1;
	}
	parse_uint16_range(&secp->range.sp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "dst_port", &j)) {
		return -1;
	}
	parse_uint16_range(&secp->range.dp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "protocol", &j)) {
		return -1;
	}
	parse_uint8_range(&secp->range.proto, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "nic", &j)) {
		return -1;
	}
	parse_nic_range(&secp->range.nic, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "action", &j)) {
		return -1;
	}
	parse_action(secp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "state", &j)) {
		return -1;
	}
	parse_state(secp, j);
	//json_object_put(j);

	//////////////////////
	//natinfo

	if (json_object_object_get_ex(j_fwp, "nat_policy", &j)) {
		parse_nat_policy(secp, j, np, used_np);
		//json_object_put(j);
	}

	return 0;
}

int load_json_policy(jobj_t *j_fw_root, policy_json_t *p, int isnat)
{
	sec_policy_t *secp = NULL, *f;
	nat_policy_t *np = NULL;
	int sz_np = 0, cur_np = 0, used_tmp_np=0;

	int arr_len = json_object_array_length(j_fw_root);

	if (arr_len < 1) {
		printf("No Firewall Policy: %d \n", arr_len);

		return -1;
	}

	secp = calloc(arr_len, sizeof(sec_policy_t));

	if (secp == NULL) {
		return -1;
	}

	if (isnat) {
		sz_np = arr_len;

		np = calloc(sz_np, sizeof(nat_policy_t));
		if (np == NULL) {
			goto ERR;
		}

		cur_np = 0;
	}

	nat_policy_t np_tmp[2];

	for (int i = 0; i < arr_len; i++) {
		jobj_t *j;

		f = &secp[i];
		f->rule_id = i + 1;
		j = json_object_array_get_idx(j_fw_root, i);

		//printf("secp[%d]: %s \n", i, json_object_get_string(j));

		if (isnat) {
			used_tmp_np = 0;
			if (parse_firewall_policy(f, j, np_tmp, &used_tmp_np)) {
				goto ERR;
			}

			// reset
			f->nat_policy_id[0] = UINT_MAX;
			f->nat_policy_id[1] = UINT_MAX;

			if (used_tmp_np & 0x01) {
				if ((sz_np - cur_np) < 1) {
					sz_np *= 2;
					np = realloc(np, sz_np *  sizeof(nat_policy_t));
				}

				memcpy(&np[cur_np], &np_tmp[0], sizeof(nat_policy_t));

				f->nat_policy_id[0] = cur_np;
				cur_np ++;
			}

			if (used_tmp_np & 0x02) {
				if ((sz_np - cur_np) < 1) {
					sz_np *= 2;
					np = realloc(np, sz_np *  sizeof(nat_policy_t));
				}

				memcpy(&np[cur_np], &np_tmp[1], sizeof(nat_policy_t));

				f->nat_policy_id[1] = cur_np;
				cur_np ++;
			}
		}
		else if (parse_firewall_policy(f, j, NULL, NULL)) {
			goto ERR;
		}
	}

	if (isnat) {
		p->sec_policy[1] = secp;
		p->num_sec_policy[1] = arr_len;
		
		p->nat_policy = np;
		p->num_nat_policy = cur_np;
	}
	else {
		p->sec_policy[0] = secp;
		p->num_sec_policy[0] = arr_len;
	}

	return 0;

ERR:
	if (secp) {
		free(secp);
	}
	
	if (np) {
		free(np);
	}

	return -1;
}

int parse_policy_json(policy_json_t *p, char *fname)
{
	enum json_type type;
	int f = -1;
	void *data = NULL;
	struct stat sb;

	f = open(fname, O_RDONLY);
	if (f == -1) {
		printf("Cannot open file: %s \n", fname);
		return -1;
	}

	if (fstat(f, &sb) == -1) {
		printf("Cannot read file info: %s \n", fname);
		goto END;
	}

	data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, f, 0);
	if (data == MAP_FAILED) {
		printf("mmap error with %s \n", fname);
		goto END;
	}

	json_object *j_root = json_tokener_parse(data);

	if (j_root == NULL) {
		printf("cannot parse json file: %s \n", fname);
		goto END;
	}

	///////////////////////////
	jobj_t *j_id = NULL, *j_ver = NULL, *j_desc = NULL;
	jobj_t *j_policy = NULL, *j_fw = NULL, *j_nat = NULL;

	json_object_object_get_ex(j_root, "version", &j_ver);
	json_object_object_get_ex(j_root, "id", &j_id);
	json_object_object_get_ex(j_root, "desc", &j_desc);

	printf("ver:%s, id: %s, desc: %s \n",
		   json_object_get_string(j_ver),
		   json_object_get_string(j_id),
		   json_object_get_string(j_desc));

	//json_object_put(j_ver);
	//json_object_put(j_id);
	//json_object_put(j_desc);

	///////////////////////////
	if (!json_object_object_get_ex(j_root, "security_policy", &j_policy)) {
		printf("No Policy \n");
		goto END;
	}

	///////////////////////////////////////////////////
	// Firewall
	if (!json_object_object_get_ex(j_policy, "firewall", &j_fw)) {
		printf("No Firewall Policy \n");
		goto END;
	}

	//printf("policy: %s \n", json_object_get_string(j_policy));

	type = json_object_get_type(j_fw);
	if (type != json_type_array) {
		printf("Wrong Firewall Policy \n");
		goto END;
	}

	if (json_object_array_length(j_fw) < 1) {
		printf("No Firewall Policy \n");
		goto END;
	}

	load_json_policy(j_fw, p, 0);

	//json_object_put(j_fw);

	///////////////////////////////////////////////////
	// NAT
	if (json_object_object_get_ex(j_policy, "nat", &j_nat)) {
		//printf("policy: %s \n", json_object_get_string(j_policy));

		type = json_object_get_type(j_nat);

		if (type != json_type_array || json_object_array_length(j_nat) < 1) {
			printf("Wrong NAT Policy \n");
		}
		else {
			load_json_policy(j_nat, p, 1);
		}

		//json_object_put(j_nat);
	}

	printf("sec_policy:fw=%d:nat=%d, nat_policy=%d,  \n", p->num_sec_policy[0], p->num_sec_policy[1], p->num_nat_policy);

END:

	json_object_put(j_root);

	if (data != NULL) {
		munmap(data, sb.st_size);
	}

	if (f != -1) {
		close(f);
	}

	return 0;
}

int free_policy_json(policy_json_t *p)
{
	if (p->sec_policy[0]) {
		free(p->sec_policy[0]);
	}

	if (p->sec_policy[1]) {
		free(p->sec_policy[1]);
	}

	if (p->nat_policy) {
		free(p->nat_policy);
	}

	return 0;
}
