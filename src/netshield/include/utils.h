#ifndef __NS_UTILS_H__
#define __NS_UTILS_H__

struct ioctl_data_s;

// protocol description
typedef struct _desc_proto {
	uint8_t p;
	char	*name;
	char	*desc;
} desc_proto_t;

//////////////////////////////////////////////////////

//int32_t ns_copy_from_user(void *_to, void *_from, int32_t nbytes);
int32_t ns_is_loopback(ip4_t ip);
uint8_t ns_get_inv_icmp_type(uint8_t icmp_type, uint32_t fflag);
void 	ns_set_transport_header(skb_t* skb, uint8_t* iph, int32_t ip_hlen);
uint32_t ns_get_nic_ip(uint32_t if_idx);
//netdev_t* ns_get_nic_by_ip(ip4_t ip);
//dstent_t* ns_get_dst_entry(skb_t *skb);
void    ns_dec_ip(ip4_t *ip);
void    ns_inc_ip(ip4_t *ip);
desc_proto_t* ns_get_protocol_desc(uint8_t p);
char* ns_get_protocol_name(uint8_t p);
int32_t ns_is_local_address(ip4_t ip);
uint8_t ns_get_nic_idx_by_ip(ip4_t ip);
//netdev_t* ns_get_nic_by_idx(int32_t ifidx);
int32_t ns_get_nic_name_by_idx(nic_id_t idx, char *buf, int len);
int copy_expand(struct ioctl_data_s *iodata, uint8_t *src, int srclen, int extlen);
char *ns_get_verdict(int32_t verdict);

#endif
