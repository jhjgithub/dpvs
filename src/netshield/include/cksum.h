#ifndef __CKSUM_H__
#define __CKSUM_H__

uint32_t ns_cksum_partial(const void *buff, int len, uint32_t sum);
uint16_t ns_csum(uint32_t oldvalinv, uint32_t newval, uint16_t oldcheck);
uint16_t ns_ip_compute_csum(const void *buff, int len);
uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr, uint32_t len, uint8_t proto, uint32_t sum);


#endif
