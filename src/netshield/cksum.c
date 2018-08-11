#include <stdio.h>
#include <stdint.h>
#include <dpdk.h>

static unsigned short from32to16(unsigned a) 
{
	unsigned short b = a >> 16; 
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n" 
	    : "=r" (b)
	    : "0" (b), "r" (a));
	return b;
}

#if 1
static uint16_t csum_fold(uint32_t sum)
{
	asm("addl %1, %0		;\n"
	    "adcl $0xffff, %0	;\n"
	    : "=r" (sum)
	    : "r" ((uint32_t)sum << 16),
	      "0" ((uint32_t)sum & 0xffff0000));
	return ( uint16_t)(~( uint32_t)sum >> 16);
}

static unsigned add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
	    "adcl $0,%0"
	    : "=r" (a)
	    : "0" (a), "rm" (b));
	return a;
}

#else
static inline __u16 csum_fold(uint32_t csum)
{
	uint32_t sum = (uint32_t)csum;
	sum += (sum >> 16) | (sum << 16);
	return ~(__u16)(sum >> 16);
}
#endif

static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (unlikely(len == 0))
		return result; 
	odd = 1 & (unsigned long) buff;
	if (unlikely(odd)) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned long zero;
			unsigned count64;
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */

			/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;
			while (count64) { 
				asm("addq 0*8(%[src]),%[res]\n\t"
				    "adcq 1*8(%[src]),%[res]\n\t"
				    "adcq 2*8(%[src]),%[res]\n\t"
				    "adcq 3*8(%[src]),%[res]\n\t"
				    "adcq 4*8(%[src]),%[res]\n\t"
				    "adcq 5*8(%[src]),%[res]\n\t"
				    "adcq 6*8(%[src]),%[res]\n\t"
				    "adcq 7*8(%[src]),%[res]\n\t"
				    "adcq %[zero],%[res]"
				    : [res] "=r" (result)
				    : [src] "r" (buff), [zero] "r" (zero),
				    "[res]" (result));
				buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8; 
			while (count) { 
				asm("addq %1,%0\n\t"
				    "adcq %2,%0\n" 
					    : "=r" (result)
				    : "m" (*(unsigned long *)buff), 
				    "r" (zero),  "0" (result));
				--count; 
					buff += 8;
			}
			result = add32_with_carry(result>>32,
						  result&0xffffffff); 

			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = add32_with_carry(result>>32, result & 0xffffffff); 
	if (unlikely(odd)) { 
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return result;
}

static inline uint32_t csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr,
					uint32_t len, uint8_t proto,
					uint32_t sum)
{
	asm("addl %1, %0	;\n"
	    "adcl %2, %0	;\n"
	    "adcl %3, %0	;\n"
	    "adcl $0, %0	;\n"
	    : "=r" (sum)
	    : "g" (daddr), "g"(saddr),
	      "g" ((len + proto) << 8), "0" (sum));
	return sum;
}

////////////////////////////////

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr, uint32_t len, uint8_t proto, uint32_t sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

uint32_t ns_cksum_partial(const void *buff, int len, uint32_t sum)
{
	return (uint32_t)add32_with_carry(do_csum(buff, len), (uint32_t)sum);
}

uint16_t ns_csum(uint32_t oldvalinv, uint32_t newval, uint16_t oldcheck)
{
	uint32_t diffs[] = { oldvalinv, newval };

	return csum_fold(ns_cksum_partial((char *)diffs, sizeof(diffs), oldcheck ^ 0xffff));
}

uint16_t ns_ip_compute_csum(const void *buff, int len)
{
	return csum_fold(ns_cksum_partial(buff,len,0));
}

