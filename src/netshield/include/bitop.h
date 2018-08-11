#ifndef __BITOP_H__
#define __BITOP_H__

void bitop_set_bit(int nr, void *addr);
void bitop_clear_bit(long nr, volatile unsigned long *addr);
unsigned long bitop_find_last_bit(const unsigned long *addr, unsigned long size);
unsigned long bitop_find_first_zero_bit(const unsigned long *addr, unsigned long size);
unsigned long bitop_find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long bitop_find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long bitop_find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long bitop_find_next_zero_bit_wrap_around(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long bitop_find_next_bit_wrap_around(const unsigned long *addr, unsigned long size, unsigned long offset);


#endif
