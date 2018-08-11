/* bit search implementation
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Copyright (C) 2008 IBM Corporation
 * 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's bitop_find_next_bit implementation)
 *
 * Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
 * size and improve performance, 2015.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#define BITS_PER_LONG __WORDSIZE
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define MAX(a,b) \
({ __typeof__ (a) _a = (a); \
 __typeof__ (b) _b = (b); \
 _a > _b ? _a : _b; })
  
#define MIN(a,b) \
({ __typeof__ (a) _a = (a); \
 __typeof__ (b) _b = (b); \
 _a < _b ? _a : _b; })

#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define ADDR				BITOP_ADDR(addr)

//////////////////////////

static __always_inline unsigned long __ffs(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return word;
}

static __always_inline unsigned long ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

static __always_inline unsigned long __fls(unsigned long word)
{
	asm("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return word;
}

/*
 * This is a common helper function for bitop_find_next_bit and
 * bitio_find_next_zero_bit.  The difference is the "invert" argument, which
 * is XORed with each fetched word before searching it for one bits.
 */
static unsigned long _find_next_bit(const unsigned long *addr,
		unsigned long nbits, unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return MIN(start + __ffs(tmp), nbits);
}

static unsigned long 
_find_next_bit_wrap_around(const unsigned long *addr, unsigned long size, 
						   unsigned long offset, unsigned long invert)
{
	unsigned long idx;

	idx = _find_next_bit(addr, size, offset, invert);

	if (idx == size && offset > 0) {
		idx = _find_next_bit(addr, offset, 0, invert);
		if (idx == offset) {
			return size;
		}
	}

	return idx;
}

/////////////////////////////////////////////

/*
 * Find the next set bit in a memory region.
 */
unsigned long bitop_find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

unsigned long bitio_find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	return _find_next_bit(addr, size, offset, ~0UL);
}

/*
 * Find the next set bit in a memory region.
 */
unsigned long 
bitop_find_next_bit_wrap_around(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	return _find_next_bit_wrap_around(addr, size, offset, 0UL);
}

unsigned long 
bitop_find_next_zero_bit_wrap_around(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	return _find_next_bit_wrap_around(addr, size, offset, ~0UL);
}

/*
 * Find the first set bit in a memory region.
 */
unsigned long bitop_find_first_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return MIN(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}

/*
 * Find the first cleared bit in a memory region.
 */
unsigned long bitop_find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return MIN(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

unsigned long bitop_find_last_bit(const unsigned long *addr, unsigned long size)
{
	if (size) {
		unsigned long val = BITMAP_LAST_WORD_MASK(size);
		unsigned long idx = (size-1) / BITS_PER_LONG;

		do {
			val &= addr[idx];
			if (val)
				return idx * BITS_PER_LONG + __fls(val);

			val = ~0ul;
		} while (idx--);
	}
	return size;
}

void bitop_clear_bit(long nr, volatile unsigned long *addr)
{
	asm volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

void bitop_set_bit(int nr, void *addr)
{
	asm("btsl %1,%0" : "+m" (*(unsigned int *)addr) : "Ir" (nr));
}

#ifdef __BIG_ENDIAN

/* include/linux/byteorder does not support "unsigned long" type */
static inline unsigned long ext2_swab(const unsigned long y)
{
#if BITS_PER_LONG == 64
	return (unsigned long) __swab64((u64) y);
#elif BITS_PER_LONG == 32
	return (unsigned long) __swab32((uint32_t) y);
#else
#error BITS_PER_LONG not defined
#endif
}

#if !defined(find_next_bit_le) || !defined(find_next_zero_bit_le)
static unsigned long _find_next_bit_le(const unsigned long *addr,
		unsigned long nbits, unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= ext2_swab(BITMAP_FIRST_WORD_MASK(start));
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return MIN(start + __ffs(ext2_swab(tmp)), nbits);
}
#endif

#ifndef find_next_zero_bit_le
unsigned long find_next_zero_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return _find_next_bit_le(addr, size, offset, ~0UL);
}
#endif

#ifndef find_next_bit_le
unsigned long find_next_bit_le(const void *addr, unsigned
		long size, unsigned long offset)
{
	return _find_next_bit_le(addr, size, offset, 0UL);
}
#endif

#endif /* __BIG_ENDIAN */
