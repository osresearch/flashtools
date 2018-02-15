#ifndef _hexdump_h_
#define _hexdump_h_

#include <stdint.h>


extern void
hexdump(
	const uintptr_t base_offset,
	const uint8_t * const buf,
	const size_t len
);


typedef enum {
	MEM_SET,
	MEM_AND,
	MEM_OR,
} mem_op_t;


extern void
memcpy_width(
	volatile void * dest,
	const volatile void * src,
	size_t len, // in bytes
	size_t width, // in bytes, 1,2,4 or 8
	mem_op_t op
);

#endif