#ifndef _hexdump_h_
#define _hexdump_h_

#include <stdint.h>
#include <sys/io.h>
#include <sys/types.h>

#ifdef __PPC64__
#define MFENCE_ASM "sync"
#else
#define MFENCE_ASM "mfence"
#endif

extern void *
map_physical(
	uint64_t phys_addr,
	size_t len
);

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

extern void
copy_physical(
	uint64_t phys_addr,
	size_t len,
	volatile void *dest
);

extern void *
map_file(
	const char *name,
	uint64_t *size,
	const int readonly
);

extern uint64_t
align_up(
	uint64_t off,
	uint32_t align
);

#endif
