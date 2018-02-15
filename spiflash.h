/** \file
 * Routines to interface with the memory mapped SPI flash chip.
 */

#ifndef _spiflash_h_
#define _spiflash_h_


typedef struct {
	void * lpc_base;
	void * spibar;
	int verbose;
} spiflash_t;


extern int
spiflash_init(
	spiflash_t * sp,
	uint64_t pci_exbar
);


extern void
spiflash_info(
	spiflash_t * sp
);


extern uint8_t
spiflash_bios_cntl(
	spiflash_t * const sp
);


extern uint8_t
spiflash_set_bios_cntl(
	spiflash_t * const sp,
	uint8_t new_bios_cntl
);


extern void
spiflash_prr(
	spiflash_t * const sp,
	uint8_t which,
	uint32_t value
);


// Set the FLOCKDN bit -- this requires a reboot to unset
extern void
spiflash_hsfs_flockdn(
	spiflash_t * const sp
);


extern int
spiflash_write_enable(
	spiflash_t * const sp
);


extern int
spiflash_size(
	spiflash_t * sp
);


/*
 * the block erase size can depend on the region of the
 * flash chip that we are in...
 */
extern int
spiflash_erase_size(
	spiflash_t * sp,
	unsigned offset
);


extern int
spiflash_read(
	spiflash_t * sp,
	unsigned offset,
	void * buf,
	unsigned len
);


extern int
spiflash_erase(
	spiflash_t * sp,
	unsigned offset,
	unsigned len
);


// Overwrite the flash (without erasing)
extern int
spiflash_write(
	spiflash_t * sp,
	unsigned offset,
	const void * buf,
	unsigned len
);


// Erase and write blocks to the flash
extern int
spiflash_program(
	spiflash_t * const sp,
	unsigned fladdr,
	const void * data,
	unsigned data_len
);


// Insert new data into the flash, preserving
// any old data that was around them.
extern int
spiflash_program_buffer(
	spiflash_t * const sp,
	unsigned fladdr,
	const void * data_ptr,
	unsigned len
);

#endif
