/** \file SPI flash ROM interface.
 *
 * Includes code from flashrom/ichspi.c, licensed under the GPL.
 */
#ifdef __efi__
#include <efi.h>
#include <efilib.h>

#define fprintf(...) do { /* nothing */ } while(0)
#define printf(...) do { /* nothing */ } while(0)
#define snprintf(...) do { /* nothing */ } while(0)

// there is nothing to map -- we are in direct mapped mode
#define iopl(n) do { /* nothing */ } while(0)
#define map_physical(addr, len) ((void*)(addr))

#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "DirectHW.h"
#endif

#include "spiflash.h"


/*
Normally these macros are the junction between userspace
and kernel space. So they've been replaced to assume
they're executing in the context of code that can already
get at all of memory
*/
//In the below macros:
// a is the base,
// b is the offset,
// c is the src/dst
//
#define MMIO_MACRO(TYPE,NAME) \
static inline TYPE \
read_mmio_##NAME( \
	const void * const base, \
	const unsigned offset \
) \
{ \
	return *(const volatile TYPE*)(offset + (const uint8_t*) base); \
} \
static inline void \
write_mmio_##NAME( \
	void * const base, \
	const unsigned offset, \
	const TYPE value \
) \
{ \
	*(volatile TYPE*)(offset + (uint8_t*) base) = value; \
	__asm__ __volatile__ ("mfence" : : : "memory"); \
} \


MMIO_MACRO(uint8_t,byte)
MMIO_MACRO(uint16_t,short)
MMIO_MACRO(uint32_t,dword)

#define PCIEXBAR_LPC_OFFSET 0xF8000
#define SPIBAR_OFFSET 0x3800
#define SPIBAR_REGION_SIZE 0x200
#define RCBA_OFFSET 0xF0

#define BIOS_CNTL_OFFSET	0xdc
#define BIOS_CNTL_BIOSWE	0x01
#define BIOS_CNTL_BLE		0x02
#define BIOS_CNTL_TOPSWAP	0x10
#define BIOS_CNTL_SMMBWP	0x20

#define MAX_SPI_REGIONS 5
#define FDATA_OFFSET 0x10
#define FLADDR_OFFSET 0x08

#define FRAP_OFFSET 0x50
#define FREG0_OFFSET 0x54

#define HSFC_OFFSET 0x06
#define HSFC_FGO_OFFSET 0
#define HSFC_FGO (0x1 << HSFC_FGO_OFFSET)
#define HSFC_FCYCLE_OFFSET 1
#define HSFC_FCYCLE (0x3 << HSFC_FCYCLE_OFFSET)
#define HSFC_FDBC_OFFSET 8
#define HSFC_FDBC (0x3f << HSFC_FDBC_OFFSET)

#define HSFS_OFFSET 0x04
#define HSFS_FDONE_OFF		0	/* 0: Flash Cycle Done */
#define HSFS_FDONE		(0x1 << HSFS_FDONE_OFF)
#define HSFS_FCERR_OFF		1	/* 1: Flash Cycle Error */
#define HSFS_FCERR		(0x1 << HSFS_FCERR_OFF)
#define HSFS_AEL_OFF		2	/* 2: Access Error Log */
#define HSFS_AEL		(0x1 << HSFS_AEL_OFF)
#define HSFS_BERASE_OFF		3	/* 3-4: Block/Sector Erase Size */
#define HSFS_BERASE		(0x3 << HSFS_BERASE_OFF)
#define HSFS_SCIP_OFF		5	/* 5: SPI Cycle In Progress */
#define HSFS_SCIP		(0x1 << HSFS_SCIP_OFF)
					/* 6-12: reserved */
#define HSFS_FDOPSS_OFF		13	/* 13: Flash Descriptor Override Pin-Strap Status */
#define HSFS_FDOPSS		(0x1 << HSFS_FDOPSS_OFF)
#define HSFS_FDV_OFF		14	/* 14: Flash Descriptor Valid */
#define HSFS_FDV		(0x1 << HSFS_FDV_OFF)
#define HSFS_FLOCKDN_OFF	15	/* 15: Flash Configuration Lock-Down */
#define HSFS_FLOCKDN		(0x1 << HSFS_FLOCKDN_OFF)


// The PRR (Protected Range Registers) are in the SPI BAR region
#define SPIBAR_PR0_OFFSET 0x74


/** Read the SPI flash status (HSFS) register.
 *
 * Bits of interest:
 * 0 == FDONE
 * 1 == FCERR
 * 2..3 == BERASE
 */
static inline uint16_t
spiflash_hsfs(
	spiflash_t * const sp
)
{
	return read_mmio_short(sp->spibar, HSFS_OFFSET);
}


/*
 * FDONE, FCERR, AEL must be cleared before calling any ops
 * clear FDONE, FCERR, AEL by writing a 1 to them (if they are set)
 */
static inline void
spiflash_hsfs_clear(
	spiflash_t * const sp
)
{
	write_mmio_short(sp->spibar, HSFS_OFFSET, spiflash_hsfs(sp));
}


void
spiflash_hsfs_flockdn(
	spiflash_t * const sp
)
{
	write_mmio_short(sp->spibar, HSFS_OFFSET, HSFS_FLOCKDN);
}



static const char *
spiflash_hsfs_str(
	spiflash_t * const sp
)
{
	static char buf[80];
	uint16_t hsfs = spiflash_hsfs(sp);
	snprintf(buf, sizeof(buf), "%04x:%s%s%s%s%s%s%s BERASE=%d",
		hsfs,
		(hsfs & HSFS_FDONE) ? " FDONE" : "",
		(hsfs & HSFS_FCERR) ? " FCERR" : "",
		(hsfs & HSFS_AEL) ? " AEL" : "",
		(hsfs & HSFS_SCIP) ? " SCIP" : "",
		(hsfs & HSFS_FDOPSS_OFF) ? " FDOPSS" : "",
		(hsfs & HSFS_FDV) ? " FDV" : "",
		(hsfs & HSFS_FLOCKDN) ? " FLOCKDN" : "",
		(hsfs >> HSFS_BERASE_OFF) & 0x3
	);

	return buf;
}

/** Read the SPI flash command (HSFC) register.
 *
 * Bits of interest:
 * 0 == FGO
 * 1 == FCYCLE
 * 8..15 == FDBC
 */
static inline uint16_t
spiflash_hsfc(
	spiflash_t * const sp
)
{
        return read_mmio_short(sp->spibar, HSFC_OFFSET);
}


static inline void
spiflash_command(
	spiflash_t * const sp,
	const uint16_t hsfc
)
{
	if (sp->verbose > 2)
		fprintf(stderr, "%s: %04x\n", __func__, hsfc);

	write_mmio_short(sp->spibar, HSFC_OFFSET, hsfc);
}


/** Set the FLA in FLADDR without touching the other bits. */
static inline void
spiflash_set_addr(
	spiflash_t * const sp,
	const uint32_t fladdr
)
{
	uint32_t old_fladdr
		= read_mmio_dword(sp->spibar, FLADDR_OFFSET) & ~0x01FFFFFF;

	if (sp->verbose > 2)
	fprintf(stderr, "%s: %08x -> %08x\n",
		__func__, fladdr, fladdr | old_fladdr);

	write_mmio_dword(sp->spibar, FLADDR_OFFSET, fladdr | old_fladdr);
}

int
spiflash_erase_size(
	spiflash_t * const sp,
	unsigned fladdr
)
{
	spiflash_set_addr(sp, fladdr);
	const uint16_t hsfs = spiflash_hsfs(sp);
	const unsigned enc_erase_size
		= (hsfs & HSFS_BERASE) >> HSFS_BERASE_OFF;

	if (enc_erase_size == 0)
		return 256;
	if (enc_erase_size == 1)
		return 4 * 1024;
	if (enc_erase_size == 2)
		return 8 * 1024;
	if (enc_erase_size == 3)
		return 64 * 1024;

	// uh oh. no idea.
        return -1;
}


static void
spin_wait(
	unsigned count
)
{
	for(volatile unsigned i = 0 ; i < count ; i++)
		__asm__ __volatile__("nop");
}




//returns 0 if wait is successful
//returns 1 if wait fails for some reason
//should probably add timeout code...
static int
spiflash_wait(
	spiflash_t * const sp
)
{
	if (sp->verbose > 2)
	fprintf(stderr, "%s: initial hsfs %s\n",
		__func__, spiflash_hsfs_str(sp));

	while (1)
	{
		spin_wait(0x1000);

        	const uint16_t hsfs
			= spiflash_hsfs(sp);

		if (hsfs & HSFS_FCERR)
			return -1; // failure
		if (hsfs & HSFS_FDONE)
			break;
	}


	// success, but wait a few cycles since the chip seems to lie
	// about when the data are actually available
        spin_wait(0x10000);

	return 0;
}


static inline uint32_t min(uint32_t a, uint32_t b)
{
    if(a < b)
        return a;
    else
        return b;
}


int
spiflash_erase_page(
	spiflash_t * const sp,
	unsigned fladdr
)
{
	if (sp->verbose > 2)
	fprintf(stderr, "%s: %08x\n", __func__, fladdr);

	spiflash_set_addr(sp, fladdr);

	uint16_t hsfc = spiflash_hsfc(sp);
	hsfc &= ~HSFC_FCYCLE; //clear cycle bit
	hsfc &= ~HSFC_FDBC; //clear byte count
	hsfc |= (0x3 << HSFC_FCYCLE_OFFSET); //set operation=erase
	hsfc |= HSFC_FGO;

	spiflash_command(sp, hsfc);

	if (spiflash_wait(sp) < 0)
	{
		fprintf(stderr, "%s: fcycle failed?\n", __func__);
		return -1;
	}

#ifdef __efi__
	// efi won't wait
	spin_wait(0x100000);
#else
	spin_wait(0x4000000);
#endif

	return 0;
}
        
//note that we can only erase in block_erase_size increments
//so we can overrun fladdr+len with erase opertion.
int
spiflash_erase(
	spiflash_t * const sp,
	unsigned fladdr,
	unsigned len
)
{
	const unsigned block_erase_size
		= spiflash_erase_size(sp, fladdr);
    
	spiflash_hsfs_clear(sp);

	if (sp->verbose > 2)
	fprintf(stderr, "%s: HSFS %s\n", __func__, spiflash_hsfs_str(sp));
    
	while (len > 0)
	{
		if (spiflash_erase_page(sp, fladdr) < 0)
			return -1;

		fladdr += block_erase_size;
		len -= min(block_erase_size,len);
	}
    
	return 0;
}


static void
write_fdata(
	spiflash_t * const sp,
	const uint8_t * data,
	const unsigned len
)
{
	for (unsigned i=0 ; i<len ; i += 4)
	{
		const uint32_t word = 0
			| (uint32_t)(data[i+0]) <<  0
			| (uint32_t)(data[i+1]) <<  8
			| (uint32_t)(data[i+2]) << 16
			| (uint32_t)(data[i+3]) << 24
			;

		write_mmio_dword(sp->spibar, FDATA_OFFSET + i, word);
	}
}


//fladdr is a Flash Linear Address (aka an offset into the flash chip)
int
spiflash_write(
	spiflash_t * const sp,
	unsigned fladdr,
	const void * buf,
	unsigned len
)
{
	const uint8_t *buf_ptr = buf;
    
	spiflash_hsfs_clear(sp);

	if (sp->verbose > 2)
		fprintf(stderr, "%s: HSFS %s\n", __func__, spiflash_hsfs_str(sp));
    	if (sp->verbose)
		fprintf(stderr, "%s: %08x + %x bytes\n", __func__, fladdr, len);

	while (len > 0)
	{
		spiflash_set_addr(sp, fladdr);
        
		unsigned block_len = 64;
		if (len < block_len)
			block_len = len;
        
		if (sp->verbose > 1)
			fprintf(stderr, "%s: %08x + %04x\n", __func__, fladdr, block_len);

		//apparently we also have to be aware of flash chip page borders??
		//algo copied from flashrom
		//block_len = min(block_len, 256 - (fladdr & 0xff));
        
		//encode fdata using its weird encoding scheme..
		write_fdata(sp, buf_ptr, block_len);
        
		uint16_t hsfc = spiflash_hsfc(sp);
		hsfc &= ~HSFC_FCYCLE; //clear operation
		hsfc |= (0x2 << HSFC_FCYCLE_OFFSET); //write operation
		hsfc &= ~HSFC_FDBC; //clear byte count
        
		hsfc |= (((block_len - 1) << HSFC_FDBC_OFFSET));
		hsfc |= HSFC_FGO;

		if (sp->verbose > 1)
			fprintf(stderr, "%s: fladdr=%x, block_len=%x, hsfc=%x, len=%x\n", __func__, fladdr, block_len, hsfc, len);

		spiflash_command(sp, hsfc);

		if (spiflash_wait(sp) < 0)
		{
			//printf("write_flash_data: spiflash_wait failed... bailing out.\n");
			return -1;
		}

		// just in case, since the chip seems to lie
		spin_wait(0x10000);

		fladdr += block_len;
		buf_ptr += block_len;
		len -= block_len;
	}
    
	return 0;
}


//data_len had better be block_erase_size aligned (usually 0x1000)
//or you could end up erasing data without reprogramming since
//erasing happens in 0x1000 byte increments
//fladdr is a Flash Linear Address (aka an offset into the flash chip)
int
spiflash_program(
	spiflash_t * const sp,
	unsigned fladdr,
	const void * data_ptr,
	unsigned len
)
{
	const uint8_t * data = data_ptr;

	spiflash_hsfs_clear(sp);

	while (len > 0)
	{
		unsigned block_size
			= spiflash_erase_size(sp, fladdr);

		if (block_size > len)
			block_size = len;

		if (spiflash_erase_page(sp, fladdr) < 0)
			return -1;

		if (spiflash_write(sp, fladdr, data, block_size) < 0)
			return -1;

		fladdr += block_size;
		data += block_size;
		len -= block_size;
	}
		

	return 0; 
}

int
spiflash_program_buffer(
	spiflash_t * const sp,
	unsigned fladdr,
	const void * data_ptr,
	unsigned len
)
{
	const uint8_t * data = data_ptr;

	spiflash_hsfs_clear(sp);

	uint8_t buf[0x1000];

	while (len > 0)
	{
		const unsigned erase_size
			= spiflash_erase_size(sp, fladdr);

		const unsigned block_mask = erase_size - 1;
		const unsigned fladdr_base = fladdr & ~block_mask;
		const unsigned block_offset = fladdr & block_mask;

		// the amount we can write in this block depends on
		// the alignment of fladdr with the block size.
		unsigned block_len = erase_size - block_offset;

		// if we are on the last block, limit the size
		if (block_len > len)
			block_len = len;

		// read the entire erase block into our buffer
		if (spiflash_read(sp, fladdr_base, buf, erase_size) < 0)
			return -1;

		// copy our data over it at the right alignment
		unsigned delta = 0;
		for(unsigned i = 0 ; i < block_len ; i++)
		{
			uint8_t old = buf[i+block_offset];
			uint8_t new = data[i];
			if (old != new)
				delta = 1;
			buf[i+block_offset] = data[i];
		}

		// now erase the entire page unless there are no changes
		if (delta == 0)
		{
			if (sp->verbose)
				printf("%s: %08x unchanged\n", __func__, fladdr_base);
		} else {
			if (spiflash_erase_page(sp, fladdr_base) < 0)
				return -1;

			// and write our entire new buffer onto it, including the
			// bit that we already copied
			if (spiflash_write(sp, fladdr_base, buf, erase_size) < 0)
				return -1;
		}

		fladdr += block_len;
		data += block_len;
		len -= block_len;
	}
		

	return 0; 
}



static void
read_fdata(
	spiflash_t * const sp,
	uint8_t * data,
	unsigned len
)
{
	for (unsigned i = 0; i < len; i += 4)
	{
		const uint32_t tmp
			= read_mmio_dword(sp->spibar, FDATA_OFFSET + i);

		data[i+0] = (tmp >>  0) & 0xFF;
		data[i+1] = (tmp >>  8) & 0xFF;
		data[i+2] = (tmp >> 16) & 0xFF;
		data[i+3] = (tmp >> 24) & 0xFF;
	}
}


//max len is 64bytes for this, as thats the most number of
//bytes we can read in one go. Output to preallocated buf
//FDONE, FCERR, AEL must be cleared before calling this
//clear FDONE, FCERR, AEL by writing a 1 to them (if they are set)
//read_mmio_short_macro(spibar, HSFS_OFFSET, &hsfs);
//write_mmio_short_macro(spibar, HSFS_OFFSET, hsfs);
//fladdr is a Flash Linear Address (aka an offset into the flash chip)
int
spiflash_read(
	spiflash_t * const sp,
	unsigned fladdr,
	void * buf,
	unsigned len
)
{
	uint8_t * buf_ptr = buf;
    
	spiflash_hsfs_clear(sp);
	unsigned offset = 0;

	while (len > 0)
	{
		unsigned block_len = 64;
		if (len < block_len)
            		block_len = len;
        
		if (sp->verbose && offset % 4096 == 0)
			fprintf(stderr, "%s: offset %08x\n", __func__, fladdr);

		spiflash_set_addr(sp, fladdr);

		uint16_t hsfc = spiflash_hsfc(sp);
		hsfc &= ~HSFC_FCYCLE; // 0 is read
		hsfc &= ~HSFC_FDBC; // clear byte count
        
		// set flash data byte count
		// 1 is automatically added to the number of bytes to read
		hsfc |= (((block_len - 1) << HSFC_FDBC_OFFSET));
		hsfc |= HSFC_FGO;
        
		spiflash_command(sp, hsfc);

		if (spiflash_wait(sp) < 0)
		{
			fprintf(stderr, "%s: spiflash_wait failed... bailing out.\n", __func__);
			return -1;
		}

		read_fdata(sp, buf_ptr, block_len);

		fladdr += block_len;
		buf_ptr += block_len;
		offset += block_len;
		len -= block_len;

	}
	return 0;
}


///////////////////////////////////////////////////////
//Configuration detect stuff:

//alternative is to hardcode to 0xfed1f800
// must read RCBA 32-bits at a time
static int
find_spibar(
	spiflash_t * const sp,
	uint64_t lpc_phys
)
{
	iopl(0);

	sp->lpc_base = map_physical(lpc_phys, 0x1000);
	if (sp->lpc_base == NULL)
		return -1;

	if (sp->verbose)
		printf("lpc_base=%p\n", sp->lpc_base);

 	uint64_t rcba = read_mmio_dword(sp->lpc_base, RCBA_OFFSET);
	if (sp->verbose)
		printf("rcba=%08"PRIx64"\n", rcba);

	//should never occur, but...
	if(!(rcba & 1))
		return -1;

	rcba &= ~1; //clear the bottom bit

	uint8_t * const spibar_ptr = map_physical(rcba, 65536);

	sp->spibar = spibar_ptr + SPIBAR_OFFSET;
	if (sp->verbose)
		printf("spibar=%p\n", sp->spibar);

	return 0;
}


static inline uint32_t get_region_limit(uint32_t freg)
{
    return (((freg & 0x1fff0000) >> 4) | 0x00000fff);
}


static inline uint32_t get_region_base(uint32_t freg)
{
    return ((freg & 0x00001fff) << 12);
}


static inline uint32_t
get_freg(
	spiflash_t * const sp,
	uint32_t region
)
{
	return read_mmio_dword(sp->spibar, FREG0_OFFSET + region*4);
}


int
spiflash_size(
	spiflash_t * const sp
)
{
    uint32_t flash_chip_limit = 0;
    
    //this algorithm finds the region with the maximum limit
    //we assume this represents the size of the flash chip
    for (unsigned region = 0; region < MAX_SPI_REGIONS; region++)
    {
        uint32_t freg = get_freg(sp, region);
        uint32_t cur_limit = get_region_limit(freg);
        uint32_t cur_base = get_region_base(freg);
        
	if (sp->verbose > 1)
	fprintf(stderr, "%s: region %d: %08x @ %08x freg=%08x\n",
		__func__, region, cur_base, cur_limit, freg);

        //region not in use
        if (cur_limit < cur_base)
            continue;
        
        if (cur_limit > flash_chip_limit)
            flash_chip_limit = cur_limit;
    }

    if (sp->verbose > 1)
    fprintf(stderr, "%s: limit %x\n", __func__, flash_chip_limit);

    return flash_chip_limit + 1;
}


uint8_t
spiflash_bios_cntl(
	spiflash_t * const sp
)
{
	return read_mmio_byte(sp->lpc_base, BIOS_CNTL_OFFSET);
}


uint8_t
spiflash_set_bios_cntl(
	spiflash_t * const sp,
	uint8_t new_bios_cntl
)
{
        write_mmio_byte(sp->lpc_base, BIOS_CNTL_OFFSET, new_bios_cntl);
	return spiflash_bios_cntl(sp);
}


void
spiflash_prr(
	spiflash_t * const sp,
	uint8_t which,
	uint32_t value
)
{
	if (which > 4)
		return;

	write_mmio_dword(sp->spibar, SPIBAR_PR0_OFFSET + which*4, value);
}



int
spiflash_write_enable(
	spiflash_t * const sp
)
{
        const uint8_t bios_cntl = spiflash_bios_cntl(sp);

	if (sp->verbose)
        fprintf(stderr, "%s: bios_cntl=%x\n", __func__, bios_cntl);

        const uint8_t new_bios_cntl =
		spiflash_set_bios_cntl(sp, bios_cntl | BIOS_CNTL_BIOSWE);

	if (sp->verbose)
        fprintf(stderr, "%s: new_bios_cntl=%x\n", __func__, new_bios_cntl);

	// if we are unable to set the write enable bit, signal a failure
	return new_bios_cntl & BIOS_CNTL_BIOSWE ? 0 : -1;
}


int
spiflash_init(
	spiflash_t * const sp,
	uint64_t pcie_xbar
)
{
	if (find_spibar(sp, pcie_xbar + PCIEXBAR_LPC_OFFSET) < 0)
		return -1;

	if (sp->verbose)
		printf("FRAP=%04x\n", read_mmio_dword(sp->spibar, FRAP_OFFSET));

	return 0;
}


void
spiflash_info(
	spiflash_t * const sp
)
{
        const uint8_t bios_cntl
		= read_mmio_byte(sp->lpc_base, BIOS_CNTL_OFFSET);

	printf("BIOS_CNTL=%02x:%s%s%s%s\n",
		bios_cntl,
		bios_cntl & BIOS_CNTL_BIOSWE ? " BIOSWE" : "",
		bios_cntl & BIOS_CNTL_BLE ? " BLE" : "",
		bios_cntl & BIOS_CNTL_TOPSWAP ? " TOPSWAP" : "",
		bios_cntl & BIOS_CNTL_SMMBWP ? " SMMBWP" : ""
	);

	printf("HSFS=%s\n", spiflash_hsfs_str(sp));

	for(int i = 0 ; i < 5 ; i++)
	{
		const uint32_t prr = read_mmio_dword(sp->spibar, SPIBAR_PR0_OFFSET + i*4);
		printf("PR%d=%08x\n", i, prr);
	}
}
