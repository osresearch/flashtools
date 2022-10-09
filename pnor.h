#ifndef _pnor_h_
#define _pnor_h_

#define FFS_VERSION_1  1
#define FFS_MAGIC      0x50415254
#define PART_NAME_MAX  15
#define FFS_USER_WORDS 16

#define FFS_ENRY_INTEG_ECC    0x00008000
#define FFS_ENTRY_VERS_SHA512 0x80000000

struct ffs_entry {
	char     name[PART_NAME_MAX + 1];
	uint32_t base;
	uint32_t size;
	uint32_t pid;
	uint32_t id;
	uint32_t type;
	uint32_t flags;
	uint32_t actual; // includes ECC
	uint32_t resvd[4];
	struct {
		uint32_t data[FFS_USER_WORDS];
	} user;
	uint32_t checksum;
} __attribute__ ((packed));

struct ffs_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t entry_size;
	uint32_t entry_count;
	uint32_t block_size;
	uint32_t block_count;
	uint32_t resvd[4];
	uint32_t checksum;
	struct ffs_entry entries[];
} __attribute__ ((packed));

#endif
