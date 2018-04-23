#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "util.h"

#define EFI_PAGE_SIZE 0x1000
#define EFI_VOLUME_SIGNATURE 0x4856465F
#define EFI_FIRMWARE_GUID1 "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
#define EFI_FIRMWARE_GUID2 "5473c07a-3dcb-4dca-bd6f-1e9689e7349a"
#define EFI_EMPTY_GUID "ffffffff-ffff-ffff-ffff-ffffffffffff"
#define EFI_SECTION_VERSION               0x14
#define EFI_SECTION_USER_INTERFACE        0x15
#define EFI_SECTION_FIRMWARE_VOLUME_IMAGE 0x17
#define EFI_SECTION_RAW                   0x19

int verbose = 0;

static const struct option long_options[] = {
	{ "verbose",		0, NULL, 'v' },
	{ "read",		1, NULL, 'r' },
	{ "rom",		2, NULL, 'o' },
	{ "list",		0, NULL, 'l' },
	{ "help",		0, NULL, 'h' },
	{ NULL,			0, NULL, 0 },
};


static const char usage[] =
"Usage: sudo uefi [options]\n"
"\n"
"    -h | -? | --help                   This help\n"
"    -v | --verbose                     Increase verbosity\n"
"    -o | --rom rom                     Use local file instead of ROM\n"
"    -l | --list                        List the GUID and names of EFI files\n"
"    -r | --read GUID                   Export an EFI file to stdout\n"
"\n";

struct efi_volume_header {
	uint8_t zero_vector[16];  // 0x00
	uint8_t guid[16];         // 0x10
	uint64_t len;             // 0x20
	uint32_t sig;             // 0x28
	uint32_t attr;            // 0x2c
	uint16_t header_len;      // 0x30
	uint16_t checksum;        // 0x32
	uint16_t ext_header_off;  // 0x34
	uint8_t reserved;         // 0x36
	uint8_t revision;         // 0x37
	uint32_t num_blocks;      // 0x38
	uint32_t block_size;      // 0x3c
	uint64_t terminate_block; // 0x40 - must be 0
};

struct efi_file_header {
	uint8_t guid[16];
	uint8_t header_um;
	uint8_t file_um;
	uint8_t type;
	uint8_t attr;
	uint8_t len[3];
	uint8_t state;
	uint64_t len64;
};

struct efi_section_header {
	uint8_t len[3];
	uint8_t type;
};

uint32_t size24(uint8_t len[3]) {
	return (uint32_t)len[0] +
		((uint32_t)(len[1]) << 8) +
		((uint32_t)(len[2]) << 16);
}

char *guid_string(uint8_t guid[16]) {
	char *s = malloc(37);
	snprintf(s, 37,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid[3], guid[2], guid[1], guid[0],
		guid[5], guid[4],
		guid[7], guid[6],
		guid[8], guid[9],
		guid[10],
		guid[11],
		guid[12],
		guid[13],
		guid[14],
		guid[15]);
	return s;
}

int main(int argc, char** argv) {
	const char * const prog_name = argv[0];
	if (argc <= 1)
	{
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}

	int opt;
	int use_file = 0;
	int do_read = 0;
	int do_list = 0;
	const char * romname = NULL;
	const char * target_guid = NULL;
	while ((opt = getopt_long(argc, argv, "h?vla:f:o:r:t:",
		long_options, NULL)) != -1)
	{
		switch(opt)
		{
		case 'v':
			verbose++;
			break;
		case 'l':
			do_list = 1;
			break;
		case 'o':
			use_file = 1;
			romname = optarg;
			break;
		case 'r':
			do_read = 1;
			target_guid = optarg;
			break;
		case '?': case 'h':
			fprintf(stderr, "%s", usage);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "%s", usage);
			return EXIT_FAILURE;
		}
	}

	if (!do_list && !do_read) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}

	argc -= optind;
	argv += optind;
	if (argc != 0)
	{
		fprintf(stderr, "%s: Excess arguments?\n", prog_name);
		return EXIT_FAILURE;
	}

	void *rom = NULL;
	uint64_t size;
	const uint64_t mem_end = 0x100000000;

	if (use_file) {
		rom = map_file(romname, &size, 0);
	} else {
		size = 0x2000000; // GRRR: FIX TO BE REAL
		rom = map_physical(mem_end - size, size);
	}

	if (rom == NULL) {
		fprintf(stderr, "Failed to map ROM file: %s '%s'\n", romname,
			strerror(errno));
		return EXIT_FAILURE;
	}

	// search for FVs

	void *voff = rom + size;
	while (voff >= rom) {
		struct efi_volume_header *header = voff;

		if (header->sig != EFI_VOLUME_SIGNATURE) {
			voff -= EFI_PAGE_SIZE;
			continue;
		}

		char *fv_guid = guid_string(header->guid);
		if (verbose) {
			fprintf(stderr, "Possible FV at %lx[%lx]+%x\n",
				(voff-rom), header->len, header->header_len);
			fprintf(stderr, "FV GUID: %s\n", fv_guid);
		}

		int parse_sections =
			strcmp(fv_guid, EFI_FIRMWARE_GUID1) == 0 ||
			strcmp(fv_guid, EFI_FIRMWARE_GUID2) == 0;

		void *foff = voff + header->header_len;
		while (foff < voff+header->len) {
			struct efi_file_header *file = foff;

			uint64_t file_len = size24(file->len);
			uint32_t header_len = 0x18;
			if (file_len == 0xFFFFFF) {
				file_len = file->len64;
				header_len = 0x20;
			}

			if (file_len > size || (foff-voff)+file_len > size) {
				break;
			}

			char *file_guid = guid_string(file->guid);
			if (verbose) {
				fprintf(stderr, "Possible FFS at %lx[%lx]+%x\n",
					(foff-rom), file_len, header_len);
				fprintf(stderr, "FFS GUID: %s TYPE: %02x\n", file_guid, file->type);
			}

			if ((strcmp(file_guid, EFI_EMPTY_GUID) == 0) ||
				!parse_sections
			) {
				goto end_file;
			}

			if (do_list) {
				fprintf(stdout, "%s\n", file_guid);
			}

			void *soff = foff+header_len;
			while (soff < foff+file_len) {
				struct efi_section_header *section = soff;
				uint64_t section_len = size24(section->len);
				if (section_len == 0) {
					break;
				}

				if (verbose) {
					fprintf(stderr, "Possible Section at %lx[%lx]\n",
						(soff-rom), section_len);
					fprintf(stderr, "TYPE: %02x\n", section->type);
				}

				if (do_read &&
					strcmp(file_guid, target_guid) == 0 &&
					section->type == EFI_SECTION_RAW
				) {
					char *section_data = (char *) soff + 4;
					for (size_t offset = 0 ; offset < section_len ; ) {
						const ssize_t rc = write(
							STDOUT_FILENO,
							section_data + offset,
							section_len - offset
						);

						if (rc <= 0) {
							fprintf(stderr, "Failed to write file to stdout: %s\n",
								strerror(errno));
							return EXIT_FAILURE;
						}

						offset += rc;
					}
					do_read++;
				}

				soff += section_len;
			}

			end_file:
			free(file_guid);
			foff += align_up(file_len, 8);
		}
		voff -= EFI_PAGE_SIZE;
	}

	if (do_read == 1) {
		fprintf(stderr, "Failed to find FFS named '%s'\n", target_guid);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
