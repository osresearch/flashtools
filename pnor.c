#define _DEFAULT_SOURCE

#include <endian.h>
#include <getopt.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pnor.h"
#include "util.h"

static int verbose = 0;
static int as_is = 0;

static const struct option long_options[] = {
	{ "verbose",		0, NULL, 'v' },
	{ "read",		1, NULL, 'r' },
	{ "write",		1, NULL, 'w' },
	{ "asis",		1, NULL, 'a' },
	{ NULL,			0, NULL, 0 },
};

static const char usage[] =
"Usage: pnor pnor.rom [options]\n"
"\n"
"    -h | -? | --help                   This help\n"
"    -v | --verbose                     Increase verbosity\n"
"    -r | --read part_name              Export a PNOR file to stdout\n"
"    -w | --write part_name             Import a PNOR file from stdin\n"
"    -a | --asis                        Raw read/write of PNOR partition\n"
"\n";

static uint8_t generate_ecc(uint64_t data) {
	static uint64_t ecc_matrix[] = {
		0x0000e8423c0f99ff,
		0x00e8423c0f99ff00,
		0xe8423c0f99ff0000,
		0x423c0f99ff0000e8,
		0x3c0f99ff0000e842,
		0x0f99ff0000e8423c,
		0x99ff0000e8423c0f,
		0xff0000e8423c0f99
	};

	uint8_t result = 0;
	for (int i = 0; i < 8; i++)
		result |= __builtin_parityll(ecc_matrix[i] & data) << i;
	return result;
}

static int read_part(struct ffs_entry *e, uint8_t *start, uint32_t size) {
	uint32_t i;

	if (!as_is && (be32toh(e->user.data[0]) & FFS_ENRY_INTEG_ECC)) {
		for (i = 0; i < size; i++) {
			// TODO: verify and correct data using ECC
			if ((i + 1) % 9 != 0)
				putchar(start[i]);
		}
	} else {
		for (i = 0; i < size; i++)
			putchar(start[i]);
	}

	return EXIT_SUCCESS;
}

static uint32_t checksum(const struct ffs_entry *e)
{
	uint32_t j;
	uint32_t sum = 0;
	for (j = 0; j < sizeof(*e) / sizeof(uint32_t) - 1; j++) {
		/* Avoid warning about possible unaligned access */
		uint32_t as_uint32;
		memcpy(&as_uint32, (uint8_t *)e + j * sizeof(uint32_t),
			   sizeof(uint32_t));
		sum ^= as_uint32;
	}
	return sum;
}

static int write_part(struct ffs_entry *e, uint8_t *start, uint32_t max_size) {
	uint32_t i = 0;

	if (!as_is && (be32toh(e->user.data[0]) & FFS_ENRY_INTEG_ECC)) {
		uint64_t data;
		while (fread(&data, sizeof(data), 1, stdin) == 1) {
			if (i == max_size) {
				fprintf(stderr, "Input data is too large.\n");
				return EXIT_FAILURE;
			}

			*(uint64_t *)&start[i] = data;
			i += 8;
			start[i] = generate_ecc(be64toh(data));
			++i;
		}
	} else {
		int c;
		while ((c = getchar()) != EOF) {
			if (i == max_size) {
				fprintf(stderr, "Input data is too large.\n");
				return EXIT_FAILURE;
			}
			start[i++] = c;
		}
	}

	e->actual = htobe32(i);
	e->checksum = checksum(e);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	const char * const prog_name = argv[0];

	if (argc <= 2) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}

	int opt;
	int do_read = 0;
	int do_write = 0;
	const char * part_name = NULL;
	while ((opt = getopt_long(argc, argv, "h?vr:w:a",
		long_options, NULL)) != -1) {
		switch(opt) {
		case 'v':
			verbose = 1;
			break;
		case 'r':
			do_read = 1;
			part_name = optarg;
			break;
		case 'w':
			do_write = 1;
			part_name = optarg;
			break;
		case 'a':
			as_is = 1;
			break;
		case '?': case 'h':
			fprintf(stderr, "%s", usage);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "%s", usage);
			return EXIT_FAILURE;
		}
	}

	if (!do_read && !do_write) {
		fprintf(stderr, "%s", usage);
		return EXIT_FAILURE;
	}

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		fprintf(stderr, "%s: Excess arguments?\n", prog_name);
		return EXIT_FAILURE;
	}

	const char * romname = argv[0];

	uint64_t size;
	int readonly = do_read;
	void *rom = map_file(romname, &size, readonly);
	if (rom == NULL) {
		fprintf(stderr, "Failed to map ROM file: %s '%s'\n", romname,
			strerror(errno));
		return EXIT_FAILURE;
	}

	struct ffs_hdr *hdr = rom;

	if (be32toh(hdr->magic) != FFS_MAGIC) {
		fprintf(stderr, "Invalid header magic: 0x%08llx\n",
			(unsigned long long)be32toh(hdr->magic));
		return EXIT_FAILURE;
	}

	if (be32toh(hdr->version) != FFS_VERSION_1) {
		fprintf(stderr, "Invalid header version: 0x%08llx\n",
			(unsigned long long)be32toh(hdr->version));
		return EXIT_FAILURE;
	}

	uint32_t i;
	for (i = 0; i < be32toh(hdr->entry_count); i++) {
		struct ffs_entry *e = &hdr->entries[i];
		if (verbose) {
			fprintf(stderr,
				"%s: base %x, size %x (%x) type %x, flags %x\n",
				e->name,
				be32toh(e->base) * be32toh(hdr->block_size),
				be32toh(e->size) * be32toh(hdr->block_size),
				be32toh(e->actual), be32toh(e->type),
				be32toh(e->flags));
		}

		if (strcmp(e->name, part_name) != 0)
			continue;

		if (checksum(e) != e->checksum) {
			fprintf(stderr, "Entry for %s is broken\n", part_name);
			return EXIT_FAILURE;
		}

		uint8_t *start = rom
		               + be32toh(hdr->block_size) * be32toh(e->base);
		uint32_t size = be32toh(e->actual);
		uint32_t max_size = be32toh(e->size) * be32toh(hdr->block_size);

		if (!as_is && (be32toh(e->user.data[1]) & FFS_ENTRY_VERS_SHA512)) {
			if (verbose)
				fprintf(stderr, "Skipping partition header\n");

			/* Skip PNOR partition header */
			start += 0x1000;
			size -= 0x1000;

			/* Possibly skip ECC of the header */
			if (be32toh(e->user.data[0]) & FFS_ENRY_INTEG_ECC) {
				start += 0x200;
				size -= 0x200;
			}
		}

		if (verbose && (be32toh(e->user.data[0]) & FFS_ENRY_INTEG_ECC))
			fprintf(stderr, "%s partition has ECC\n", part_name);

		if (do_read)
			return read_part(e, start, size);
		return write_part(e, start, max_size);
	}

	fprintf(stderr, "Couldn't find %s partition\n", part_name);
	return EXIT_FAILURE;
}
