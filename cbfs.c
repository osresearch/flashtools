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

#define CBFS_HEADER_MAGIC  0x4F524243
#define CBFS_HEADER_VERSION1 0x31313131
#define CBFS_HEADER_VERSION2 0x31313132
#define CBFS_HEADER_VERSION  CBFS_HEADER_VERSION2

#define MAX_CBFS_FILE_HEADER_BUFFER 1024
#define CBFS_CONTENT_DEFAULT_VALUE	(-1)
#define CBFS_FILENAME_ALIGN	(16)
#define CBFS_COMPONENT_RAW 0x50
#define CBFS_COMPONENT_NULL 0xFFFFFFFF

int verbose = 0;

static const struct option long_options[] = {
	{ "verbose",		0, NULL, 'v' },
	{ "read",		1, NULL, 'r' },
	{ "add",		1, NULL, 'a' },
	{ "file",		1, NULL, 'f' },
	{ "rom",		1, NULL, 'o' },
	{ "list",		0, NULL, 'l' },
	{ "type",		1, NULL, 't' },
	{ "help",		0, NULL, 'h' },
	{ NULL,			0, NULL, 0 },
};


static const char usage[] =
"Usage: sudo cbfs [options]\n"
"\n"
"    -h | -? | --help                   This help\n"
"    -v | --verbose                     Increase verbosity\n"
"    -o | --rom file                    Use local file instead of internal ROM\n"
"    -l | --list                        List the names of CBFS files\n"
"    -r | --read name                   Export a CBFS file to stdout\n"
"    -a | --add name -f | --file path   Add a CBFS file\n"
"    -t | --type 50                     Filter/set to CBFS file type (hex)\n"
"\n";

struct cbfs_header {
	uint32_t magic;
	uint32_t version;
	uint32_t romsize;
	uint32_t bootblocksize;
	uint32_t align; /* hard coded to 64 byte */
	uint32_t offset;
	uint32_t architecture;  /* Version 2 */
	uint32_t pad[1];
};

#define CBFS_FILE_MAGIC "LARCHIVE"

struct cbfs_file {
	uint8_t magic[8];
	/* length of file data */
	uint32_t len;
	uint32_t type;
	/* offset to struct cbfs_file_attribute or 0 */
	uint32_t attributes_offset;
	/* length of header incl. variable data */
	uint32_t offset;
	char filename[];
};

size_t cbfs_calculate_file_header_size(const char *name)
{
	return (sizeof(struct cbfs_file) +
		align_up(strlen(name) + 1, CBFS_FILENAME_ALIGN));
}

struct cbfs_file *cbfs_create_file_header(int type,
          size_t len, const char *name)
{
	struct cbfs_file *entry = malloc(MAX_CBFS_FILE_HEADER_BUFFER);
	memset(entry, CBFS_CONTENT_DEFAULT_VALUE, MAX_CBFS_FILE_HEADER_BUFFER);
	memcpy(entry->magic, CBFS_FILE_MAGIC, sizeof(entry->magic));
	entry->type = htonl(type);
	entry->len = htonl(len);
	entry->attributes_offset = 0;
	entry->offset = htonl(cbfs_calculate_file_header_size(name));
	memset(entry->filename, 0, ntohl(entry->offset) - sizeof(*entry));
	strcpy(entry->filename, name);
	return entry;
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
	int do_add = 0;
	int do_read = 0;
	int do_list = 0;
	int do_type = 0;
	uint32_t cbfs_file_type = 0;
	const char * romname = NULL;
	const char * cbfsname = NULL;
	const char * filename = NULL;
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
		case 'f':
			filename = optarg;
			break;
		case 'a':
			do_add = 1;
			cbfsname = optarg;
			break;
		case 'r':
			do_read = 1;
			cbfsname = optarg;
			break;
		case 't':
			do_type = 1;
			cbfs_file_type = strtoul(optarg, NULL, 16);
			break;
		case '?': case 'h':
			fprintf(stderr, "%s", usage);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "%s", usage);
			return EXIT_FAILURE;
		}
	}

	if (!do_list && !do_read && !do_add) {
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

	int32_t header_delta;
	struct cbfs_header header;
	void *rom = NULL, *off = NULL;
	uint64_t size;
	const uint64_t mem_end = 0x100000000;

	if (use_file) {
		rom = map_file(romname, &size, 0);
		if (rom == NULL) {
			fprintf(stderr, "Failed to map ROM file: %s '%s'\n", romname,
				strerror(errno));
			return EXIT_FAILURE;
		}
		header_delta = *((int32_t *)(rom + size - 4));
		memcpy(&header, rom + size + header_delta, sizeof(header));
	} else {
		copy_physical(mem_end - 4, sizeof(header_delta), &header_delta);
		copy_physical(mem_end + header_delta, sizeof(header), &header);
	}

	header.magic = ntohl(header.magic);
	header.version = ntohl(header.version);
	header.romsize = ntohl(header.romsize);
	header.bootblocksize = ntohl(header.bootblocksize);
	header.align = ntohl(header.align);
	header.offset = ntohl(header.offset);
	header.architecture = ntohl(header.architecture);

	if (verbose) {
		fprintf(stderr, "Header delta          : %d\n", header_delta);
		fprintf(stderr, "Header magic          : %x\n", header.magic);
		fprintf(stderr, "Header version        : %x\n", header.version);
		fprintf(stderr, "Header ROM size       : %x\n", header.romsize);
		fprintf(stderr, "Header boot block size: %x\n", header.bootblocksize);
		fprintf(stderr, "Header align          : %x\n", header.align);
		fprintf(stderr, "Header offset         : %x\n", header.offset);
		fprintf(stderr, "Header arch           : %x\n", header.architecture);
	}

	if (header.magic != CBFS_HEADER_MAGIC) {
		fprintf(stderr, "Failed to find valid header\n");
		return EXIT_FAILURE;
	}

	if (!use_file) {
		size = (uint64_t) header.romsize;
		rom = map_physical(mem_end - size, size);
	}

	// Setup file to add to ROM
	struct cbfs_file *add_file;
	void *add, *empty_start = NULL, *empty_end = NULL;
	uint64_t add_need_size = 0;
	if (do_add) {
		if (!use_file) {
			fprintf(stderr, "Adding directly to flash not yet supported");
			return EXIT_FAILURE;
		}

		if (filename == NULL) {
			fprintf(stderr, "-f || --file is required to add a file");
			fprintf(stderr, "%s", usage);
			return EXIT_FAILURE;
		}

		uint64_t add_size;
		add = map_file(filename, &add_size, 1);
		if (add == NULL) {
			fprintf(stderr, "Failed to map add file: %s '%s'\n", filename,
				strerror(errno));
			return EXIT_FAILURE;
		}

		add_file = cbfs_create_file_header(
			do_type ? cbfs_file_type : CBFS_COMPONENT_RAW,
			add_size,
			cbfsname
		);
		add_need_size = align_up(ntohl(add_file->offset) + ntohl(add_file->len),
			(uint32_t)header.align);

		if (verbose) {
			fprintf(stderr, "Looking for %lx space for '%s': %lx %x %x\n",
				add_need_size, filename,
				add_size, ntohl(add_file->offset), ntohl(add_file->len));
		}
	}

	// loop through files
	off = rom + ((uint64_t) header.offset);
	while (off < rom + size) {
		if (verbose) {
			fprintf(stderr, "Potential CBFS File Offset: %lx\n", (off - rom));
		}
		struct cbfs_file file;
		memcpy(&file, off, sizeof(file));

		file.len = ntohl(file.len);
		file.type = ntohl(file.type);
		file.attributes_offset = ntohl(file.attributes_offset);
		file.offset = ntohl(file.offset);

		if (verbose) {
			fprintf(stderr, "File magic             : %.8s\n", file.magic);
			fprintf(stderr, "File len               : %x\n", file.len);
			fprintf(stderr, "File type              : %x\n", file.type);
			fprintf(stderr, "File attributes_offset : %x\n", file.attributes_offset);
			fprintf(stderr, "File offset            : %x\n", file.offset);
		}

		if (strncmp((char *)file.magic, CBFS_FILE_MAGIC, 8) != 0) {
			break;
		}

		size_t name_size = file.offset - sizeof(file);
		char *name = (char *)off + sizeof(file);

		if (verbose) {
			fprintf(stderr, "File name              : '%s'\n", name);
		}

		if (do_list &&
			(!do_type || (do_type && file.type == cbfs_file_type))) {
			printf("%s\n", name);
		}

		if (do_read &&
			(!do_type || (do_type && file.type == cbfs_file_type)) &&
			strncmp(name, cbfsname, name_size) == 0)
		{
			if (off + file.offset + file.len > rom + size) {
				fprintf(stderr, "File offset/length extends beyond ROM");
				return EXIT_FAILURE;
			}

			char *file_data = (char *) off + file.offset;
			for (size_t offset = 0 ; offset < file.len ; ) {
				const ssize_t rc = write(
					STDOUT_FILENO,
					file_data + offset,
					file.len - offset
				);

				if (rc <= 0) {
					fprintf(stderr, "Failed to write file to stdout: %s\n",
						strerror(errno));
					return EXIT_FAILURE;
				}

				offset += rc;
			}

			do_read++;
			break;
		}

		uint64_t inc = align_up(file.offset + file.len, (uint32_t)header.align);
		if (do_add) {
			if (strncmp(name, cbfsname, name_size) == 0) {
				fprintf(stderr, "File already exists: %s\n", name);
				return EXIT_FAILURE;
			}

			if (file.type == CBFS_COMPONENT_NULL && inc >= add_need_size) {
				empty_start = off;
				empty_end = off + inc;
				if (verbose) {
					fprintf(stderr, "Found space at %lx[%lx] for %lx\n",
						(off - rom), inc, add_need_size);
				}
			} else {
				if (verbose) {
					fprintf(stderr, "Skipped space at %lx[%lx] for %lx\n",
						(off - rom), inc, add_need_size);
				}
			}
		}

		off += inc;
	}

	if (do_add) {
		if (empty_start == NULL) {
			fprintf(stderr, "Failed to find space to add this file\n");
			return EXIT_FAILURE;
		}

		if (verbose) {
			fprintf(stdout, "Adding file between %lx:%lx\n",
				(empty_start - rom), (empty_start + add_need_size - rom));
		}

		uint32_t file_offset = ntohl(add_file->offset);
		// copy new file header
		memcpy(empty_start, add_file, file_offset);
		// copy new file data
		memcpy(empty_start+file_offset, add, ntohl(add_file->len));

		empty_start += add_need_size;
		uint32_t min_entry_size = cbfs_calculate_file_header_size("");
		if (empty_end - empty_start >= min_entry_size) {
			if (verbose) {
				fprintf(stdout, "Adding empty file between %lx:%lx\n",
					(empty_start - rom), (empty_end - rom));
			}
			uint32_t new_empty_len = empty_end - empty_start - min_entry_size;
			struct cbfs_file *new_empty_file =
				cbfs_create_file_header(CBFS_COMPONENT_NULL, new_empty_len, "");

			uint32_t empty_offset = ntohl(new_empty_file->offset);
			// copy new file header
			memcpy(empty_start, new_empty_file, empty_offset);
		}
	}

	if (do_read == 1) {
		fprintf(stderr, "Failed to find CBFS file named '%s'\n", cbfsname);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
