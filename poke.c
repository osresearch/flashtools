/** \file
 * Write arbitrary physical memory locations.
 *
 * WARNING: This is a dangerous tool.
 * It can/will crash or corrupt your system if you write
 * to the wrong locations.
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "util.h"

int verbose = 0;

static const struct option long_options[] = {
	{ "width",		0, NULL, 'w' },
	{ "and",		0, NULL, 'a' },
	{ "or",			0, NULL, 'o' },
	{ "hex",		0, NULL, 'x' },
	{ "force",		0, NULL, 'f' },
	{ "verbose",		0, NULL, 'v' },
	{ NULL,			0, NULL, 0 },
};


static const char usage[] =
"Usage: sudo poke [options] phys_address [data....]\n"
"\n"
"-w | --width 1,2,4,8     Width of memory writes\n"
"-a | --and               AND with the existing memory contents\n"
"-o | --or                OR with the existing memory contents\n"
"-x | --hex               Assume arguments are in hex\n"
"-f | --force             Ignore formatting errors\n"
"-v | --verbose           Increase verbosity\n"
"\n"
"If no bytes are specified, read from stdin.\n"
"\n"
"If data are specified on the commandline, each argument must\n"
"will be treated as an element to be written.\n"
"\n";


int
main(
	int argc,
	char ** argv
)
{
	const char * const prog_name = argv[0];
	int opt;
	int force = 0;
	int base = 0; // auto-detect
	mem_op_t mem_op = MEM_SET;
	unsigned width = 1;

	while((opt = getopt_long(argc, argv, "h?vxfaow:", long_options, NULL)) != -1)
	{
		switch(opt)
		{
		case 'a': mem_op = MEM_AND; break;
		case 'o': mem_op = MEM_OR; break;
		case 'f': force = 1; break;
		case 'x': base = 16; break;
		case 'v': verbose++; break;
		case 'w': width = strtoul(optarg, NULL, 0); break;
		case 'h': case '?':
			printf("%s", usage);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "%s", usage);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
	{
		fprintf(stderr, "%s: Address must be specified\n", prog_name);
		return EXIT_FAILURE;
	}

	// make sure width is supported
	if (width != 1 && width != 2 && width != 4 && width != 8)
	{
		fprintf(stderr, "%s: Width %d is not supported\n", prog_name, width);
		return EXIT_FAILURE;
	}

	char * end_ptr;
	uintptr_t addr = strtoul(argv[0], &end_ptr, base);
	if (*end_ptr != '\0' || end_ptr == argv[0])
	{
		fprintf(stderr, "%s: Unable to parse address '%s'\n", prog_name, argv[0]);
		if (!force)
			return EXIT_FAILURE;
	}

	size_t len;
	uint8_t * buf;

	if (argc > 1)
	{
		// parse all of the arguments and make them into
		// a buffer
		len = (argc-1) * width;
		buf = calloc(len, width);
		if (!buf)
		{
			perror("calloc");
			return EXIT_FAILURE;
		}

		for(int i = 0 ; i < argc-1 ; i++)
		{
			char * arg = argv[i+1];
			char * end_ptr;
			uint64_t v = strtoul(arg, &end_ptr, base);
			if (*end_ptr != '\0' || end_ptr == arg)
			{
				fprintf(stderr, "%s: Unable to parse '%s'\n", prog_name, arg);
				if (!force)
					return EXIT_FAILURE;
			}

			if(width != 8 && (v >> (8*width)) != 0)
			{
				fprintf(stderr, "%s: '%s' larger than width %d\n", prog_name, arg, width);
				if (!force)
					return EXIT_FAILURE;
			}

			if (width == 1)
				*(uint8_t*)(buf + i*width) = (uint8_t) v;
			else
			if (width == 2)
				*(uint16_t*)(buf + i*width) = (uint16_t) v;
			else
			if (width == 4)
				*(uint32_t*)(buf + i*width) = (uint32_t) v;
			else
			if (width == 8)
				*(uint64_t*)(buf + i*width) = (uint64_t) v;
		}
	} else {
		// need to write reading code
		return EXIT_FAILURE;
/*
		size_t offset = 0;
		while (offset < len)
		{
			ssize_t rc = read(STDIN_FILENO, inbuf + offset, len - offset);
			if (rc <= 0)
			{
				perror("read");
				return EXIT_FAILURE;
			}

			offset += rc;
		}
*/
	}

	if (verbose > 1)
	{
		printf("User buffer:\n");
		hexdump(0, buf, len);
	}

	if (iopl(0) < 0)
	{
		perror("iopl");
		return EXIT_FAILURE;
	}

	volatile uint8_t * const mem = map_physical(addr, len);
	if (mem == NULL)
	{
		perror("mmap");
		return EXIT_FAILURE;
	}

	memcpy_width(mem, buf, len, width, mem_op);

	if (verbose)
	{
		// read it back and print it
		memcpy_width(buf, mem, len, width, MEM_SET);
		hexdump(addr, buf, len);
	}

	return EXIT_SUCCESS;
}
