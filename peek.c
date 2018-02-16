/** \file
 * Read arbitrary physical memory.
 *
 * This is not as dangerous as poke, but you should still be careful!
 * For instance, attempting to read from SMRAM will cause an immediate
 * kernel panic.
 *
 * (c) 2015 Trammell Hudson
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include "util.h"

int verbose = 0;


int
main(
	int argc,
	char ** argv
)
{
	int do_ascii = 0;

	if (argc != 3 && argc != 4)
	{
		fprintf(stderr, "Usage: %s [-x] phys-address len\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "-x") == 0)
	{
		do_ascii = 1;
		argv++;
	}

	const uintptr_t addr = strtoul(argv[1], NULL, 0);
	const size_t len = strtoul(argv[2], NULL, 0);

	if (iopl(0) < 0)
	{
		perror("iopl");
		return EXIT_FAILURE;
	}

	const uint8_t * const buf = map_physical(addr, len);
	if (buf == NULL)
	{
		perror("mmap");
		return EXIT_FAILURE;
	}

	// because the PCIe space doesn't like being probed at anything
	// other than 4-bytes at a time, we force a copy of the region
	// into a local buffer.
	void * const out_buf = calloc(1, len);
	if (!out_buf)
	{
		perror("calloc");
		return EXIT_FAILURE;
	}

	memcpy_width(out_buf, buf, len, 4, MEM_SET);

	if (do_ascii)
	{
		hexdump(addr, out_buf, len);
	} else {
		for(size_t offset = 0 ; offset < len ; )
		{
			const ssize_t rc = write(
				STDOUT_FILENO,
				out_buf + offset,
				len - offset
			);

			if (rc <= 0)
			{
				perror("write");
				return EXIT_FAILURE;
			}

			offset += rc;
		}
	}

	return EXIT_SUCCESS;
}
