/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 Hiroki Sato <hrs@FreeBSD.org> */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../dhcp6.h"
#include "../config.h"
#include "../common.h"

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_CLIENT;

int
main(int argc, char **argv)
{
	static const unsigned char expected[] = {
		0, 1, 0, 10, 0, 3, 0, 1, 2, 3, 4, 5, 6, 7,
		0, 8, 0, 2, 0x12, 0x34
	};
	static char duid[] = { 0, 3, 0, 1, 2, 3, 4, 5, 6, 7 };
	union {
		max_align_t alignment;
		unsigned char bytes[64];
	} output;
	struct dhcp6_optinfo options;
	size_t capacity, i, prefix, written;
	int exact, result;

	if (argc != 2 || (strcmp(argv[1], "exact") != 0 &&
	    strcmp(argv[1], "short") != 0))
		return (2);
	exact = strcmp(argv[1], "exact") == 0;
	capacity = exact ? sizeof(expected) : sizeof(expected) - 1;
	prefix = sizeof(struct dhcp6opt) + sizeof(duid);
	written = exact ? sizeof(expected) : prefix;

	memset(output.bytes, 0xa5, sizeof(output.bytes));
	dhcp6_init_options(&options);
	options.clientID.duid_id = duid;
	options.clientID.duid_len = sizeof(duid);
	options.elapsed_time = 0x1234;
	result = dhcp6_set_options(DH6_SOLICIT,
	    (struct dhcp6opt *)output.bytes,
	    (struct dhcp6opt *)(output.bytes + capacity), &options);

	if (result != (exact ? (int)sizeof(expected) : -1)) {
		fprintf(stderr, "capacity %zu: unexpected return %d\n",
		    capacity, result);
		return (1);
	}
	if (memcmp(output.bytes, expected, written) != 0) {
		fputs("unexpected encoded bytes\n", stderr);
		return (1);
	}
	for (i = written; i < sizeof(output.bytes); i++) {
		if (output.bytes[i] != 0xa5) {
			fprintf(stderr, "unexpected write at byte %zu\n", i);
			return (1);
		}
	}
	if (exact)
		printf("Exact fit: %zu bytes written, guard bytes unchanged\n",
		    written);
	else
		printf("One byte short: capacity %zu, second option untouched\n",
		    capacity);
	return (0);
}
