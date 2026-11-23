/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 Hiroki Sato <hrs@FreeBSD.org> */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	struct sockaddr_in6 address = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int fd, error;

#ifdef __FreeBSD__
	address.sin6_len = sizeof(address);
#endif
	address.sin6_port = htons(15547);
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return (2);
	}
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		error = errno;
		close(fd);
		if (error == ECONNREFUSED)
			return (1);
		errno = error;
		perror("connect");
		return (2);
	}
	close(fd);
	return (0);
}
