/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 Hiroki Sato <hrs@FreeBSD.org> */

#include <sys/time.h>

#include <stdio.h>

struct dhcp6_timer;

void __real_dhcp6_set_timer(struct timeval *, struct dhcp6_timer *);
void __wrap_dhcp6_set_timer(struct timeval *, struct dhcp6_timer *);

void
__wrap_dhcp6_set_timer(struct timeval *interval, struct dhcp6_timer *timer)
{
	struct timeval shortened = { .tv_sec = 8 };

	if (interval->tv_sec == 3600 && interval->tv_usec == 0) {
		fputs("retry test timer: requested 3600s, running 8s\n", stderr);
		__real_dhcp6_set_timer(&shortened, timer);
		return;
	}
	__real_dhcp6_set_timer(interval, timer);
}
