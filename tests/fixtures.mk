# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

# GNU make entry point for the lifecycle test fixtures.
.PHONY: fixtures
fixtures: dhcp6c dhcp6s dhcp6ctl dhcp6c-retry-test dhcp6s-retry-test

include Makefile

.DELETE_ON_ERROR:
.INTERMEDIATE: dhcp6s-retry-test.c

dhcp6c-retry-test: $(CLIENTOBJS) $(LIBOBJS) tests/refused-retry-clock.o
	$(CC) $(LDFLAGS) -Wl,--wrap=dhcp6_set_timer -o $@ $^ $(LIBS)

dhcp6s-retry-test.c: dhcp6s.c tests/refused-retry-server.patch
	patch -o $@ $< < $(word 2,$^)

dhcp6s-retry-test: dhcp6s-retry-test.o $(filter-out dhcp6s.o,$(SERVOBJS)) $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
