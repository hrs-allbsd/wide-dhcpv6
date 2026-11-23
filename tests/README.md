# WIDE-DHCPv6 tests

The suite targets FreeBSD, NetBSD, OpenBSD, and Linux.
FreeBSD and Linux are the initial lifecycle backend targets.
NetBSD and OpenBSD lifecycle backends are planned.

Run `./tests/run.sh` from the source directory with Kyua and ATF
installed. FreeBSD uses `/usr/libexec/atf-sh` when available.
Otherwise the runner resolves `atf-sh` through `PATH`.

Use `KYUA` and `ATF_SH` to select alternate tool installations.
Arguments such as `-r /tmp/dhcp6-results.db` pass through to
`kyua test`.
