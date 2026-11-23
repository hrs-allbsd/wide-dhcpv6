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

## Run the DHCPv6 lifecycle on FreeBSD or Linux

The same ATF cases use two isolated network contexts with private filesystem
roots. FreeBSD uses VNET jails and epair. Linux uses named network namespaces,
veth, and chroot. Run the suite with root privileges in a dedicated test
environment. FreeBSD requires the epair cloner and devfs/BPF for packet
capture. Linux requires iproute2, IPv6 and veth support, and permission to
create network namespaces, mount, and chroot. Both require tcpdump for the
wire cases.

In a disposable FreeBSD build directory, configure and build with:

```sh
./configure --with-localdbdir=/var/db
gmake -f tests/fixtures.mk
```

On Linux, use the same local database path so each chroot gets its own DUID.
For GCC 15 and glibc, use these configure flags:

```sh
MAKE=gmake CC=cc YACC=yacc \
    CFLAGS='-O0 -g -std=gnu17 -D_GNU_SOURCE -include time.h -D__unused=' \
    ./configure --with-localdbdir=/var/db
gmake -f tests/fixtures.mk
```

Then run the common lifecycle cases:

```sh
sudo env DHCP6_TEST_BINDIR="$PWD" ./tests/run.sh ia_lifecycle_test
```

The suite checks IA_NA and IA_PD acquisition, renewal and release, DNS
option reload, interface replacement, raw options, delayed retries, control
listener startup, and Advertise selection. FreeBSD checks the refreshed
kernel IA_NA lifetime with ifconfig. Linux checks the client's renewal
log and verifies the addresses remain configured. The separate Linux
`iana_expiry_test` checks the renewed expiry deadline.

## Build the bundled tools

A POSIX shell, C and C++20 compilers with their standard libraries, GNU make,
pkg-config, tar and a SHA-256 utility are required. The release archives include
their generated build files. The script builds the tools and their library
dependencies from the checked-in sources without downloading additional files.
Give it a new, absolute installation directory owned by the current user.
`CC`, `CXX`, `MAKE`, `PKG_CONFIG` and `JOBS` can be set in the environment.
The FreeBSD build defaults to the base `cc` and `c++` drivers and `gmake`.

```sh
prefix=/tmp/wide-dhcpv6-tools
JOBS=4 ./tests/build-tools.sh "$prefix"
KYUA="$prefix/bin/kyua" ATF_SH="$prefix/bin/atf-sh" ./tests/run.sh
```

The installation is for test use. Use a fresh prefix when retrying a failed
installation. The default build and test scratch directories are temporary.
See [vendor/README.md](vendor/README.md) for the source versions and licenses.

`ia_lifecycle_test:raw_option` runs the same lifecycle with raw options 15,
16, and 65535 configured. It captures client traffic on the isolated server
context's test link with tcpdump and checks the exact options in Solicit,
Request, Renew, and Release. FreeBSD also needs BPF and a temporary devfs
mount. Cleanup removes the test topology and the temporary mount.
