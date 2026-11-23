#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "Usage: $0 /absolute/path/to/new/prefix" >&2
	exit 1
fi
prefix=$1
case "$prefix" in
/*[![:alnum:]_./+-]* | / | '' | [!/]*)
	printf '%s\n' 'Use an absolute prefix without spaces or shell metacharacters.' >&2
	exit 1
	;;
esac

tests=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
vendor=$tests/vendor
platform=$(uname -s)
make_cmd=${MAKE:-make}
if [ "$platform" = FreeBSD ]; then
	make_cmd=${MAKE:-gmake}
	export CC="${CC:-cc}" CXX="${CXX:-c++}"
fi
jobs=${JOBS:-1}
case "$jobs" in
'' | *[!0-9]*)
	printf '%s\n' 'JOBS must be a positive integer.' >&2
	exit 1
	;;
esac
if [ "$jobs" -lt 1 ]; then
	printf '%s\n' 'JOBS must be a positive integer.' >&2
	exit 1
fi

for tool in "$make_cmd" "${PKG_CONFIG:-pkg-config}"; do
	command -v "$tool" >/dev/null || {
		printf 'Required build tool missing: %s\n' "$tool" >&2
		exit 1
	}
done

build=$(mktemp -d "${TMPDIR:-/tmp}/wide-dhcpv6-tools.XXXXXXXX")
trap 'rm -rf -- "$build"' EXIT
trap 'exit 1' HUP INT TERM

while read -r checksum archive; do
	if command -v sha256sum >/dev/null; then
		actual=$(sha256sum < "$vendor/$archive")
	elif command -v sha256 >/dev/null; then
		actual=$(sha256 -q "$vendor/$archive")
	else
		actual=$(shasum -a 256 < "$vendor/$archive")
	fi
	if [ "${actual%% *}" != "$checksum" ]; then
		printf 'Source checksum mismatch: %s\n' "$archive" >&2
		exit 1
	fi
	tar -xf "$vendor/$archive" -C "$build"
done < "$vendor/SHA256"

if [ "$platform" = FreeBSD ]; then
	patch -d "$build/kyua-0.15.2" -p1 < "$vendor/kyua-0.15.2-freebsd-jail-string.patch"
fi

mkdir -- "$prefix"
prefix=$(CDPATH= cd -- "$prefix" && pwd -P)
export MAKE="$make_cmd"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"

build_project()
(
	cd "$build/$1"
	shift
	./configure --prefix="$prefix" --libdir="$prefix/lib" "$@"
	"$make_cmd" -j "$jobs"
	"$make_cmd" install
)

(
	cd "$build/lua-5.4.8"
	"$make_cmd" -j "$jobs" CC="${CC:-cc}" MYCFLAGS=-fPIC posix
	"$make_cmd" INSTALL_TOP="$prefix" install
)
mkdir -p "$PKG_CONFIG_PATH"
cat > "$PKG_CONFIG_PATH/lua-5.4.pc" <<END
Name: Lua
Description: Lua bundled for WIDE-DHCPv6 testing
Version: 5.4.8
Cflags: -I$prefix/include
Libs: -L$prefix/lib -llua -lm
END
build_project sqlite-autoconf-3540100 --disable-readline --disable-static-shell
build_project atf-0.26 --disable-shared

export LDFLAGS="${LDFLAGS:+$LDFLAGS }-Wl,-rpath,$prefix/lib"
build_project lutok-0.6.2 --disable-atf
build_project kyua-0.15.2 --disable-atf --without-doxygen

printf 'Test tools installed in %s\n' "$prefix"
