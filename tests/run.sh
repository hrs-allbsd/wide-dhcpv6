#!/bin/sh
set -eu

tests=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kyua=${KYUA:-kyua}
if [ -z "${ATF_SH:-}" ] && [ "$(uname -s)" = FreeBSD ] &&
    [ -x /usr/libexec/atf-sh ]; then
	atf_sh=/usr/libexec/atf-sh
else
	atf_sh=$(command -v "${ATF_SH:-atf-sh}") || {
		printf '%s\n' 'atf-sh is required. See tests/README.md.' >&2
		exit 1
	}
fi
case "$atf_sh" in
/*) ;;
*)
	printf '%s\n' 'ATF_SH must resolve to an absolute path.' >&2
	exit 1
	;;
esac
command -v "$kyua" >/dev/null || {
	printf '%s\n' 'Kyua is required. See tests/README.md.' >&2
	exit 1
}

build=$(mktemp -d "${TMPDIR:-/tmp}/wide-dhcpv6-tests.XXXXXXXX")
trap 'rm -rf -- "$build"' EXIT
trap 'exit 1' HUP INT TERM

printf '%s\n' "$atf_sh" > "$build/atf-sh-path"
for helper in "$tests/"net-*.sh "$tests/"*-wire.awk; do
	[ -f "$helper" ] || continue
	cp -p "$helper" "$build/"
done
for source in "$tests"/*_test.sh; do
	[ -f "$source" ] || continue
	name=$(basename "$source" .sh)
	cat > "$build/$name" <<'WRAPPER'
#!/bin/sh
dir=${0%/*}
IFS= read -r atf_sh < "$dir/atf-sh-path" || exit 1
exec "$atf_sh" "$0.atf" "$@"
WRAPPER
	cp "$source" "$build/$name.atf"
	chmod +x "$build/$name"
done

set -- test --kyuafile="$tests/Kyuafile" --build-root="$build" "$@"
if [ -n "${DHCP6_TEST_BINDIR:-}" ]; then
	set -- -v "test_suites.wide-dhcpv6.dhcp6_bindir=$DHCP6_TEST_BINDIR" "$@"
fi
"$kyua" "$@"
