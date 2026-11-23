# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

atf_test_case iana_iapd cleanup
iana_iapd_head()
{
	atf_set "descr" "Acquire, renew and release IA_NA and IA_PD over an isolated link"
	lifecycle_head
}

load_network_backend()
{
	case "$(uname -s)" in
	FreeBSD) . "$(atf_get_srcdir)/net-vnet.sh" ;;
	Linux) . "$(atf_get_srcdir)/net-netns.sh" ;;
	*) return 1 ;;
	esac
	net_exec="$(atf_get_srcdir)/net-exec.sh"
}

lifecycle_head()
{
	local programs="ldd readelf"

	if load_network_backend; then
		programs="$programs $net_required_programs"
	fi
	atf_set "require.user" "root"
	atf_set "require.progs" "$programs"
	atf_set "timeout" "90"
}

fail_with_logs()
{
	local log

	for log in "$net/server.log" "$net/client.log"; do
		if [ -f "$log" ]; then
			printf '\n--- %s ---\n' "${log##*/}" >&2
			tail -60 "$log" >&2
		fi
	done
	atf_fail "$*"
}

wait_until()
{
	local seconds="$1" description="$2" deadline

	shift 2
	deadline=$(($(date +%s) + seconds))
	until "$@"; do
		[ "$(date +%s)" -lt "$deadline" ] ||
		    fail_with_logs "Timed out waiting for $description"
		sleep 0.2
	done
}

setup_root()
{
	local root="$1" program="${3:-$bindir/$2}" binary="$2" loader libraries library

	mkdir -p "$root/run" "$root/var/db" ||
	    atf_fail "Could not create test directories"
	cp "$program" "$root/$binary" ||
	    atf_fail "Could not copy $binary into the test root"
	loader=$(readelf -l "$program" |
	    sed -n 's/.*Requesting program interpreter: \(\/[^]]*\)].*/\1/p')
	[ -n "$loader" ] || return 0
	libraries=$(net_libraries "$program") ||
	    atf_fail "Could not resolve the libraries for $binary"
	for library in $loader $libraries; do
		case "$library" in
		/*)
			mkdir -p "$root${library%/*}" &&
			    cp -L "$library" "$root$library" ||
			    atf_fail "Could not copy $library into the test root"
			;;
		*) atf_fail "Unresolved library for $binary: $library" ;;
		esac
	done
}

link_ready()
{
	has_addresses "$server" "$server_if" '^fe80:' 1 &&
	    has_addresses "$client" "$client_if" '^fe80:' 1
}

daemon_started()
{
	kill -0 "$1" 2>/dev/null || fail_with_logs "$2 exited during startup"
	[ -s "$3" ] && grep -Fq "$4" "$5"
}

leases_acquired()
{
	has_addresses "$client" "$client_if" '^2001:db8:1::10$' 1 128 &&
	    has_addresses "$client" "$downstream" '^2001:db8:2:1:' 1 64
}

start_server()
{
	rm -f "$net/server/run/server.pid" ||
	    fail_with_logs "Could not remove the previous server PID file"
	"$net_exec" "$server" "$net/server" /dhcp6s -D -f -c /dhcp6s.conf \
	    -P /run/server.pid -k /run/no-control-key "$server_if" > "$net/server.log" 2>&1 &
	server_pid=$!
	wait_until 10 "server startup" daemon_started "$server_pid" dhcp6s \
	    "$net/server/run/server.pid" 'skip opening control port' "$net/server.log"
}

leases_renewed()
{
	grep -Fq 'received renew from ' "$net/server.log" &&
	    grep -Eq 'update binding .*type=NA, iaid=0,' "$net/server.log" &&
	    grep -Eq 'update binding .*type=PD, iaid=1,' "$net/server.log" &&
	    grep -Fq 'update a prefix 2001:db8:2::/56 ' "$net/client.log" &&
	    leases_acquired && net_renewal_verified
}

leases_released()
{
	grep -Fq 'bound address 2001:db8:1::10 has been released' "$net/server.log" &&
	    grep -Fq 'bound prefix 2001:db8:2::/56 has been released' "$net/server.log" &&
	    has_addresses "$client" "$client_if" '^2001:db8:1::10$' 0 &&
	    has_addresses "$client" "$downstream" '^2001:db8:2:1:' 0
}

iana_iapd_body()
{
	local binary duid

	load_network_backend || atf_skip "Requires FreeBSD or Linux"
	net_require

	bindir=$(atf_config_get dhcp6_bindir "")
	case "$bindir" in
	'') atf_skip "Set DHCP6_TEST_BINDIR to the directory containing dhcp6c and dhcp6s" ;;
	/*) ;;
	*) atf_fail "DHCP6_TEST_BINDIR must be an absolute path" ;;
	esac
	for binary in dhcp6c dhcp6s; do
		[ -x "$bindir/$binary" ] || atf_fail "Missing $bindir/$binary"
	done
	export LC_ALL=C

	net=$(mktemp -d "$PWD/network.XXXXXXXX") || atf_fail "Could not create test directory"
	printf '%s\n' "$net" > topology
	server="wd6s_${net##*.}"
	client="wd6c_${net##*.}"
	setup_root "$net/server" dhcp6s "$bindir/dhcp6s"
	setup_root "$net/client" dhcp6c "$bindir/dhcp6c"
	net_setup
	wait_until 10 "IPv6 link-local addresses" link_ready

	cat > "$net/client/dhcp6c.conf" <<END
interface $client_if {
	send ia-na 0;
	send ia-pd 1;
};
id-assoc na 0 {
};
id-assoc pd 1 {
	prefix-interface $downstream {
		sla-id 1;
		sla-len 8;
	};
};
END
	"$net_exec" "$client" "$net/client" /dhcp6c -D -f -c /dhcp6c.conf \
	    -p /run/client.pid -k /run/no-control-key "$client_if" > "$net/client.log" 2>&1 &
	client_pid=$!
	wait_until 10 "client startup" daemon_started "$client_pid" dhcp6c \
	    "$net/client/run/client.pid" 'reset a timer' "$net/client.log"
	# The DUID file begins with its two-byte length.
	duid=$(od -An -v -tx1 -j2 "$net/client/var/db/dhcp6c_duid" |
	    awk '{ for (i = 1; i <= NF; i++) printf "%s%s", n++ ? ":" : "", $i }')
	[ -n "$duid" ] || fail_with_logs "Could not read the client DUID"

	cat > "$net/server/dhcp6s.conf" <<END
host client {
	duid $duid;
	address 2001:db8:1::10 40 80;
	prefix 2001:db8:2::/56 40 80;
};
END
	start_server

	wait_until 15 "installation of the IA_NA address and IA_PD subnet" leases_acquired
	printf '%s\n' 'Acquired IA_NA 2001:db8:1::10 and IA_PD 2001:db8:2::/56'
	net_show_leases
	wait_until 30 "Renew and update of both bindings" leases_renewed
	printf '%s\n' 'Renewed both IA_NA and IA_PD bindings'
	net_show_leases
	kill -TERM "$client_pid" || fail_with_logs "Could not stop dhcp6c for Release"
	wait_until 10 "server Release and removal of both client addresses" leases_released
	printf '%s\n' 'Server released both bindings and the client removed both addresses'
	wait "$client_pid" || fail_with_logs "dhcp6c did not exit successfully"
}

iana_iapd_cleanup()
{
	local net

	[ -s topology ] || return 0
	read -r net < topology
	load_network_backend || return 1
	net_cleanup || atf_fail "Could not remove all test network resources"
}

atf_init_test_cases()
{
	atf_add_test_case iana_iapd
}
