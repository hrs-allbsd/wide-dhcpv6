# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

atf_test_case iana_iapd cleanup
iana_iapd_head()
{
	atf_set "descr" "Acquire, renew and release IA_NA and IA_PD over an isolated link"
	lifecycle_head
}

atf_test_case dns_search_reload cleanup
dns_search_reload_head()
{
	atf_set "descr" "Receive DNS servers and search domains before and after reload"
	lifecycle_head
}

dns_search_reload_body()
{
	lifecycle_setup
	verify_dns_search_reload
}

dns_search_reload_cleanup()
{
	iana_iapd_cleanup
}

atf_test_case interface_restart cleanup
interface_restart_head()
{
	atf_set "descr" "Reacquire IA_NA and IA_PD after replacing the interface"
	lifecycle_head
}

interface_restart_body()
{
	lifecycle_setup
	setup_root "$net/client" dhcp6ctl
	net_loopback "$client"
	printf '%s\n' 'Y3RsLXRlc3Qta2V5' > "$net/client/run/control.key"
	start_lease_exchange /run/control.key
	verify_interface_restart
}

interface_restart_cleanup()
{
	iana_iapd_cleanup
}

atf_test_case raw_option cleanup
raw_option_head()
{
	atf_set "descr" "Check raw option bytes on the wire during the DHCPv6 lifecycle"
	lifecycle_head capture
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
		if [ "${1:-}" = capture ]; then
			programs="$programs tcpdump $net_capture_programs"
		fi
	fi
	atf_set "require.user" "root"
	atf_set "require.progs" "$programs"
	atf_set "timeout" "90"
}

fail_with_logs()
{
	local log

	for log in "$net/server.log" "$net/client.log" "$net/capture.log"; do
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
	local key="${1:-/run/no-control-key}" ready="${2-skip opening control port}"

	rm -f "$net/server/run/server.pid" ||
	    fail_with_logs "Could not remove the previous server PID file"
	"$net_exec" "$server" "$net/server" /dhcp6s -D -f -c /dhcp6s.conf \
	    -P /run/server.pid -k "$key" "$server_if" > "$net/server.log" 2>&1 &
	server_pid=$!
	wait_until 10 "server startup" daemon_started "$server_pid" dhcp6s \
	    "$net/server/run/server.pid" "$ready" "$net/server.log"
}

query_dns_options()
{
	local expected="$1" result="$net/client/run/dns-options" received

	rm -f "$result" || fail_with_logs "Could not remove the old DNS result"
	"$net_exec" "$client" "$net/client" /dhcp6c -D -f -c /dhcp6c.conf \
	    -p /run/client.pid -k /run/no-control-key "$client_if" > "$net/client.log" 2>&1 &
	client_pid=$!
	wait_until 12 "DNS options in an Information-request Reply" grep -qs '^search=' "$result"
	received=$(sed 's/[[:blank:]]*$//' "$result")
	printf '%s\n' "$received"
	[ "$received" = "$expected" ] || fail_with_logs "Unexpected DNS options"
	kill -TERM "$client_pid" || fail_with_logs "Could not stop dhcp6c"
	wait "$client_pid" || fail_with_logs "dhcp6c did not exit successfully"
}

verify_dns_search_reload()
{
	local server_config="$net/server/dhcp6s.conf"

	wait_until 10 "IPv6 link-local addresses" link_ready

	mkdir -p "$net/client/bin" || atf_fail "Could not create the client bin directory"
	setup_root "$net/client" bin/sh /bin/sh
	setup_root "$net/server" dhcp6ctl
	net_loopback "$server"
	printf '%s\n' 'Y3RsLXRlc3Qta2V5' > "$net/server/run/control.key"
	cat > "$net/client/dhcp6c.conf" <<END
interface $client_if {
	information-only;
	request domain-name-servers;
	request domain-name;
	script "/dns-options";
};
END
	cat > "$net/client/dns-options" <<'END'
#!/bin/sh
[ -n "$new_domain_name" ] || exit 0
printf 'servers=%s\nsearch=%s\n' "$new_domain_name_servers" "$new_domain_name" \
    > /run/dns-options
END
	chmod 0755 "$net/client/dns-options" || atf_fail "Could not set hook permissions"
	cat > "$server_config" <<'END'
option domain-name-servers 2001:db8::35 2001:db8::36;
option domain-name "campus.example";
option domain-name "lab.example.";
END
	start_server /run/control.key ''
	printf '%s\n' 'Initial DNS options'
	query_dns_options 'servers=2001:db8::35 2001:db8::36
search=campus.example. lab.example.'

	cat > "$server_config" <<'END'
option domain-name-servers 2001:db8::54;
option domain-name "updated.example";
END
	atf_check -s exit:0 "$net_exec" "$server" "$net/server" /dhcp6ctl -S -k /run/control.key reload
	wait_until 10 "server to reload its DNS configuration" \
	    grep -Fq 'server reloaded' "$net/server.log"
	printf '%s\n' 'Reloaded DNS options'
	query_dns_options 'servers=2001:db8::54
search=updated.example.'
	kill -0 "$server_pid" || fail_with_logs "Server process changed during reload"
}

verify_interface_restart()
{
	local old_scope new_scope pid

	old_scope=$(net_link_scope)
	[ -n "$old_scope" ] || fail_with_logs "Missing original link scope"
	atf_check -s exit:0 "$net_exec" "$client" "$net/client" /dhcp6ctl -C -k /run/control.key \
	    stop interface "$client_if"
	wait_until 10 "release of both leases before replacing the link" leases_released
	kill -TERM "$server_pid" || fail_with_logs "Could not stop dhcp6s"
	wait "$server_pid" || fail_with_logs "dhcp6s did not exit successfully"

	net_replace_uplink
	wait_until 10 "replacement link-local addresses" link_ready
	new_scope=$(net_link_scope)
	[ -n "$new_scope" ] && [ "$old_scope" != "$new_scope" ] ||
	    fail_with_logs "Replacement did not change the interface index"
	printf 'Replaced %s with link scope %s -> %s\n' "$client_if" "$old_scope" "$new_scope"

	start_server
	atf_check -s exit:0 "$net_exec" "$client" "$net/client" /dhcp6ctl -C -k /run/control.key \
	    start interface "$client_if"
	wait_until 15 "IA_NA and IA_PD on the replacement interface" leases_acquired
	read -r pid < "$net/client/run/client.pid"
	[ "$pid" = "$client_pid" ] && kill -0 "$client_pid" 2>/dev/null ||
	    fail_with_logs "Client process changed during the interface restart"
	printf '%s\n' 'Reacquired IA_NA and IA_PD with the same client process'
	net_show_leases
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

lifecycle_setup()
{
	local binary

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
}

start_lease_exchange()
{
	local key="${1:-/run/no-control-key}" options="${2:-}" duid

	wait_until 10 "IPv6 link-local addresses" link_ready

	cat > "$net/client/dhcp6c.conf" <<END
interface $client_if {
	send ia-na 0;
	send ia-pd 1;
	$options
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
	    -p /run/client.pid -k "$key" "$client_if" > "$net/client.log" 2>&1 &
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
}

verify_lease_lifecycle()
{
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

capture_start()
{
	local filter="$1"
	net_prepare_capture
	if [ -n "$net_capture_user" ]; then
		set -- -Z "$net_capture_user"
	else
		set --
	fi
	"$net_exec" "$server" "$net/server" /tcpdump "$@" -n -U --immediate-mode \
	    -s 0 -i "$server_if" -w - \
	    "$filter" \
	    > "$net/client.pcap" 2> "$net/capture.log" &
	capture_pid=$!
	wait_until 10 "tcpdump capture to start" grep -Fq 'listening on' "$net/capture.log"
}

capture_ready()
{
	tcpdump -nn -x -r "$net/client.pcap" 2>/dev/null |
	    awk -f "$(atf_get_srcdir)/raw-option-wire.awk" > /dev/null
}

capture_verify()
{
	local artifacts

	wait_until 5 "all four DHCPv6 message types in the capture" capture_ready
	kill -INT "$capture_pid" || fail_with_logs "Could not stop tcpdump"
	wait "$capture_pid" || fail_with_logs "tcpdump exited unsuccessfully"
	tcpdump -nn -x -r "$net/client.pcap" > "$net/client.hex" ||
	    fail_with_logs "Could not decode captured packets"
	awk -f "$(atf_get_srcdir)/raw-option-wire.awk" "$net/client.hex" ||
	    fail_with_logs "Unexpected raw options in captured DHCPv6 packets"
	if grep -Eiq '00:03:61:62:63|00:00:04:0e:00:03:61:62:63' "$net/client.log"; then
		fail_with_logs "Raw payload written to the client log"
	fi
	artifacts=$(atf_config_get dhcp6_artifacts "")
	if [ -n "$artifacts" ]; then
		atf_check -s exit:0 cp "$net/client.pcap" "$artifacts/raw-option.pcap"
		atf_check -s exit:0 cp "$net/client.hex" "$artifacts/raw-option-wire.txt"
	fi
}

iana_iapd_body()
{
	lifecycle_setup
	start_lease_exchange
	verify_lease_lifecycle
}

raw_option_body()
{
	local options='send raw-option 15 00:03:61:62:63,
	    raw-option 16 00:00:04:0e:00:03:61:62:63;
	send raw-option 65535 "";'

	lifecycle_setup
	setup_root "$net/server" tcpdump "$(command -v tcpdump)"
	capture_start 'ip6 and udp and src port 546 and dst port 547'
	start_lease_exchange /run/no-control-key "$options"
	verify_lease_lifecycle
	capture_verify
}

raw_option_cleanup()
{
	iana_iapd_cleanup
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
	atf_add_test_case dns_search_reload
	atf_add_test_case interface_restart
	atf_add_test_case raw_option
}
