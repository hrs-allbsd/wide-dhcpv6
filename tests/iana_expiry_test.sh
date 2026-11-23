# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

atf_test_case linux_iana_expiry cleanup
linux_iana_expiry_head()
{
	atf_set "descr" "Renew an existing IA_NA on Linux and expire it at the renewed deadline"
	atf_set "require.user" "root"
	atf_set "require.progs" "ip strace"
	atf_set "timeout" "115"
}

fail_lease()
{
	tail -50 client.log server.log client.ioctl >&2 || :
	atf_fail "$*"
}

wait_lease()
{
	local deadline=$(( $(date +%s) + $1 )) label="$2"

	shift 2
	until "$@"; do
		[ "$(date +%s)" -lt "$deadline" ] || fail_lease "Timed out waiting for $label"
		sleep 0.2
	done
}

assigned()
{
	ip -n "$client" -6 addr show dev "$1" |
	    grep -Eq "$2"
}

na_present()
{
	assigned cwan 'inet6 2001:db8:1::10/128'
}

pd_present()
{
	assigned lan0 'inet6 2001:db8:2:1:[^ ]*/64'
}

renewed()
{
	grep -Eq 'SIOCSIFADDR.* = -1 EEXIST' client.ioctl &&
	    grep -Fq 'update an address 2001:db8:1::10' client.log &&
	    grep -Fq 'update a prefix 2001:db8:2::/56' client.log &&
	    grep -Eq 'update binding .*type=NA, iaid=0' server.log &&
	    grep -Eq 'update binding .*type=PD, iaid=1' server.log
}

na_gone()
{
	! na_present
}

linux_iana_expiry_body()
{
	local bindir localdb token client server wan_a wan_b duid
	local acquired received now expired

	[ "$(uname -s)" = Linux ] || atf_skip "Requires Linux network namespaces"
	bindir=$(atf_config_get dhcp6_bindir "")
	localdb=$(atf_config_get dhcp6_linux_dbdir "")
	[ -x "$bindir/dhcp6c" ] && [ -x "$bindir/dhcp6s-expiry-test" ] &&
	    [ -n "$localdb" ] || atf_skip "Requires the Linux VM fixture and its lease directory"
	token=$(basename "$(mktemp -d "$PWD/ns.XXXXXXXX")")
	token=${token#ns.}
	client="c-$token"
	server="s-$token"
	wan_a="a$token"
	wan_b="b$token"
	printf '%s\n' "$client" "$server" "$wan_a" "$wan_b" > topology
	touch client.log server.log client.ioctl
	atf_check -s exit:0 ip netns add "$server"
	atf_check -s exit:0 ip netns add "$client"
	atf_check -s exit:0 ip link add "$wan_a" type veth peer name "$wan_b"
	atf_check -s exit:0 ip link set "$wan_a" netns "$server"
	atf_check -s exit:0 ip link set "$wan_b" netns "$client"
	atf_check -s exit:0 ip -n "$server" link set "$wan_a" name swan
	atf_check -s exit:0 ip -n "$client" link set "$wan_b" name cwan
	atf_check -s exit:0 ip -n "$client" link add lan0 type veth peer name lan1
	for name in cwan lo lan0 lan1; do
		atf_check -s exit:0 ip -n "$client" link set "$name" up
	done
	atf_check -s exit:0 ip -n "$server" link set lo up
	atf_check -s exit:0 ip -n "$server" link set swan up
	atf_check -s exit:0 ip -n "$server" -6 addr add fe80::1/64 dev swan nodad
	atf_check -s exit:0 ip -n "$client" -6 addr add fe80::2/64 dev cwan nodad
	atf_check -s exit:0 ip -n "$client" -6 addr add fe80::3/64 dev lan0 nodad

	cat > dhcp6c.conf <<'END'
interface cwan {
	send ia-na 0;
	send ia-pd 1;
};
id-assoc na 0 {
};
id-assoc pd 1 {
	prefix-interface lan0 {
		sla-id 1;
		sla-len 8;
	};
};
END
	ip netns exec "$client" strace -f -e trace=ioctl -o "$PWD/client.ioctl" \
	    "$bindir/dhcp6c" -D -f -c "$PWD/dhcp6c.conf" -p "$PWD/client.pid" \
	    -k "$PWD/no-key" cwan > client.log 2>&1 &
	wait_lease 10 "client startup" test -s client.pid
	duid=$(od -An -v -tx1 -j2 "$localdb/dhcp6c_duid" |
	    awk '{ for (i = 1; i <= NF; i++) printf "%s%s", n++ ? ":" : "", $i }')
	[ -n "$duid" ] || fail_lease "Could not read client DUID"
	cat > dhcp6s.conf <<END
host client {
	duid $duid;
	address 2001:db8:1::10 40 42;
	prefix 2001:db8:2::/56 40 95;
};
END
	ip netns exec "$server" "$bindir/dhcp6s-expiry-test" -D -f \
	    -c "$PWD/dhcp6s.conf" -P "$PWD/server.pid" -k "$PWD/no-key" swan > server.log 2>&1 &
	wait_lease 12 "IA_NA and IA_PD acquisition" na_present
	pd_present || fail_lease "IA_PD was not installed"
	acquired=$(date +%s)
	wait_lease 28 "IA_NA renewal returning EEXIST and successful IA_PD renewal" renewed
	received=$(date +%s)
	printf 'Acquired IA_NA and IA_PD at %s; renewed both at %s\n' "$acquired" "$received"
	grep -E 'SIOCSIFADDR.* = -1 EEXIST' client.ioctl
	now=$(date +%s)
	[ "$now" -lt "$((acquired + 44))" ] || fail_lease "Initial deadline already passed"
	sleep "$((acquired + 44 - now))"
	na_present && pd_present || fail_lease "An assignment vanished at the original deadline"
	printf 'IA_NA and IA_PD still present after the original 42-second validity\n'
	wait_lease 28 "IA_NA expiry at its renewed deadline" na_gone
	expired=$(date +%s)
	[ "$expired" -ge "$((received + 39))" ] &&
	    [ "$expired" -le "$((received + 46))" ] ||
	    fail_lease "Expired outside the renewed deadline window: $expired versus $received"
	sleep 2
	na_gone && pd_present || fail_lease "Unexpected IA_NA or missing IA_PD after expiry"
	grep -Fq 'remove an address 2001:db8:1::10' client.log ||
	    fail_lease "Missing client expiry event"
	if grep -Fq 'remove a site prefix' client.log; then
		fail_lease "The delegated prefix was removed during the test"
	fi
	printf 'IA_NA expired %ss after Renew; IA_PD remained configured\n' "$((expired - received))"
	artifacts=$(atf_config_get dhcp6_artifacts "")
	if [ -n "$artifacts" ]; then
		cp client.log "$artifacts/linux-client.log"
		cp server.log "$artifacts/linux-server.log"
		cp client.ioctl "$artifacts/linux-client.ioctl"
	fi
}

linux_iana_expiry_cleanup()
{
	local client server wan_a wan_b namespace pid

	[ -f topology ] || return 0
	read -r client < topology
	server=$(sed -n '2p' topology)
	wan_a=$(sed -n '3p' topology)
	wan_b=$(sed -n '4p' topology)
	for namespace in "$client" "$server"; do
		for pid in $(ip netns pids "$namespace" 2>/dev/null); do
			kill -KILL "$pid" 2>/dev/null || :
		done
		ip netns del "$namespace" 2>/dev/null || :
	done
	for device in "$wan_a" "$wan_b"; do
		ip link del "$device" 2>/dev/null || :
	done
}

atf_init_test_cases()
{
	atf_add_test_case linux_iana_expiry
}
