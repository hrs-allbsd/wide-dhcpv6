# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

# Linux network backend for the DHCPv6 lifecycle cases.
net_required_programs="ip chroot mknod"
net_capture_programs=
net_capture_user=root

net_require()
{
	if ! ip netns list >/dev/null 2>&1; then
		atf_skip "Requires Linux network namespace support"
	fi
}

net_libraries()
{
	local libraries

	libraries=$(ldd "$1") || return 1
	printf '%s\n' "$libraries" | awk '
		$2 == "=>" {
			if ($3 !~ /^\//)
				exit 1
			print $3
			next
		}
		$1 ~ /^\// { print $1 }
	'
}

net_link_up()
{
	local context="$1" interface="$2" address="$3"

	atf_check -s exit:0 ip -n "$context" link set dev "$interface" addrgenmode none
	atf_check -s exit:0 ip -n "$context" link set dev "$interface" up
	atf_check -s exit:0 ip -n "$context" -6 addr add "$address/64" dev "$interface" nodad
}

net_attach_uplink()
{
	local server_link="$1" client_link="$2"

	atf_check -s exit:0 ip -n "$server" link set dev "$server_link" name "$server_if"
	atf_check -s exit:0 ip -n "$client" link set dev "$client_link" name "$client_if"
	net_link_up "$server" "$server_if" fe80::1
	net_link_up "$client" "$client_if" fe80::2
}

net_create_uplink()
{
	local server_link="$1" client_link="$2"

	atf_check -s exit:0 ip -n "$server" link add "$server_link" type veth peer name "$client_link"
	atf_check -s exit:0 ip -n "$server" link set dev "$client_link" netns "$client"
}

net_setup()
{
	local role context

	server_if=swan
	client_if=cwan
	downstream=lan0
	for role in server client; do
		mkdir -p "$net/$role/dev" "$net/$role/etc" ||
		    atf_fail "Could not prepare $role test root"
		atf_check -s exit:0 mknod -m 666 "$net/$role/dev/null" c 1 3
		atf_check -s exit:0 mknod -m 666 "$net/$role/dev/urandom" c 1 9
		case "$role" in
		server) context="$server" ;;
		client) context="$client" ;;
		esac
		atf_check -s exit:0 ip netns add "$context"
		printf '%s\n' "$context" >> "$net/namespaces" ||
		    atf_fail "Could not record $role namespace"
	done
	net_create_uplink uplink-server uplink-client
	net_attach_uplink uplink-server uplink-client
	atf_check -s exit:0 ip -n "$client" link add "$downstream" type veth peer name lan1
	net_link_up "$client" "$downstream" fe80::3
	net_link_up "$client" lan1 fe80::4
}

net_loopback()
{
	atf_check -s exit:0 ip -n "$1" link set dev lo up
}

net_prepare_capture()
{
	printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' > "$net/server/etc/passwd" ||
	    atf_fail "Could not create the capture user"
}

net_replace_uplink()
{
	# Allocate the replacement before deleting the original interface.
	net_create_uplink uplink-server uplink-client
	atf_check -s exit:0 ip -n "$client" link del dev "$client_if"
	net_attach_uplink uplink-server uplink-client
}

has_addresses()
{
	local context="$1" interface="$2" pattern="$3" present="$4"
	local prefixlen="${5:-}" addresses

	addresses=$(ip -n "$context" -o -6 addr show dev "$interface") || return 1
	printf '%s\n' "$addresses" |
	    awk -v pattern="$pattern" -v present="$present" -v prefixlen="$prefixlen" '
		$3 == "inet6" {
			split($4, address, "/")
			if (address[1] ~ pattern && (!prefixlen || address[2] == prefixlen) &&
			    (!present || $0 !~ /tentative|dadfailed/))
				found = 1
		}
		END { exit ((found + 0) != present) }
	    '
}

net_link_scope()
{
	ip -n "$client" -o link show dev "$client_if" | awk -F: 'NR == 1 { print $1 }'
}

net_renewal_verified()
{
	# The Linux address ioctl does not expose address lifetimes.
	grep -Fq 'update an address 2001:db8:1::10 ' "$net/client.log"
}

net_show_leases()
{
	ip -n "$client" -6 addr show dev "$client_if" to 2001:db8:1::10/128
	ip -n "$client" -6 addr show dev "$downstream" to 2001:db8:2:1::/64
}

net_cleanup()
{
	local context pid status=0

	[ -s "$net/namespaces" ] || return 0
	while read -r context; do
		for pid in $(ip netns pids "$context"); do
			kill -KILL "$pid" 2>/dev/null || :
		done
		ip netns del "$context" || status=1
	done < "$net/namespaces"
	return "$status"
}
