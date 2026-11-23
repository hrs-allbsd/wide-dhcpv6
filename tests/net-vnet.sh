# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

# FreeBSD network backend for the DHCPv6 lifecycle cases.
net_required_programs="/sbin/ifconfig /usr/sbin/jail /usr/sbin/jexec /usr/sbin/jls"
net_capture_programs="/sbin/mount /sbin/umount"
net_capture_user=

net_require()
{
	[ "$(sysctl -n security.jail.jailed)" = 0 ] ||
	    atf_skip "Requires a FreeBSD host outside a jail"
	ifconfig -C | tr ' ' '\n' | grep -qx epair ||
	    atf_skip "Requires the epair interface cloner"
}

net_libraries()
{
	ldd -f '%p\n' "$1"
}

net_setup()
{
	local downstream_peer interface

	atf_check -s exit:0 jail -c "name=$server" "path=$net/server" vnet persist
	printf '%s\n' "$server" > "$net/jails" || atf_fail "Could not record server jail"
	atf_check -s exit:0 jail -c "name=$client" "path=$net/client" vnet persist
	printf '%s\n' "$client" >> "$net/jails" || atf_fail "Could not record client jail"
	ifconfig epair create > "$net/uplink" || atf_fail "Could not create uplink"
	ifconfig epair create > "$net/downlink" || atf_fail "Could not create downlink"
	read -r server_if < "$net/uplink"
	read -r downstream < "$net/downlink"
	client_if="${server_if%a}b"
	downstream_peer="${downstream%a}b"
	atf_check -s exit:0 ifconfig "$server_if" vnet "$server"
	for interface in "$client_if" "$downstream" "$downstream_peer"; do
		atf_check -s exit:0 ifconfig "$interface" vnet "$client"
	done
	atf_check -s exit:0 ifconfig -j "$server" "$server_if" inet6 -ifdisabled auto_linklocal up
	for interface in "$client_if" "$downstream" "$downstream_peer"; do
		atf_check -s exit:0 ifconfig -j "$client" "$interface" inet6 -ifdisabled auto_linklocal up
	done
}

net_loopback()
{
	atf_check -s exit:0 ifconfig -j "$1" lo0 inet6 ::1 prefixlen 128 up
}

net_prepare_capture()
{
	mkdir "$net/server/dev" || fail_with_logs "Could not create capture devfs mount point"
	mount -t devfs devfs "$net/server/dev" ||
	    fail_with_logs "Could not mount capture devfs"
	touch "$net/capture-devfs" || atf_fail "Could not record capture devfs mount"
}

net_replace_uplink()
{
	local replacement replacement_peer

	# Attach the replacement before destroying the old pair so that their
	# interface indices differ even if indices are reused.
	ifconfig epair create > "$net/replacement" ||
	    fail_with_logs "Could not create replacement uplink"
	read -r replacement < "$net/replacement"
	replacement_peer="${replacement%a}b"
	atf_check -s exit:0 ifconfig "$replacement" vnet "$server"
	atf_check -s exit:0 ifconfig "$replacement_peer" vnet "$client"
	atf_check -s exit:0 ifconfig -j "$client" "$client_if" destroy
	atf_check -s exit:0 -o ignore ifconfig -j "$server" "$replacement" name "$server_if"
	atf_check -s exit:0 -o ignore ifconfig -j "$client" "$replacement_peer" name "$client_if"
	atf_check -s exit:0 ifconfig -j "$server" "$server_if" inet6 -ifdisabled auto_linklocal up
	atf_check -s exit:0 ifconfig -j "$client" "$client_if" inet6 -ifdisabled auto_linklocal up
}

has_addresses()
{
	local jail="$1" interface="$2" pattern="$3" present="$4"
	local prefixlen="${5:-}" addresses

	addresses=$(ifconfig -j "$jail" "$interface" inet6) || return 1
	printf '%s\n' "$addresses" |
	    awk -v pattern="$pattern" -v present="$present" -v prefixlen="$prefixlen" '
		$1 == "inet6" && $2 ~ pattern &&
		    (!present || $0 !~ /tentative|duplicated/) &&
		    (!prefixlen || $0 ~ (" prefixlen " prefixlen "([[:space:]]|$)")) {
			found = 1
		}
		END { exit ((found + 0) != present) }
	    '
}

net_link_scope()
{
	ifconfig -j "$client" "$client_if" inet6 |
	    awk '$1 == "inet6" && $2 ~ /^fe80:/ && $0 !~ /tentative|duplicated/ {
		for (i = 3; i < NF; i++)
			if ($i == "scopeid") {
				print $(i + 1)
				exit
			}
	    }'
}

net_renewal_verified()
{
	local addresses

	addresses=$(ifconfig -j "$client" -L "$client_if" inet6) || return 1
	printf '%s\n' "$addresses" | awk '
		$1 == "inet6" && $2 == "2001:db8:1::10" {
			# The 80s valid lifetime has already run for at least T1 (20s).
			for (i = 3; i < NF; i++)
				if ($i == "vltime" && $(i + 1) ~ /^[0-9]+$/ &&
				    $(i + 1) >= 70)
					refreshed = 1
		}
		END { exit !refreshed }
	'
}

net_show_leases()
{
	ifconfig -j "$client" -L "$client_if" inet6 |
	    awk '$1 == "inet6" && $2 == "2001:db8:1::10" { print }'
	ifconfig -j "$client" -L "$downstream" inet6 |
	    awk '$1 == "inet6" && $2 ~ /^2001:db8:2:1:/ { print }'
}

net_cleanup()
{
	local jail file interface status=0

	if [ -f "$net/jails" ]; then
		while read -r jail; do
			if jls -j "$jail" jid >/dev/null 2>&1; then
				jail -r "$jail" || status=1
			fi
		done < "$net/jails"
	fi
	if [ -f "$net/capture-devfs" ]; then
		umount "$net/server/dev" || status=1
	fi
	for file in "$net/uplink" "$net/downlink" "$net/replacement"; do
		[ -s "$file" ] || continue
		read -r interface < "$file"
		if ifconfig "$interface" >/dev/null 2>&1; then
			ifconfig "$interface" destroy || status=1
		fi
	done
	return "$status"
}
