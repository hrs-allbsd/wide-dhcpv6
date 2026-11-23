# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

# Verify the raw TLVs in tcpdump -nn -x output from an isolated link.
function uint(hex,    chars, i, n)
{
	chars = "0123456789abcdef"
	n = 0
	for (i = 1; i <= length(hex); i++)
		n = n * 16 + index(chars, substr(hex, i, 1)) - 1
	return n
}

function packet(frame,    kind, size, p, code, len, data, n15, n16, n65535)
{
	if (frame == "")
		return
	# IPv6 header, then UDP (546 to 547), then the four-byte DHCPv6 header.
	if (substr(frame, 1, 1) != "6" || substr(frame, 13, 2) != "11" ||
	    substr(frame, 81, 8) != "02220223" || length(frame) < 104) {
		bad = 1
		return
	}
	size = 80 + uint(substr(frame, 89, 4)) * 2
	kind = uint(substr(frame, 97, 2))
	if (size != length(frame) || !(kind in names)) {
		bad = 1
		return
	}
	for (p = 105; p <= size; p += len + 8) {
		if (p + 7 > size) {
			bad = 1
			return
		}
		code = uint(substr(frame, p, 4))
		len = uint(substr(frame, p + 4, 4)) * 2
		if (p + 7 + len > size) {
			bad = 1
			return
		}
		data = substr(frame, p + 8, len)
		if (code == 15) {
			n15++
			bad = bad || data != "0003616263"
		} else if (code == 16) {
			n16++
			bad = bad || data != "0000040e0003616263"
		} else if (code == 65535) {
			n65535++
			bad = bad || len != 0
		}
	}
	if (n15 != 1 || n16 != 1 || n65535 != 1)
		bad = 1
	count[kind]++
}

BEGIN {
	names[1] = "Solicit"
	names[3] = "Request"
	names[5] = "Renew"
	names[8] = "Release"
}

/^[[:space:]]*0x[[:xdigit:]]+:/ {
	for (i = 2; i <= NF; i++)
		frame = frame tolower($i)
	next
}

{
	packet(frame)
	frame = ""
}

END {
	packet(frame)
	for (i = 1; i <= 8; i++) {
		if (!(i in names))
			continue
		printf "%s: %d packet(s) checked for raw options 15, 16 and 65535\n",
		    names[i], count[i]
		if (count[i] == 0)
			bad = 1
	}
	exit bad
}
