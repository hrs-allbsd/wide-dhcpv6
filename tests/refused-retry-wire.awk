# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

# Decode the isolated IPv6/UDP exchange from tcpdump -tt -nn -x.
function uint(hex,    chars, i, n)
{
	chars = "0123456789abcdef"
	n = 0
	for (i = 1; i <= length(hex); i++)
		n = n * 16 + index(chars, substr(hex, i, 1)) - 1
	return n
}

function packet(frame, stamp,    kind, xid, p, size, code, len, q, subcode, sublen, na, pd, denied, prefix, renew)
{
	if (frame == "")
		return
	if (length(frame) < 104 || substr(frame, 1, 1) != "6" ||
	    substr(frame, 13, 2) != "11" ||
	    (substr(frame, 81, 8) != "02220223" &&
	    substr(frame, 85, 4) != "0222")) {
		bad = 1
		return
	}
	size = 80 + uint(substr(frame, 89, 4)) * 2
	if (size != length(frame)) {
		bad = 1
		return
	}
	kind = uint(substr(frame, 97, 2))
	xid = substr(frame, 99, 6)
	for (p = 105; p <= size; p += len + 8) {
		code = uint(substr(frame, p, 4))
		len = uint(substr(frame, p + 4, 4)) * 2
		if (p + 7 + len > size) {
			bad = 1
			return
		}
		if (code == 13 && len >= 4 && substr(frame, p + 8, 4) == "0002")
			denied = 1
		if ((code != 3 && code != 25) || len < 24)
			continue
		if (code == 3 && substr(frame, p + 8, 8) == "00000000")
			na = 1
		if (code == 25 && substr(frame, p + 8, 8) == "00000001")
			pd = 1
		for (q = p + 32; q < p + 8 + len; q += sublen + 8) {
			subcode = uint(substr(frame, q, 4))
			sublen = uint(substr(frame, q + 4, 4)) * 2
			if (q + 8 + sublen > p + 8 + len) {
				bad = 1
				return
			}
			if (code == 3 && subcode == 13 && sublen >= 4 &&
			    substr(frame, q + 8, 4) == "0002")
				denied = 1
			if (code == 25 && subcode == 26 && sublen >= 50 &&
			    uint(substr(frame, q + 16, 8)) > 0 &&
			    substr(frame, q + 24, 34) == "3820010db8000200000000000000000000")
				prefix = 1
		}
	}
	printf "%.6f %s %s NA=%d PD=%d NoAddrsAvail=%d prefix=%d\n",
	    stamp, names[kind], xid, na, pd, denied, prefix
	if (kind == 1 && na && pd)
		initial = 1
	if (kind == 3 && na && pd)
		request[xid] = 1
	if (kind == 7 && (xid in request) && na && pd && denied && prefix)
		refused = stamp
	if (kind == 5 && pd && !na)
		renewals[xid] = stamp
	if (kind == 7 && (xid in renewals) && pd && !na && prefix)
		renewed = 1
	if (kind == 1 && refused != 0) {
		if (!na || pd)
			bad = 1
		if (!(xid in sends)) {
			order[++exchanges] = xid
			start[xid] = stamp
		}
		sends[xid]++
		last[xid] = stamp
	}
	if (kind == 2 && denied && (xid in sends))
		rejections[xid]++
}

BEGIN {
	names[1] = "Solicit"; names[2] = "Advertise"; names[3] = "Request"
	names[5] = "Renew"; names[7] = "Reply"
}

/^[[:space:]]*0x[[:xdigit:]]+:/ {
	for (i = 2; i <= NF; i++)
		frame = frame tolower($i)
	next
}

/^[0-9]+\.[0-9]+ / {
	packet(frame, stamp)
	stamp = $1 + 0
	frame = ""
}

END {
	packet(frame, stamp)
	if (diagnostics)
		printf "initial=%d refused=%.6f renewed=%d exchanges=%d malformed=%d\n",
		    initial, refused, renewed, exchanges, bad
	first = order[1]
	second = order[2]
	first_delay = start[first] - refused
	pause = start[second] - last[first]
	printf "First delay: %.3fs, gap from fifth send to next exchange: %.3fs\n",
	    first_delay, pause
	printf "First exchange: xid=%s sends=%d refused Advertises=%d\n",
	    first, sends[first], rejections[first]
	printf "Second exchange: xid=%s sends=%d; successful PD Renew/Reply=%d\n",
	    second, sends[second], renewed
	exit (bad || !initial || !refused || !renewed || exchanges != 2 ||
	    first_delay < 7.9 || first_delay > 12 || pause < 7.9 ||
	    sends[first] != 5 || rejections[first] != 5 || sends[second] < 1)
}
