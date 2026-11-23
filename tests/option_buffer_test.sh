# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

atf_test_case exact_fit
exact_fit_head()
{
	atf_set "descr" "Encode the last option when the buffer fits exactly"
}
exact_fit_body()
{
	local check

	check=$(encoder_check) || atf_skip "Build option-buffer-check in DHCP6_TEST_BINDIR"
	atf_check -s exit:0 -o 'inline:Exact fit: 20 bytes written, guard bytes unchanged\n' \
	    "$check" exact
}

atf_test_case one_byte_short
one_byte_short_head()
{
	atf_set "descr" "Reject an option when the buffer is one byte short"
}
one_byte_short_body()
{
	local check

	check=$(encoder_check) || atf_skip "Build option-buffer-check in DHCP6_TEST_BINDIR"
	atf_check -s exit:0 -o 'inline:One byte short: capacity 19, second option untouched\n' \
	    "$check" short
}

encoder_check()
{
	local bindir

	bindir=$(atf_config_get dhcp6_bindir "")
	[ -n "$bindir" ] || return 1
	[ -x "$bindir/option-buffer-check" ] || return 1
	printf '%s\n' "$bindir/option-buffer-check"
}

atf_init_test_cases()
{
	atf_add_test_case exact_fit
	atf_add_test_case one_byte_short
}
