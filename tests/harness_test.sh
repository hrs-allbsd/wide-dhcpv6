# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

atf_test_case atf_check_runs
atf_check_runs_head()
{
	atf_set "descr" "Verify that the ATF shell test driver can run atf-check"
}
atf_check_runs_body()
{
	atf_check -s exit:0 -o 'inline:wide-dhcpv6\n' -e empty \
	    printf '%s\n' wide-dhcpv6
}

atf_init_test_cases()
{
	atf_add_test_case atf_check_runs
}
