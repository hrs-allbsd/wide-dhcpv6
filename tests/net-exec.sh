#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

set -eu

context=$1
shift 2
case "$(uname -s)" in
FreeBSD) exec jexec "$context" "$@" ;;
esac
exit 1
