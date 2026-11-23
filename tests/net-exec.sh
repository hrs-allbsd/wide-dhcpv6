#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2026 Hiroki Sato <hrs@FreeBSD.org>

set -eu

context=$1
root=$2
shift 2
case "$(uname -s)" in
FreeBSD) exec jexec "$context" "$@" ;;
Linux) exec ip netns exec "$context" chroot "$root" "$@" ;;
esac
exit 1
