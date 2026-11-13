#!/usr/bin/env sh

# SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
#
# SPDX-License-Identifier: MIT

# Keep the test below a namespace init: running it as PID 1 changes signal rules.

set -eu
limit=$1
shift
# SC2016: the namespace's shell expands its own positional arguments.
# shellcheck disable=SC2016
exec timeout --signal=KILL "${limit}" \
    unshare --user --map-root-user --pid --fork --mount-proc --kill-child=KILL \
    /bin/sh -c '"$@"; result=$?; exit "$result"' test-init "$@"
