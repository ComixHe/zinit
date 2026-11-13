#!/usr/bin/env sh

# SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
#
# SPDX-License-Identifier: MIT

# Run zinit as PID 1 in a PID namespace.
#
# Usage: tools/pid1.sh <path-to-zinit>
#

set -eu

bounded=0
if [ "${1:-}" = --bounded ]; then
    bounded=1
    shift
fi

probe_unshare() {
    if unshare --pid --fork --mount-proc --kill-child=KILL /bin/true >/dev/null 2>&1; then
        echo direct
        return 0
    fi

    if unshare --user --map-root-user --pid --fork --mount-proc --kill-child=KILL /bin/true >/dev/null 2>&1; then
        echo user
        return 0
    fi

    return 1
}

if [ "${bounded}" -eq 0 ]; then
    if mode=$(probe_unshare); then
        exec timeout --signal=KILL 30s /bin/sh "$0" --bounded "$@"
    fi

    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -- timeout --signal=KILL 30s /bin/sh "$0" --bounded "$@"
    fi

    echo "cannot create a PID namespace directly or through sudo" >&2
    echo "need CAP_SYS_ADMIN, unprivileged user namespaces, or passwordless sudo" >&2
    exit 2
fi

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-zinit>" >&2
    exit 2
fi

zinit=$1
[ -x "${zinit}" ] || {
    echo "not executable: ${zinit}" >&2
    exit 2
}

command -v unshare >/dev/null 2>&1 || {
    echo "unshare is required" >&2
    exit 2
}

mode=$(probe_unshare) || {
    echo "cannot create a PID namespace" >&2
    exit 2
}

case "${mode}" in
    direct)
        run_pid1() {
            unshare --pid --fork --mount-proc --kill-child=KILL "${zinit}" "$@"
        }
        ;;
    user)
        run_pid1() {
            unshare --user --map-root-user --pid --fork --mount-proc --kill-child=KILL "${zinit}" "$@"
        }
        ;;
    *)
        echo "unknown namespace mode: ${mode}" >&2
        exit 2
        ;;
esac

run_pid1 -s -- /bin/sh -c '[ "$$" -eq 2 ]'

set +e
run_pid1 -- /bin/sh -c 'exit 7'
code=$?
set -e
[ "${code}" -eq 7 ] || {
    echo "exit code: expected 7, got ${code}" >&2
    exit 1
}

set +e
# shellcheck disable=SC2016 # $PPID is expanded by the workload shell, not this script.
run_pid1 -- /bin/sh -c 'kill -TERM $PPID; exec sleep 30'
code=$?
set -e
[ "${code}" -eq 143 ] || {
    echo "signal forwarding: expected 143, got $code" >&2
    exit 1
}

run_pid1 -s -t 1 -- /bin/sh -c '/bin/sh -c "sleep 30" & exit 0'

adopt_dir=$(mktemp -d)
trap 'rm -rf "$adopt_dir"' EXIT
# shellcheck disable=SC2016 # expanded by the workload shell, not this script.
run_pid1 -- /bin/sh -c '
    ( /bin/sh -c "sleep 0.2" & printf "%d" $! > "$1/orphan.tmp"; mv "$1/orphan.tmp" "$1/orphan" ) &
    i=0
    while [ ! -e "$1/orphan" ] && [ "$i" -lt 500 ]; do i=$((i+1)); sleep 0.01; done
    orphan=$(cat "$1/orphan" 2>/dev/null) || exit 8
    i=0
    while [ -e "/proc/$orphan" ] && [ "$i" -lt 500 ]; do i=$((i+1)); sleep 0.01; done
    [ ! -e "/proc/$orphan" ] || exit 9
    echo "natural adoption without -s: reaped while PID 1 stayed alive"
' sh "${adopt_dir}"

set +e
# shellcheck disable=SC2016 # expanded by the workload shell, not this script.
run_pid1 -- /bin/sh -c '(sleep 0.3; [ "$(awk "{print \$3}" /proc/1/stat)" != T ] || exit 9; kill -CONT $$) & kill -STOP $$; exit 3'
code=$?
set -e
[ "${code}" -eq 3 ] || {
    echo "PID 1 job control: expected 3, got ${code}" >&2
    exit 1
}
