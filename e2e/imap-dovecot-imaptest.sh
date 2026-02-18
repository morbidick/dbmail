#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

PLAIN_PORT="${IMAPTEST_PLAIN_PORT:-1143}"
TLS_PORT="${IMAPTEST_TLS_PORT:-1993}"
USER_NAME="${IMAPTEST_USER:-test}"
USER_PASS="${IMAPTEST_PASS:-changeme123}"
MBOX_FILE="${IMAPTEST_MBOX_FILE:-$SCRIPT_DIR/imaptest-message.mbox}"

if [ ! -f "$MBOX_FILE" ]; then
	echo "missing mbox file: $MBOX_FILE" >&2
	exit 1
fi

MBOX_REALPATH="$(realpath "$MBOX_FILE")"

run_imaptest() {
	local mode="$1"
	shift
	echo "=== $mode ==="
	podman run --rm \
		--network host \
		-v "$MBOX_REALPATH":/data/imaptest-message.mbox:ro,Z \
		docker.io/dovecot/imaptest \
		host=localhost \
		user="$USER_NAME" \
		pass="$USER_PASS" \
		clients=5 \
		secs=5 \
		mbox=/data/imaptest-message.mbox \
		"$@"
}

run_imaptest "plain imap" port="$PLAIN_PORT" login logout
run_imaptest "imaps" port="$TLS_PORT" ssl=any-cert login logout