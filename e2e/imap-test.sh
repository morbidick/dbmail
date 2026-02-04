#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

HOST="${IMAP_HOST:-127.0.0.1}"
PLAIN_PORT="${IMAP_PORT:-1143}"
TLS_PORT="${IMAPS_PORT:-1993}"
IMAP_USER="${IMAP_USER:-test}"
IMAP_PASS="${IMAP_PASS:-changeme123}"
MAILBOX="${IMAP_MAILBOX:-INBOX}"

find_uid_from_search() {
	local search_payload="$1"
	local uid_line
	local uid

	uid_line="$(printf '%s\n' "$search_payload" | grep -E '\* SEARCH' | tail -n1 || true)"
	uid="$(printf '%s\n' "$uid_line" | grep -Eo '[0-9]+' | tail -n1 || true)"

	if [ -z "$uid" ]; then
		echo "could not resolve UID from IMAP search response"
	fi

	echo "$uid"
}

if ! command -v curl >/dev/null 2>&1; then
	echo "curl is required but was not found in PATH" >&2
	exit 1
fi

MESSAGE_FILE="$(mktemp)"
trap 'rm -f "$MESSAGE_FILE"' EXIT

MESSAGE_ID="<e2e-$RANDOM-$(date +%s)@dbmail.local>"
cat > "$MESSAGE_FILE" <<EOF
From: test@example.com
To: test@example.com
Subject: IMAP E2E test message
Message-ID: $MESSAGE_ID
Date: $(LC_ALL=C date -R)

Hello from IMAP E2E roundtrip.
EOF

echo "1/5 append message via IMAP STARTTLS on ${HOST}:${PLAIN_PORT}"
curl --silent --show-error --fail \
	--ssl-reqd --insecure \
	--user "${IMAP_USER}:${IMAP_PASS}" \
	--url "imap://${HOST}:${PLAIN_PORT}/${MAILBOX}" \
	--upload-file "$MESSAGE_FILE" \
	>/dev/null

echo "2/5 list all mail UIDs via IMAP STARTTLS on ${HOST}:${PLAIN_PORT}"
SEARCH_RESULT="$(curl --silent --show-error --fail \
	--ssl-reqd --insecure \
	--user "${IMAP_USER}:${IMAP_PASS}" \
	--url "imap://${HOST}:${PLAIN_PORT}/${MAILBOX}" \
	--request "UID SEARCH ALL"
)"
ALL_UIDS="$(printf '%s\n' "$SEARCH_RESULT" | grep -E '\* SEARCH' | tail -n1 | sed -E 's/^\* SEARCH[[:space:]]*//' || true)"
if [ -n "$ALL_UIDS" ]; then
	echo "all mail UIDs: $ALL_UIDS"
fi
MESSAGE_UID="$(find_uid_from_search "$SEARCH_RESULT")"

echo "3/5 fetch message via IMAP STARTTLS on ${HOST}:${PLAIN_PORT} (UID ${MESSAGE_UID})"
STARTTLS_FETCH="$(curl --silent --show-error --fail \
	--ssl-reqd --insecure \
	--user "${IMAP_USER}:${IMAP_PASS}" \
	--url "imap://${HOST}:${PLAIN_PORT}/${MAILBOX};UID=${MESSAGE_UID}"
)"
if ! grep -Fq "$MESSAGE_ID" <<< "$STARTTLS_FETCH"; then
	echo "could not find appended message in STARTTLS IMAP fetch"
fi

echo "4/5 fetch message via plain IMAP on ${HOST}:${PLAIN_PORT} (UID ${MESSAGE_UID})"
PLAIN_FETCH="$(curl --silent --show-error --fail \
	--user "${IMAP_USER}:${IMAP_PASS}" \
	--url "imap://${HOST}:${PLAIN_PORT}/${MAILBOX};UID=${MESSAGE_UID}"
)"

if ! grep -Fq "$MESSAGE_ID" <<< "$PLAIN_FETCH"; then
	echo "could not find appended message in plain IMAP fetch"
fi

echo "5/5 fetch message via TLS IMAP on ${HOST}:${TLS_PORT} (UID ${MESSAGE_UID})"
TLS_FETCH="$(curl --silent --show-error --fail --insecure \
	--user "${IMAP_USER}:${IMAP_PASS}" \
	--url "imaps://${HOST}:${TLS_PORT}/${MAILBOX};UID=${MESSAGE_UID}"
)"

if ! grep -Fq "$MESSAGE_ID" <<< "$TLS_FETCH"; then
	echo "could not find appended message in TLS IMAP fetch"
fi

echo "IMAP roundtrip succeeded (STARTTLS append/read + plain read + TLS read)."
