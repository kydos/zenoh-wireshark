#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin="$repo_root/zenoh.lua"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

assert_contains() {
    local file="$1"
    local pattern="$2"

    if ! grep -Fq "$pattern" "$file"; then
        echo "Expected to find pattern in $(basename "$file"): $pattern" >&2
        exit 1
    fi
}

run_capture() {
    local capture="$1"
    shift

    local out
    out="$(mktemp "$tmpdir/$(basename "$capture").XXXXXX")"

    HOME="$tmpdir/home" \
    XDG_CONFIG_HOME="$tmpdir/config" \
    tshark -r "$repo_root/$capture" -X "lua_script:$plugin" -Y zenoh -V >"$out"

    for pattern in "$@"; do
        assert_contains "$out" "$pattern"
    done

    echo "ok  $(basename "$capture")"
}

require_cmd luac
require_cmd tshark

luac -p "$plugin"
echo "ok  zenoh.lua syntax"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
mkdir -p "$tmpdir/home" "$tmpdir/config"

run_capture \
    "assets/pubsub.pcapng" \
    "Transport: INIT (InitSyn)" \
    "Patch Version: 1" \
    "Declaration: D_KEYEXPR" \
    "Declaration: D_SUBSCRIBER" \
    "Key Expression (resolved): demo/example/zenoh-rs-pub" \
    "Payload (omitted):"

run_capture \
    "assets/pubsub-couple.pcapng" \
    "Transport: INIT (InitSyn)" \
    "Session Source ZID:" \
    "Declaration: D_KEYEXPR" \
    "Declaration: D_SUBSCRIBER" \
    "Key Expression (resolved): demo/example/zenoh-rs-pub" \
    "Payload (omitted):"

run_capture \
    "assets/sample-data.pcap" \
    "Transport: INIT (InitSyn)" \
    "Session Source ZID:" \
    "Declaration: D_KEYEXPR" \
    "Declaration: D_SUBSCRIBER" \
    "Key Expression (resolved): demo/example/zenoh-rs-put" \
    "Payload (omitted):"

# REQUEST / RESPONSE / RESPONSE_FINAL flow (z_queryable + z_get)
run_capture \
    "assets/query-reply.pcapng" \
    "Transport: INIT (InitSyn)" \
    "Declaration: D_QUERYABLE" \
    "Network: REQUEST" \
    "Request Body: QUERY" \
    "Key Expression (resolved): demo/example/**" \
    "Network: RESPONSE" \
    "Response Body: REPLY" \
    "Key Expression (resolved): demo/example/zenoh-rs-queryable" \
    "Network: RESPONSE_FINAL" \
    "Transport: CLOSE"

# Scouting messages (SCOUT on UDP multicast)
run_capture \
    "assets/scout.pcapng" \
    "Scouting: SCOUT" \
    "WhatAmI Matcher: 0x03"

# LZ4 batch compression (INIT with compression extension, BatchHeader, decompressed frames)
run_capture \
    "assets/pub-sub-compression.pcapng" \
    "Transport: INIT (InitSyn)" \
    "ID=0x6 (Compression) Unit" \
    "Batch Header: 0x01" \
    "LZ4 Compressed: Yes" \
    "Zenoh Frame [436 bytes, decompressed from 299]" \
    "Batch Header: 0x00" \
    "LZ4 Compressed: No" \
    "Declaration: D_KEYEXPR" \
    "Key Expression (resolved): demo/example"

echo "All regression checks passed."
