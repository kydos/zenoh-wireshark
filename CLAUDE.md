# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A Wireshark Lua dissector for the [Zenoh protocol](https://spec.zenoh.io). The entire implementation lives in a single file: `zenoh.lua`. There is no build system — the file is installed by copying it to the platform-specific Wireshark Lua plugins directory.

The dissector registers under the abbreviation `zenoh_lua` (display name **Zenoh Protocol (Lua)**) to coexist safely with the native Rust-based [zenoh-dissector](https://github.com/ZettaScaleLabs/zenoh-dissector).

## Testing the dissector

Run against a sample capture without installing:

```sh
tshark -r assets/pubsub.pcapng -X lua_script:zenoh.lua -Y zenoh_lua -V
```

Reload in a running Wireshark instance (no restart needed):

```
Analyze → Reload Lua Plugins  (Ctrl+Shift+L)
```

## Architecture of `zenoh.lua`

The file is organized into 12 sequential sections that must remain in order (Lua requires definitions before use):

1. **Protocol object** — `zenoh_proto` with the `zenoh_lua` abbreviation.
2. **Value-string tables** — lookup tables mapping numeric IDs to names for message types, flags, and extensions at each protocol layer (transport, network, scouting).
3. **ProtoField definitions** — all `ProtoField` declarations registered with `zenoh_proto.fields`; adding a new field requires an entry here and a call to `subtree:add()` in the relevant parser.
4. **Helper functions** — `read_vle()` (LEB128 integer decoding), `read_string()`, `read_bytes()`, `parse_ext()` (recursive extension chain walker), `parse_timestamp()`.
5. **Data sub-message parsers** — `parse_put`, `parse_del`, `parse_query`, `parse_reply`, `parse_err`.
6. **Declaration parsers** — `parse_wire_expr` (key expression from headers), `parse_declaration` (dispatches all D_/U_ variants).
7. **Network message parsers** — `parse_push`, `parse_declare`, `parse_request`, `parse_response`, `parse_response_final`, `parse_interest`, `parse_oam_net`.
8. **Transport message parsers** — `parse_init`, `parse_open`, `parse_close`, `parse_keep_alive`, `parse_frame`, `parse_fragment`, `parse_join`, `parse_oam`.
9. **Transport-layer batch dissector** — `dissect_batch()` loops over the message stream within one TCP segment or UDP datagram, dispatching by the message-ID byte.
10. **Scouting message parsers** — `parse_scout`, `parse_hello`.
11. **Main dissector entry points** — TCP dissector uses `DissectorTable` with a 2-byte little-endian length prefix for desegmentation; UDP dissector calls `dissect_batch()` directly (one datagram = one batch).
12. **Port registration** — TCP 7447; UDP 7446, 7447, 7448.

### Key encoding conventions

- **VLE (Variable-Length Encoding)**: LEB128 — the low 7 bits of each byte are data, bit 7 indicates "more bytes follow". Decoded by `read_vle()`.
- **z-int sizes**: `z8`, `z16`, `z32`, `z64` variants appear throughout header parsing.
- **TCP framing**: each batch is prefixed by a 2-byte little-endian length; `DissectorTable` handles stream reassembly.
- **Message header byte**: low 5 bits = message ID, bits 5–7 = flags (A/B/Z or similar per message type).
- **Extensions**: chained after the fixed header when the Z flag is set; each extension has an ID byte (low 6 bits = ID, bits 6–7 = encoding, bit 7 = "more extensions"). Parsed by `parse_ext()`.

### Protocol spec

The authoritative wire-format reference is the [Zenoh draft specification](https://spec.zenoh.io). Two local Rust implementations serve as the ground-truth reference when the spec is ambiguous:

- **zenoh-rust**: `/Users/kydos/yukido/labs/zenoh-rust/commons/zenoh-protocol` — the main Zenoh Rust codebase; codec logic lives here.
- **zenoh-nostd**: `/Users/kydos/yukido/labs/zenoh-nostd/crates/zenoh-proto` — a `no_std`-compatible protocol implementation; often the clearest source for wire-format details.

### Sample captures

`assets/` holds `.pcap`/`.pcapng` files used for manual verification. Prefer `pubsub.pcapng` for general testing and `pubsub-couple.pcapng` for multi-node scenarios.
