# Zenoh Wireshark Dissector — User Guide

A Wireshark Lua dissector for the [Zenoh protocol](https://zenoh.io).  
Spec: [spec.zenoh.io](https://spec.zenoh.io).

---

## Table of contents

1. [Installation](#1-installation)
2. [Quick start](#2-quick-start)
3. [Ports and transports](#3-ports-and-transports)
4. [Message types decoded](#4-message-types-decoded)
5. [Display filters](#5-display-filters)
6. [Preferences](#6-preferences)
7. [Request-response correlation](#7-request-response-correlation)
8. [Sequence-number gap detection](#8-sequence-number-gap-detection)
9. [Declaration lifecycle tracking](#9-declaration-lifecycle-tracking)
10. [Session summary](#10-session-summary)
11. [Statistics tap](#11-statistics-tap)
12. [Payload display](#12-payload-display)
13. [Heuristic dissection](#13-heuristic-dissection)
14. [Sample captures](#14-sample-captures)

---

## 1. Installation

### macOS / Linux

```sh
mkdir -p ~/.local/lib/wireshark/plugins
cp zenoh.lua ~/.local/lib/wireshark/plugins/
```

### Windows

Copy `zenoh.lua` to:

```
%APPDATA%\Wireshark\plugins\
```

For example: `C:\Users\<you>\AppData\Roaming\Wireshark\plugins\zenoh.lua`

### Finding the plugins directory

Open Wireshark and go to **Help → About Wireshark → Folders**.  
Look for the **Personal Lua Plugins** row, or run:

```sh
tshark -G folders | grep "Lua Plugins"
```

### Activating

After copying the file either **restart Wireshark** or reload all Lua
plugins without restarting:

- **Wireshark**: Analyze → Reload Lua Plugins (`Ctrl+Shift+L`)
- **tshark**: not applicable; re-run the command

### Coexistence with the native plugin

The dissector registers under the abbreviation `zenoh` and the display
name **Zenoh Protocol (Lua)**.  It coexists safely with the
[zenoh-dissector](https://github.com/ZettaScaleLabs/zenoh-dissector) Rust
plugin — both can be loaded at the same time.

---

## 2. Quick start

Apply the display filter `zenoh` to see all decoded traffic:

```
zenoh
```

Or from the command line:

```sh
tshark -r <capture.pcapng> -X lua_script:zenoh.lua -Y zenoh -V
```

Run the bundled regression suite against the provided sample captures:

```sh
bash tests/regression.sh
```

---

## 3. Ports and transports

| Port | Transport | Usage                                        |
|------|-----------|----------------------------------------------|
| 7447 | TCP       | Session transport (2-byte LE batch-length prefix) |
| 7447 | UDP       | Session transport (datagram = one batch)     |
| 7446 | UDP       | Scouting (SCOUT / HELLO)                     |
| 7448 | UDP       | Multicast transport                          |

The dissector also registers TCP and UDP **heuristics** so it can decode
traffic on non-standard ports — see [Section 13](#13-heuristic-dissection).

---

## 4. Message types decoded

### Transport layer

| ID   | Name         | Notes                            |
|------|--------------|----------------------------------|
| 0x01 | INIT         | Syn / Ack variants               |
| 0x02 | OPEN         | Syn / Ack variants               |
| 0x03 | CLOSE        | Reason code decoded              |
| 0x04 | KEEP_ALIVE   |                                  |
| 0x05 | FRAME        | Carries network messages inside  |
| 0x06 | FRAGMENT     | Reassembly chain cross-referenced|
| 0x07 | JOIN         | Multicast session establishment  |
| 0x00 | OAM          | LinkState body decoded           |

### Network layer (inside FRAME)

| ID   | Name           | Notes                                        |
|------|----------------|----------------------------------------------|
| 0x1D | PUSH           | Carries PUT or DEL                           |
| 0x1E | DECLARE        | All D_* / U_* variants                       |
| 0x1C | REQUEST        | Carries QUERY; correlated with RESPONSE      |
| 0x1B | RESPONSE       | Carries REPLY or ERR; correlated with REQUEST|
| 0x1A | RESPONSE_FINAL | End-of-query marker                          |
| 0x19 | INTEREST       | Interest declaration                         |
| 0x1F | OAM            |                                              |

### Data sub-messages

| ID   | Name  | Carried by         |
|------|-------|--------------------|
| 0x01 | PUT   | PUSH               |
| 0x02 | DEL   | PUSH               |
| 0x03 | QUERY | REQUEST            |
| 0x04 | REPLY | RESPONSE           |
| 0x05 | ERR   | RESPONSE           |

### Declarations (inside DECLARE)

| ID   | Name          |
|------|---------------|
| 0x00 | D_KEYEXPR     |
| 0x01 | U_KEYEXPR     |
| 0x02 | D_SUBSCRIBER  |
| 0x03 | U_SUBSCRIBER  |
| 0x04 | D_QUERYABLE   |
| 0x05 | U_QUERYABLE   |
| 0x06 | D_TOKEN       |
| 0x07 | U_TOKEN       |
| 0x1A | D_FINAL       |

### Scouting

| ID   | Name  |
|------|-------|
| 0x01 | SCOUT |
| 0x02 | HELLO |

---

## 5. Display filters

All fields below can be used in the Wireshark filter bar or with
`tshark -Y`.

### Basic protocol filter

```
zenoh
```

### Message type

```
zenoh.msg_id == 0x05              # FRAME (transport layer)
zenoh.net.msg_id == 0x1d          # PUSH
zenoh.net.msg_id == 0x1c          # REQUEST
zenoh.net.msg_id == 0x1b          # RESPONSE
zenoh.net.msg_id == 0x1e          # DECLARE
zenoh.net.msg_id == 0x19          # INTEREST
```

`zenoh.msg_id` matches any Zenoh message (transport **or** network layer).
`zenoh.net.msg_id` matches only network-layer messages carried inside
FRAME batches.

### Key expression

`zenoh.key_suffix` — raw suffix string from the wire:

```
zenoh.key_suffix contains "zenoh-rs-pub"
zenoh.key_suffix == "/zenoh-rs-pub"
```

`zenoh.keyexpr` — **fully resolved** key expression built by replaying
`D_KEYEXPR` declarations seen earlier in the session.  Useful when packets
carry only a numeric scope ID instead of the full path:

```
zenoh.keyexpr == "demo/example/zenoh-rs-pub"
zenoh.keyexpr contains "demo/example"
```

Combine to narrow down traffic:

```
zenoh.net.msg_id == 0x1d and zenoh.keyexpr contains "demo"
```

### Peer identity (ZID)

The session ZID is extracted from INIT / JOIN / HELLO messages and
propagated as a virtual field to **every packet** on the same TCP stream
or UDP 4-tuple.

```
zenoh.session.src_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
zenoh.session.dst_zid == 08:18:09:7e:d4:0c:0a:17:11:8b:9f:56:28:a6:42:f5
```

Show all traffic involving a specific peer (either direction):

```
zenoh.session.src_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
  or
zenoh.session.dst_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
```

### Request-response correlation

```
zenoh.req.response_frame          # exists on REQUEST packets that received a response
zenoh.resp.request_frame          # exists on RESPONSE/RESPONSE_FINAL packets
zenoh.req.response_time_ms > 10   # requests whose response took more than 10 ms
```

### Sequence-number gaps

```
zenoh.sn.gap == true              # packets where a gap was detected
zenoh.sn.gap_size > 0             # packets with at least one missing frame
```

### Declaration lifecycle

```
zenoh.decl.undeclared_frame       # D_* packets that later had a matching U_* 
zenoh.decl.declared_frame         # U_* packets — links back to the D_* packet
zenoh.decl.active_ms > 5000       # subscriptions active for more than 5 seconds
```

### Quick-reference table

| Field                       | Type      | Description                              |
|-----------------------------|-----------|------------------------------------------|
| `zenoh`                     | protocol  | Any Zenoh packet                         |
| `zenoh.msg_id`              | uint8     | Transport or network message ID          |
| `zenoh.net.msg_id`          | uint8     | Network-layer message ID (inside FRAME)  |
| `zenoh.key_suffix`          | string    | Raw wire suffix of a key expression      |
| `zenoh.keyexpr`             | string    | Fully resolved key expression            |
| `zenoh.session.src_zid`     | bytes     | Session initiator ZID                    |
| `zenoh.session.dst_zid`     | bytes     | Session responder ZID                    |
| `zenoh.request_id`          | uint32    | Request correlation ID                   |
| `zenoh.req.response_frame`  | framenum  | Frame number of the response             |
| `zenoh.req.response_time_ms`| float     | Round-trip time in ms (on both sides)    |
| `zenoh.resp.request_frame`  | framenum  | Frame number of the original request     |
| `zenoh.sn.gap`              | bool      | Sequence-number gap detected             |
| `zenoh.sn.gap_size`         | uint32    | Number of missing frames                 |
| `zenoh.decl.declared_frame` | framenum  | D_* packet for this U_* packet           |
| `zenoh.decl.undeclared_frame`| framenum | U_* packet for this D_* packet           |
| `zenoh.decl.active_ms`      | float     | Time the declaration was active (ms)     |
| `zenoh.session.version`     | uint8     | Zenoh protocol version byte              |
| `zenoh.session.ke_count`    | uint32    | Declared key expressions in session      |
| `zenoh.session.sub_count`   | uint32    | Active subscribers in session            |
| `zenoh.session.qbl_count`   | uint32    | Active queryables in session             |
| `zenoh.session.tok_count`   | uint32    | Active tokens in session                 |

---

## 6. Preferences

Open **Edit → Preferences → Protocols → zenoh (Lua)**.

| Setting | Default | Description |
|---------|---------|-------------|
| **Show payload bytes** | off | When on, payload content is decoded and annotated as JSON, text, or binary instead of showing just the byte count. |
| **Warn on unknown message IDs** | on | Emit an expert-info warning when an unrecognised transport or network message ID is encountered. |

---

## 7. Request-response correlation

The dissector automatically correlates `REQUEST` messages with their
`RESPONSE` and `RESPONSE_FINAL` replies using the `rid` (request ID) field
shared by both sides.

When a matching pair is found, two **generated fields** are added to the
packet tree (shown in italics in Wireshark):

On the **REQUEST** packet:

- **Response In** (`zenoh.req.response_frame`) — frame number of the first
  RESPONSE or RESPONSE_FINAL that carries the same `rid`.
- **Response Time (ms)** (`zenoh.req.response_time_ms`) — elapsed time
  from the REQUEST to that RESPONSE, in milliseconds.

On the **RESPONSE** / **RESPONSE_FINAL** packet:

- **Request In** (`zenoh.resp.request_frame`) — frame number of the
  original REQUEST.
- **Response Time (ms)** (`zenoh.req.response_time_ms`) — same delta,
  shown on both ends for easy reference.

Clicking a `Response In` or `Request In` field in the detail pane jumps
directly to the linked frame.

**Example workflow:**

1. Open a capture containing a `z_get` / `z_queryable` exchange.
2. Apply filter `zenoh.net.msg_id == 0x1c` to isolate REQUEST packets.
3. Expand the network message subtree — `Response In` points to the reply.
4. Apply filter `zenoh.req.response_time_ms > 5` to find slow queries.

---

## 8. Sequence-number gap detection

Each Zenoh FRAME carries a sequence number (`sn`) on a per-channel
(`R` = reliable, `B` = best-effort) per-stream basis.  The dissector
tracks the last-seen SN for each channel and raises an expert-info notice
when the next frame's SN is not the expected increment.

When a gap is detected the FRAME tree shows:

- **Sequence Number Gap** (`zenoh.sn.gap`) — boolean field set to `true`.
- **Missing Frames Count** (`zenoh.sn.gap_size`) — number of frames absent
  between the previous SN and the current one.
- An **expert info** notice at the `PI_SEQUENCE` / `PI_NOTE` level is
  highlighted in the expert-info column.

Filter for all packets with gaps:

```
zenoh.sn.gap == true
```

---

## 9. Declaration lifecycle tracking

The dissector cross-references matching `D_*` (declare) and `U_*`
(undeclare) pairs for the following entity types:

| D_ message      | U_ message      | Tracked as |
|-----------------|-----------------|------------|
| D_KEYEXPR       | U_KEYEXPR       | `ke`       |
| D_SUBSCRIBER    | U_SUBSCRIBER    | `sub`      |
| D_QUERYABLE     | U_QUERYABLE     | `qbl`      |
| D_TOKEN         | U_TOKEN         | `tok`      |

When both ends of a declaration pair are visible in the capture, each
packet gets two generated fields:

On the **D_*** packet (the declaration):

- **Undeclared In** (`zenoh.decl.undeclared_frame`) — frame number of the
  corresponding `U_*` packet.
- **Active Duration (ms)** (`zenoh.decl.active_ms`) — how long the entity
  was declared before being removed.

On the **U_*** packet (the undeclaration):

- **Declared In** (`zenoh.decl.declared_frame`) — frame number of the
  original `D_*` packet.
- **Active Duration (ms)** (`zenoh.decl.active_ms`) — same delta.

**Example use cases:**

- Find short-lived subscriptions (possible connection churn):
  ```
  zenoh.decl.active_ms < 1000
  ```
- Find D_KEYEXPR packets that were never undeclared (no `Undeclared In`
  field — apply filter then look for packets with no generated field).

---

## 10. Session summary

A **Session State** subtree is added to the root Zenoh node of every
packet once the dissector has enough information about the session.  All
fields are **generated** (shown in italics) and reflect cumulative state
seen up to the current packet:

| Field                       | Description                                      |
|-----------------------------|--------------------------------------------------|
| Protocol Version            | Version byte from the first INIT or JOIN message |
| Declared Key Expressions    | Total `D_KEYEXPR` declarations seen              |
| Active Subscribers          | Total `D_SUBSCRIBER` declarations seen           |
| Active Queryables           | Total `D_QUERYABLE` declarations seen            |
| Active Tokens               | Total `D_TOKEN` declarations seen                |

The counts include all declarations seen in both directions on the same
TCP stream or UDP 4-tuple.  They do **not** subtract undeclarations — they
represent the peak number of entities that were ever declared.

---

## 11. Statistics tap

The dissector registers a Wireshark statistics tap named `zenoh`.

### tshark

```sh
tshark -r <capture.pcapng> -X lua_script:zenoh.lua -z zenoh,stat -q
```

The `-q` flag suppresses the per-packet output so only the statistics
table is printed. Example output:

```
============================================================
Zenoh Protocol Statistics
============================================================
  Total bytes decoded : 12453

  Transport messages:
    CLOSE                : 2
    FRAME                : 84
    INIT                 : 4
    KEEP_ALIVE           : 6
    OPEN                 : 4

  Network messages:
    DECLARE              : 8
    PUSH                 : 40
    REQUEST              : 6
    RESPONSE             : 6
    RESPONSE_FINAL       : 6

  Query response times:
    Samples : 6
    Min     : 0.241 ms
    Avg     : 0.618 ms
    Max     : 1.432 ms
============================================================
```

### Wireshark GUI

The tap is available under **Statistics** when Wireshark supports Lua
taps for the loaded protocol.  Results are refreshed each time
**Statistics → Refresh** is triggered or a capture is re-analysed.

The response-time section appears only when the capture contains at least
one resolved REQUEST↔RESPONSE pair.  The scouting section appears only
when SCOUT or HELLO messages are present.

---

## 12. Payload display

By default the dissector records the payload length but does not show the
actual bytes — the packet tree shows `Payload (omitted): N byte(s) not shown`.

When the **Show payload bytes** preference is enabled
(Edit → Preferences → Protocols → zenoh (Lua) → Show payload bytes), the
dissector attempts to decode the raw bytes and annotates the payload field:

| Detection        | Trigger                             | Annotation            |
|------------------|-------------------------------------|-----------------------|
| JSON             | First byte is `{` (0x7B) or `[` (0x5B) | `[JSON: …]`        |
| Printable text   | All bytes in printable ASCII range  | `[Text: …]`           |
| Binary           | Otherwise                           | `[Binary: N bytes]`   |

The annotation is appended to the `Payload Data` field label in the detail
tree.  The raw bytes are still visible by expanding the field.

---

## 13. Heuristic dissection

The dissector registers TCP and UDP heuristics so it can decode Zenoh
traffic on non-standard ports.

**TCP heuristic** checks:

1. Minimum 3 bytes available.
2. The 2-byte little-endian frame-length prefix is non-zero and ≤ 65535.
3. Bits 4:0 of the header byte are a valid transport message ID (0x01–0x07).
4. For INIT (0x01) and JOIN (0x07), the version byte is non-zero.

**UDP heuristic** checks:

1. Minimum 1 byte available.
2. Bits 4:0 of the first byte are a valid transport message ID (0x01–0x07).
3. For INIT / JOIN, the version byte is non-zero.

Once a session is recognised the dissector is locked to that TCP
connection or UDP 4-tuple for all subsequent packets (`pinfo.conversation`
is set), so the heuristic fires only once per session.

UDP scouting traffic (SCOUT / HELLO) is identified by its registered
port (7446) rather than the UDP heuristic.

---

## 14. Sample captures

The `assets/` directory contains captures for both manual inspection and
the regression suite.

| File | Contents |
|------|----------|
| `pubsub.pcapng` | Single publisher–subscriber session |
| `pubsub-couple.pcapng` | Two-node pub–sub with multi-session ZID injection |
| `sample-data.pcap` | PUT traffic with resolved key expressions |
| `query-reply.pcapng` | `z_queryable` + `z_get` — exercises REQUEST / RESPONSE / RESPONSE_FINAL / CLOSE |
| `scout.pcapng` | `z_scout` — exercises SCOUT messages on UDP multicast |

### Working with the sample captures

```sh
# Inspect all fields verbosely
tshark -r assets/pubsub.pcapng -X lua_script:zenoh.lua -Y zenoh -V

# Show only REQUEST and RESPONSE packets
tshark -r assets/query-reply.pcapng -X lua_script:zenoh.lua \
    -Y "zenoh.net.msg_id == 0x1c or zenoh.net.msg_id == 0x1b" -V

# Print statistics
tshark -r assets/query-reply.pcapng -X lua_script:zenoh.lua \
    -z zenoh,stat -q

# Filter by resolved key expression
tshark -r assets/pubsub.pcapng -X lua_script:zenoh.lua \
    -Y 'zenoh.keyexpr contains "demo"' -V

# Find sequence-number gaps
tshark -r assets/pubsub.pcapng -X lua_script:zenoh.lua \
    -Y "zenoh.sn.gap == true" -V
```
