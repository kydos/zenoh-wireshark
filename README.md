# zenoh-wireshark

A Wireshark Lua dissector for the [Zenoh](https://zenoh.io) protocol whose draft 
specification is available [here](https://spec.zenoh.io).

Supports TCP and UDP transport on the standard Zenoh ports (7447, 7448) and
UDP scouting on port 7446. Highlights all protocol boundaries — transport
messages, network messages, declarations, key expressions, extensions, and
more — while omitting user payload content.

## Installation

### macOS

Copy `zenoh.lua` to your personal Lua plugins directory:

```sh
mkdir -p ~/.local/lib/wireshark/plugins
cp zenoh.lua ~/.local/lib/wireshark/plugins/
```

### Linux

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

---

After copying the file, **restart Wireshark** (or reload Lua plugins via
**Analyze → Reload Lua Plugins**, shortcut `Ctrl+Shift+L`).

### Finding the right directory

If you are unsure of the correct path on your system, open Wireshark and go to
**Help → About Wireshark → Folders**. Look for the row labelled
**Personal Lua Plugins** and place `zenoh.lua` in that directory.

Alternatively, run:

```sh
tshark -G folders | grep "Lua Plugins"
```

## Verifying the installation

Open Wireshark and capture (or open a saved `.pcap`/`.pcapng` file) on port
7447. Apply the display filter:

```
zenoh
```

You should see Zenoh messages decoded in the packet detail pane.

To verify from the command line (after installation):

```sh
tshark -r <capture.pcapng> -Y zenoh -V
```

## Coexistence with the native Zenoh dissector

The plugin uses the display name **Zenoh Protocol (Lua)**, so it coexists
safely with the
[zenoh-dissector](https://github.com/ZettaScaleLabs/zenoh-dissector) Rust
plugin. Both can be loaded at the same time.

## Ports

| Port | Transport | Usage                         |
|------|-----------|-------------------------------|
| 7446 | UDP       | Scouting (SCOUT / HELLO)      |
| 7447 | TCP / UDP | Session transport             |
| 7448 | UDP       | Multicast transport           |

## Heuristic dissection

The dissector registers TCP and UDP heuristics, so it automatically recognises
Zenoh traffic on **non-standard ports** without any manual "Decode As" step.
The heuristic validates the 2-byte little-endian frame-length prefix (TCP) and
checks that the first message byte carries a valid transport message ID.  Once
a session is recognised the dissector is locked to that TCP connection or UDP
4-tuple for all subsequent packets.

## Display filters

All fields below can be used in the Wireshark display filter bar or with
`tshark -Y`.

### Filter by peer identity

The session ZID (Zenoh ID) is captured from INIT, JOIN, and HELLO messages and
propagated to every packet on the same TCP stream or UDP 4-tuple.

```
zenoh.session.src_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
zenoh.session.dst_zid == 08:18:09:7e:d4:0c:0a:17:11:8b:9f:56:28:a6:42:f5
```

Show all traffic involving a specific peer (either as initiator or responder):

```
zenoh.session.src_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
  or
zenoh.session.dst_zid == f7:90:74:83:17:da:39:82:b8:93:24:19:27:0f:11:82
```

### Filter by network message type

`zenoh.net.msg_id` matches only **network-layer** message IDs (those carried
inside a FRAME), keeping it distinct from `zenoh.msg_id` which also matches
transport-layer messages.

```
zenoh.net.msg_id == 0x1d   # PUSH
zenoh.net.msg_id == 0x1c   # REQUEST
zenoh.net.msg_id == 0x1b   # RESPONSE
zenoh.net.msg_id == 0x1e   # DECLARE
zenoh.net.msg_id == 0x19   # INTEREST
```

### Filter by key expression

`zenoh.key_suffix` matches the raw suffix string on the wire:

```
zenoh.key_suffix contains "zenoh-rs-pub"
zenoh.key_suffix == "/zenoh-rs-pub"
```

`zenoh.keyexpr` holds the **fully resolved** key expression reconstructed from
`D_KEYEXPR` declarations seen earlier in the session.  This makes it possible
to filter on the complete key even when packets carry only a numeric scope ID:

```
zenoh.keyexpr == "demo/example/zenoh-rs-pub"
zenoh.keyexpr contains "demo/example"
```

Combine filters to narrow down traffic of interest:

```
zenoh.net.msg_id == 0x1d and zenoh.keyexpr contains "demo"
```

## Message types decoded

**Transport layer**: INIT (Syn/Ack), OPEN (Syn/Ack), CLOSE, KEEP_ALIVE,
FRAME, FRAGMENT, JOIN

**Network layer** (inside FRAME): PUSH, DECLARE, REQUEST, RESPONSE,
RESPONSE_FINAL, INTEREST

**Data sub-messages**: PUT, DEL, QUERY, REPLY, ERR

**Declarations**: D_KEYEXPR, U_KEYEXPR, D_SUBSCRIBER, U_SUBSCRIBER,
D_QUERYABLE, U_QUERYABLE, D_TOKEN, U_TOKEN, D_FINAL

**Scouting**: SCOUT, HELLO
