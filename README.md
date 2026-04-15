# zenoh-wireshark

A Wireshark Lua dissector for the [Zenoh](https://zenoh.io) protocol.

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
zenoh_lua
```

You should see Zenoh messages decoded in the packet detail pane.

To verify from the command line:

```sh
tshark -r <capture.pcapng> -X lua_script:zenoh.lua -Y zenoh_lua -V
```

## Coexistence with the native Zenoh dissector

The plugin registers itself under the protocol abbreviation `zenoh_lua` and
the display name **Zenoh Protocol (Lua)**, so it coexists safely with the
[zenoh-dissector](https://github.com/ZettaScaleLabs/zenoh-dissector) Rust
plugin without conflicts. Both can be loaded at the same time.

## Ports

| Port | Transport | Usage                         |
|------|-----------|-------------------------------|
| 7446 | UDP       | Scouting (SCOUT / HELLO)      |
| 7447 | TCP / UDP | Session transport             |
| 7448 | UDP       | Multicast transport           |

## Message types decoded

**Transport layer**: INIT (Syn/Ack), OPEN (Syn/Ack), CLOSE, KEEP_ALIVE,
FRAME, FRAGMENT, JOIN

**Network layer** (inside FRAME): PUSH, DECLARE, REQUEST, RESPONSE,
RESPONSE_FINAL, INTEREST

**Data sub-messages**: PUT, DEL, QUERY, REPLY, ERR

**Declarations**: D_KEYEXPR, U_KEYEXPR, D_SUBSCRIBER, U_SUBSCRIBER,
D_QUERYABLE, U_QUERYABLE, D_TOKEN, U_TOKEN, D_FINAL

**Scouting**: SCOUT, HELLO
