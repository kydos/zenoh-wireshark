# Zenoh Display Filter Quick Reference

## Basic

| Filter | What it selects |
|--------|-----------------|
| `zenoh` | Any Zenoh packet |

## Message type

| Filter | What it selects |
|--------|-----------------|
| `zenoh.msg_id == 0x01` | INIT (transport) |
| `zenoh.msg_id == 0x02` | OPEN (transport) |
| `zenoh.msg_id == 0x03` | CLOSE |
| `zenoh.msg_id == 0x05` | FRAME |
| `zenoh.msg_id == 0x06` | FRAGMENT |
| `zenoh.msg_id == 0x07` | JOIN |
| `zenoh.net.msg_id == 0x19` | INTEREST (network) |
| `zenoh.net.msg_id == 0x1a` | RESPONSE_FINAL |
| `zenoh.net.msg_id == 0x1b` | RESPONSE |
| `zenoh.net.msg_id == 0x1c` | REQUEST |
| `zenoh.net.msg_id == 0x1d` | PUSH |
| `zenoh.net.msg_id == 0x1e` | DECLARE |

## Key expression

| Filter | What it selects |
|--------|-----------------|
| `zenoh.key_suffix contains "foo"` | Packets with "foo" in the raw wire suffix |
| `zenoh.keyexpr == "a/b/c"` | Packets whose fully resolved key is exactly `a/b/c` |
| `zenoh.keyexpr contains "demo"` | Packets with "demo" anywhere in the resolved key |

## Peer identity

| Filter | What it selects |
|--------|-----------------|
| `zenoh.session.src_zid == AA:BB:CC:...` | Packets from a specific peer |
| `zenoh.session.dst_zid == AA:BB:CC:...` | Packets to a specific peer |

## Request-response correlation

| Filter | What it selects |
|--------|-----------------|
| `zenoh.request_id == 5` | All REQUEST / RESPONSE with rid=5 |
| `zenoh.req.response_frame` | REQUEST packets that received a response |
| `zenoh.resp.request_frame` | RESPONSE packets linked to a request |
| `zenoh.req.response_time_ms > 10` | Exchanges taking more than 10 ms |

## Sequence-number gaps

| Filter | What it selects |
|--------|-----------------|
| `zenoh.sn.gap == true` | Frames with a missing predecessor |
| `zenoh.sn.gap_size > 1` | Frames where more than one predecessor is missing |

## Declaration lifecycle

| Filter | What it selects |
|--------|-----------------|
| `zenoh.decl.undeclared_frame` | D_* packets that have a matching U_* later |
| `zenoh.decl.declared_frame` | U_* packets linked to an earlier D_* |
| `zenoh.decl.active_ms < 1000` | Declarations active for less than 1 second |
| `zenoh.decl.active_ms > 60000` | Declarations active for more than 1 minute |

## Session summary (generated, visible in detail pane)

| Field | Description |
|-------|-------------|
| `zenoh.session.version` | Protocol version byte (e.g. 0x08) |
| `zenoh.session.ke_count` | Declared key expressions seen so far |
| `zenoh.session.sub_count` | Subscribers declared so far |
| `zenoh.session.qbl_count` | Queryables declared so far |
| `zenoh.session.tok_count` | Tokens declared so far |
