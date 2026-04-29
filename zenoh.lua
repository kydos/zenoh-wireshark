-- zenoh.lua  ─  Wireshark Lua dissector for the Zenoh protocol
--
-- Supports:
--   TCP 7447  – transport messages   (2-byte LE batch-length prefix)
--   UDP 7447  – transport messages   (datagram boundary = batch)
--   UDP 7446  – scouting messages    (SCOUT / HELLO)
--
-- Zenoh wire-format references
--   spec  : zenoh-spec/docs/modules/wire/pages/
--   impls : zenoh-rust/commons/zenoh-codec/src/
--
-- Message IDs (5-bit field, bits 4:0 of header byte)
--   Transport : OAM(0x00) INIT(0x01) OPEN(0x02) CLOSE(0x03)
--               KEEP_ALIVE(0x04) FRAME(0x05) FRAGMENT(0x06) JOIN(0x07)
--   Network   : INTEREST(0x19) RESPONSE_FINAL(0x1A) RESPONSE(0x1B)
--               REQUEST(0x1C) PUSH(0x1D) DECLARE(0x1E) OAM(0x1F)
--   Data-body : PUT(0x01) DEL(0x02) QUERY(0x03) REPLY(0x04) ERR(0x05)
--   Scouting  : SCOUT(0x01) HELLO(0x02)
--
-- Header byte layout:
--   bit 7 = Z  (extensions follow)
--   bit 6 = FL2 (message-specific)
--   bit 5 = FL1 (message-specific)
--   bits 4:0 = message ID

-- ──────────────────────────────────────────────────────────────
-- 1.  Protocol object
-- ──────────────────────────────────────────────────────────────

-- Use a unique abbr so this Lua dissector coexists with any installed native plugin.
-- The display name is still "Zenoh Protocol" for readability in the UI.
local zenoh_proto      = Proto("zenoh", "Zenoh Protocol (Lua)")

-- ──────────────────────────────────────────────────────────────
-- 1.5  Preferences
-- ──────────────────────────────────────────────────────────────
-- Access via Edit → Preferences → Protocols → zenoh (Lua).

zenoh_proto.prefs.show_payload = Pref.bool(
    "Show payload bytes",
    false,
    "Decode and display payload content instead of showing only the length")

zenoh_proto.prefs.expert_unknown = Pref.bool(
    "Warn on unknown message IDs",
    true,
    "Emit an expert-info warning when an unrecognised transport or network message ID is encountered")

-- ──────────────────────────────────────────────────────────────
-- 2.  Value-string tables (for display)
-- ──────────────────────────────────────────────────────────────

local vs_transport_id  = {
    [0x00] = "OAM",
    [0x01] = "INIT",
    [0x02] = "OPEN",
    [0x03] = "CLOSE",
    [0x04] = "KEEP_ALIVE",
    [0x05] = "FRAME",
    [0x06] = "FRAGMENT",
    [0x07] = "JOIN",
}
local vs_network_id    = {
    [0x19] = "INTEREST",
    [0x1A] = "RESPONSE_FINAL",
    [0x1B] = "RESPONSE",
    [0x1C] = "REQUEST",
    [0x1D] = "PUSH",
    [0x1E] = "DECLARE",
    [0x1F] = "OAM",
}
local vs_data_id       = {
    [0x01] = "PUT",
    [0x02] = "DEL",
    [0x03] = "QUERY",
    [0x04] = "REPLY",
    [0x05] = "ERR",
}
local vs_decl_id       = {
    [0x00] = "D_KEYEXPR",
    [0x01] = "U_KEYEXPR",
    [0x02] = "D_SUBSCRIBER",
    [0x03] = "U_SUBSCRIBER",
    [0x04] = "D_QUERYABLE",
    [0x05] = "U_QUERYABLE",
    [0x06] = "D_TOKEN",
    [0x07] = "U_TOKEN",
    [0x1A] = "D_FINAL",
}
local vs_scout_id      = { [0x01] = "SCOUT", [0x02] = "HELLO" }
local vs_wai           = { [0] = "Router", [1] = "Peer", [2] = "Client" }
-- WhatAmI as direct Rust enum repr (Router=0b001, Peer=0b010, Client=0b100).
-- Used wherever the raw bitmask value is written to the wire (e.g. LinkState OAM body).
local vs_wai_bitmask   = { [1] = "Router", [2] = "Peer", [4] = "Client" }
local vs_enc_type      = { [0] = "Unit", [1] = "Z64", [2] = "ZBuf", [3] = "Reserved" }
local vs_close_reason  = {
    [0] = "Generic",
    [1] = "Expired",
    [2] = "Full",
    [3] = "Invalid",
    [4] = "MaxSessions",
    [5] = "MaxLinks",
}
local vs_consolidation = {
    [0] = "Auto", [1] = "None", [2] = "Monotonic", [3] = "Latest",
}
local vs_priority      = {
    [0] = "Control",
    [1] = "RealTime",
    [2] = "InteractiveHigh",
    [3] = "InteractiveLow",
    [4] = "DataHigh",
    [5] = "Data",
    [6] = "DataLow",
    [7] = "Background",
}
local vs_resolution    = {
    [0] = "8-bit", [1] = "16-bit", [2] = "32-bit", [3] = "64-bit",
}
local vs_qos_congestion = {
    [0] = "Drop",
    [1] = "Block",
    [2] = "BlockFirst",
}
local vs_request_target = {
    [0] = "BestMatching",
    [1] = "All",
    [2] = "AllComplete",
}
local vs_interest_mode  = {
    [0] = "Final",
    [1] = "Current",
    [2] = "Future",
    [3] = "CurrentFuture",
}

-- ──────────────────────────────────────────────────────────────
-- 3.  ProtoField definitions
-- ──────────────────────────────────────────────────────────────

local pf               = {}
local F                = zenoh_proto.fields -- must assign all pf.*  values here

-- framing
pf.frame_len           = ProtoField.uint16("zenoh.frame_len",       "Frame Length",    base.DEC)
pf.batch_header        = ProtoField.uint8( "zenoh.batch.header",    "Batch Header",    base.HEX)
pf.batch_compressed    = ProtoField.bool(  "zenoh.batch.compressed","LZ4 Compressed",  8, {"Yes","No"}, 0x01)

-- generic header/flags
pf.header              = ProtoField.uint8("zenoh.header", "Header Byte", base.HEX)
pf.msg_id              = ProtoField.uint8("zenoh.msg_id", "Message ID", base.HEX)
pf.flag_z              = ProtoField.bool("zenoh.flag_z", "Z (Extensions)", 8, { "Yes", "No" }, 0x80)
pf.flag_fl2            = ProtoField.bool("zenoh.flag_fl2", "FL2", 8, { "Yes", "No" }, 0x40)
pf.flag_fl1            = ProtoField.bool("zenoh.flag_fl1", "FL1", 8, { "Yes", "No" }, 0x20)

-- VLE-encoded integers (uint32 covers 32-bit default resolution; shown with explicit value)
pf.seq_num             = ProtoField.uint32("zenoh.seq_num", "Sequence Number", base.DEC)
pf.request_id          = ProtoField.uint32("zenoh.request_id", "Request ID", base.DEC)
pf.interest_id         = ProtoField.uint32("zenoh.interest_id", "Interest ID", base.DEC)
pf.expr_id             = ProtoField.uint32("zenoh.expr_id", "Expression ID", base.DEC)
pf.entity_id           = ProtoField.uint32("zenoh.entity_id", "Entity ID", base.DEC)
pf.key_scope           = ProtoField.uint32("zenoh.key_scope", "Key Scope (ExprId)", base.DEC)
pf.key_suffix          = ProtoField.string("zenoh.key_suffix", "Key Suffix")
pf.payload_len         = ProtoField.uint32("zenoh.payload_len", "Payload Length", base.DEC)
pf.payload_data        = ProtoField.bytes("zenoh.payload", "Payload (omitted)", base.NONE)

-- INIT / JOIN
pf.version             = ProtoField.uint8("zenoh.version", "Protocol Version", base.HEX)
pf.zid                 = ProtoField.bytes("zenoh.zid", "Zenoh ID")
pf.wai                 = ProtoField.uint8("zenoh.wai", "WhatAmI", base.DEC, vs_wai)
pf.resolution          = ProtoField.uint8("zenoh.resolution", "Resolution Byte", base.HEX)
pf.res_fsn             = ProtoField.uint8("zenoh.res_fsn", "FSN Resolution", base.DEC, vs_resolution)
pf.res_rid             = ProtoField.uint8("zenoh.res_rid", "RID Resolution", base.DEC, vs_resolution)
pf.batch_size          = ProtoField.uint16("zenoh.batch_size", "Batch Size", base.DEC)
pf.cookie              = ProtoField.bytes("zenoh.cookie", "Cookie")

-- OPEN
pf.lease               = ProtoField.uint32("zenoh.lease", "Lease Duration", base.DEC)
pf.initial_sn          = ProtoField.uint32("zenoh.initial_sn", "Initial Seq Num", base.DEC)

-- CLOSE
pf.close_reason        = ProtoField.uint8("zenoh.close_reason", "Close Reason", base.DEC, vs_close_reason)

-- FRAME / FRAGMENT
pf.frame_reliable      = ProtoField.bool("zenoh.frame_reliable", "Reliable Channel", 8, { "Yes", "No" }, 0x20)
pf.fragment_more       = ProtoField.bool("zenoh.fragment_more", "More Fragments", 8, { "Yes", "No" }, 0x40)

-- JOIN
pf.join_lease          = ProtoField.uint32("zenoh.join_lease", "Lease", base.DEC)
pf.next_sn_re          = ProtoField.uint32("zenoh.next_sn_re", "Next SN Reliable", base.DEC)
pf.next_sn_be          = ProtoField.uint32("zenoh.next_sn_be", "Next SN BestEffort", base.DEC)

-- Encoding field
pf.encoding_id         = ProtoField.uint32("zenoh.encoding_id", "Encoding ID", base.DEC)
pf.encoding_schema     = ProtoField.bytes("zenoh.encoding_schema", "Encoding Schema")

-- Timestamp
pf.ts_ntp              = ProtoField.bytes("zenoh.ts_ntp", "Timestamp (NTP64)")
pf.ts_zid              = ProtoField.bytes("zenoh.ts_zid", "Timestamp ZenohID")

-- PUT / DEL / QUERY / REPLY / ERR
pf.consolidation       = ProtoField.uint8("zenoh.consolidation", "Consolidation", base.DEC, vs_consolidation)
pf.query_params        = ProtoField.string("zenoh.query_params", "Query Parameters")
pf.query_body_len      = ProtoField.uint32("zenoh.query.body_len", "Query Body Length", base.DEC)
pf.data_msg_id         = ProtoField.uint8("zenoh.data.msg_id", "Data Message ID", base.HEX, vs_data_id)

-- DECLARE / declarations
pf.decl_interest_id    = ProtoField.uint32("zenoh.decl_interest_id", "Interest ID", base.DEC)
pf.decl_id             = ProtoField.uint8("zenoh.decl_id", "Declaration ID", base.HEX, vs_decl_id)
pf.queryable_complete  = ProtoField.bool("zenoh.queryable.complete", "Queryable Complete", 8, { "Yes", "No" }, 0x01)
pf.queryable_distance  = ProtoField.uint16("zenoh.queryable.distance", "Queryable Distance", base.DEC)

-- Extensions
pf.extension           = ProtoField.uint8("zenoh.extension", "Extension Header", base.HEX)
pf.ext_id              = ProtoField.uint8("zenoh.ext_id", "  ID", base.HEX)
pf.ext_m               = ProtoField.bool("zenoh.ext_m", "  Mandatory", 8, { "Yes", "No" }, 0x10)
pf.ext_enc             = ProtoField.uint8("zenoh.ext_enc", "  Encoding", base.DEC, vs_enc_type)
pf.ext_z64_val         = ProtoField.uint32("zenoh.ext_z64", "  Value (Z64)", base.DEC)
pf.ext_zbuf            = ProtoField.bytes("zenoh.ext_zbuf", "  Body (ZBuf)")
pf.ext_qos_prio        = ProtoField.uint8("zenoh.ext_qos_prio", "  QoS Priority", base.DEC, vs_priority)
pf.ext_qos_cong        = ProtoField.uint8("zenoh.ext_qos_congestion", "  QoS Congestion", base.DEC, vs_qos_congestion)
pf.ext_qos_express     = ProtoField.bool("zenoh.ext_qos_express", "  QoS Express", 8, { "Yes", "No" }, 0x10)
pf.ext_qos_drop_first  = ProtoField.bool("zenoh.ext_qos_drop_first", "  QoS Drop First", 8, { "Yes", "No" }, 0x20)
pf.ext_patch           = ProtoField.uint32("zenoh.ext_patch", "  Patch Version", base.DEC)
pf.ext_region_name     = ProtoField.string("zenoh.ext_region_name", "  Region Name")
pf.ext_remote_bound    = ProtoField.uint32("zenoh.ext_remote_bound", "  Remote Bound", base.DEC)
pf.net_node_id         = ProtoField.uint32("zenoh.net.node_id", "Node ID", base.DEC)
pf.request_target      = ProtoField.uint8("zenoh.request.target", "Request Target", base.DEC, vs_request_target)
pf.request_budget      = ProtoField.uint32("zenoh.request.budget", "Request Budget", base.DEC)
pf.request_timeout     = ProtoField.uint32("zenoh.request.timeout", "Request Timeout", base.DEC)
pf.source_zid          = ProtoField.bytes("zenoh.source.zid", "Source Zenoh ID")
pf.source_eid          = ProtoField.uint32("zenoh.source.eid", "Source Entity ID", base.DEC)
pf.source_sn           = ProtoField.uint32("zenoh.source.sn", "Source Sequence Number", base.DEC)
pf.responder_zid       = ProtoField.bytes("zenoh.responder.zid", "Responder Zenoh ID")
pf.responder_eid       = ProtoField.uint32("zenoh.responder.eid", "Responder Entity ID", base.DEC)
pf.attachment_count    = ProtoField.uint32("zenoh.attachment.count", "Attachment Entry Count", base.DEC)
pf.attachment_key      = ProtoField.string("zenoh.attachment.key", "Attachment Key")
pf.attachment_val      = ProtoField.bytes("zenoh.attachment.value", "Attachment Value")

-- SCOUT / HELLO
pf.scout_wai_matcher   = ProtoField.uint8("zenoh.scout_matcher", "WhatAmI Matcher", base.HEX)
pf.locator_count       = ProtoField.uint32("zenoh.locator_count", "Locator Count", base.DEC)
pf.locator             = ProtoField.string("zenoh.locator", "Locator")
pf.scout_id_flag       = ProtoField.bool("zenoh.scout_id_flag", "I (ZID Present)", 8, { "Yes", "No" }, 0x08)

-- OAM
pf.oam_id              = ProtoField.uint32("zenoh.oam_id", "OAM ID", base.DEC)

-- INTEREST
pf.interest_options    = ProtoField.uint8("zenoh.interest_options", "Options Byte", base.HEX)
pf.interest_mod        = ProtoField.uint8("zenoh.interest_mod", "Mode", base.DEC, vs_interest_mode)
pf.interest_opt_keyexprs = ProtoField.bool("zenoh.interest.keyexprs", "Interest Key Expressions", 8,
                            { "Yes", "No" }, 0x01)
pf.interest_opt_subscribers = ProtoField.bool("zenoh.interest.subscribers", "Interest Subscribers", 8,
                               { "Yes", "No" }, 0x02)
pf.interest_opt_queryables = ProtoField.bool("zenoh.interest.queryables", "Interest Queryables", 8,
                              { "Yes", "No" }, 0x04)
pf.interest_opt_tokens = ProtoField.bool("zenoh.interest.tokens", "Interest Tokens", 8,
                          { "Yes", "No" }, 0x08)
pf.interest_opt_restricted = ProtoField.bool("zenoh.interest.restricted", "Interest Restricted", 8,
                               { "Yes", "No" }, 0x10)
pf.interest_opt_named  = ProtoField.bool("zenoh.interest.named", "Interest Named", 8,
                          { "Yes", "No" }, 0x20)
pf.interest_opt_mapping = ProtoField.bool("zenoh.interest.mapping", "Interest Mapping", 8,
                           { "Sender", "Receiver" }, 0x40)
pf.interest_opt_aggregate = ProtoField.bool("zenoh.interest.aggregate", "Interest Aggregate Replies", 8,
                              { "Yes", "No" }, 0x80)

-- Session ZID (propagated from INIT/JOIN/HELLO to every subsequent packet)
pf.session_src_zid     = ProtoField.bytes("zenoh.session.src_zid", "Session Source ZID")
pf.session_dst_zid     = ProtoField.bytes("zenoh.session.dst_zid", "Session Dest ZID")
-- Network-layer message ID (distinct from transport-layer zenoh.msg_id)
pf.net_msg_id          = ProtoField.uint8("zenoh.net.msg_id", "Network Message ID",
                             base.HEX, vs_network_id)
-- Fully resolved key expression (scope looked up from D_KEYEXPR declarations)
pf.keyexpr             = ProtoField.string("zenoh.keyexpr", "Key Expression (resolved)")

-- Request-Response Correlation
pf.req_response_frame   = ProtoField.framenum("zenoh.req.response_frame",  "Response In")
pf.req_response_time_ms = ProtoField.float("zenoh.req.response_time_ms",   "Response Time (ms)")
pf.resp_request_frame   = ProtoField.framenum("zenoh.resp.request_frame",  "Request In")
-- SN Gap Detection
pf.sn_gap               = ProtoField.bool("zenoh.sn.gap",      "Sequence Number Gap",  8, {"Gap","No Gap"}, 0x01)
pf.sn_gap_size          = ProtoField.uint32("zenoh.sn.gap_size","Missing Frames Count", base.DEC)

-- Declaration Lifecycle
pf.decl_declared_frame   = ProtoField.framenum("zenoh.decl.declared_frame",   "Declared In")
pf.decl_undeclared_frame = ProtoField.framenum("zenoh.decl.undeclared_frame",  "Undeclared In")
pf.decl_active_ms        = ProtoField.float("zenoh.decl.active_ms",            "Active Duration (ms)")
-- Session Summary
pf.session_version       = ProtoField.uint8( "zenoh.session.version",    "Protocol Version",          base.HEX)
pf.session_ke_count      = ProtoField.uint32("zenoh.session.ke_count",   "Declared Key Expressions",  base.DEC)
pf.session_sub_count     = ProtoField.uint32("zenoh.session.sub_count",  "Active Subscribers",        base.DEC)
pf.session_qbl_count     = ProtoField.uint32("zenoh.session.qbl_count",  "Active Queryables",         base.DEC)
pf.session_tok_count     = ProtoField.uint32("zenoh.session.tok_count",  "Active Tokens",             base.DEC)

-- Assign all fields to the protocol
for _, v in pairs(pf) do
    F[#F + 1] = v
end

-- ──────────────────────────────────────────────────────────────
-- 3.5  Cross-packet state
-- ──────────────────────────────────────────────────────────────

-- ZID table: stream_zid_table[stream_key] = { src = ByteArray, dst = ByteArray }
-- Populated by INIT/JOIN/SCOUT/HELLO parsers on the first dissection pass.
local stream_zid_table     = {}
-- Key expression table: keyexpr_table[stream_key][direction][expr_id] = "full/key/expression"
-- Populated when a D_KEYEXPR declaration is parsed. ExprIds are scoped per face
-- AND per direction in Zenoh, so we must keep separate tables for each side of
-- the link. The 'direction' key identifies the declarer (src side of the packet
-- carrying the D_KEYEXPR).
local keyexpr_table        = {}
-- Per-packet ZID snapshot — stable across Wireshark's multiple re-dissection passes.
local packet_zid_cache     = {}
-- Per-packet resolved key expression cache.
local packet_keyexpr_cache = {}
-- Fragment tracking: frag_table[stream_key][channel] = { first_sn, last_sn, count, total_bytes }
-- channel key: string "R" (reliable) or "B" (best-effort)
-- Updated on first pass (pinfo.visited == false); read-only on re-dissection.
local frag_table           = {}
-- Per-packet fragment annotation cache for stable re-dissection.
local packet_frag_cache    = {}

-- Request-Response Correlation
-- req_table[sk][rid] = { frame = N, time_s = T }
local req_table          = {}
-- pkt_req_resp_cache[pkt] = { resp_frame=N, delta_ms=M }   (populated from RESPONSE back-annotation)
local pkt_req_resp_cache = {}
-- pkt_resp_req_cache[pkt][rid] = { req_frame=N, delta_ms=M } (populated from RESPONSE/FINAL parsing)
local pkt_resp_req_cache = {}
-- SN Gap Detection: sn_state[sk][ch] = last_sn  (ch = "R" or "B")
local sn_state           = {}
-- pkt_sn_cache[pkt] = { expected=N, got=N, channel="R"|"B" }
local pkt_sn_cache       = {}

-- Declaration Lifecycle
-- decl_state[sk][dtype][eid] = { decl_frame=N, decl_time_s=T [, undecl_frame=N, undecl_time_s=T] }
-- dtype: "sub" | "qbl" | "tok" | "ke"
local decl_state         = {}
-- pkt_decl_cache[pkt] = { partner_frame=N, delta_ms=M, is_undecl=bool }
local pkt_decl_cache     = {}
-- Session protocol version: session_ver[sk] = version_byte
local session_ver        = {}

-- Compression state per TCP stream.
-- stream_compress_init[sk] = true  when InitAck on this stream carries extension ID 0x6,
--   meaning both peers agreed to use batch-level LZ4 compression.
local stream_compress_init = {}
-- stream_compress_from[sk] = pinfo.number of the OpenAck that closed the handshake.
-- Every batch in frames with pinfo.number > this value starts with a 1-byte BatchHeader
--   (bit 0: 1 = LZ4-compressed, 0 = sent uncompressed despite compression being enabled).
local stream_compress_from = {}

-- Field extractor for tcp.stream.  Field.new MUST be called at the script top level
-- (i.e. during plugin load), not inside any function — Wireshark registers extractors
-- at load time.  The actual value is retrieved by calling f_tcp_stream() at dissect time.
local f_tcp_stream = Field.new("tcp.stream")

-- ──────────────────────────────────────────────────────────────
-- 4.  Helper functions
-- ──────────────────────────────────────────────────────────────

-- Return a stable string key for the current packet's stream/session.
-- TCP: uses the tcp.stream integer index from the field extractor.
-- UDP: constructs a sorted 4-tuple so A→B and B→A share the same key.
local function get_stream_key(pinfo)
    local tcp_fi = f_tcp_stream()
    if tcp_fi then
        return "tcp:" .. tostring(tcp_fi.value)
    end
    -- UDP fallback
    local s1 = tostring(pinfo.src)  .. ":" .. tostring(pinfo.src_port)
    local s2 = tostring(pinfo.dst)  .. ":" .. tostring(pinfo.dst_port)
    if s1 > s2 then s1, s2 = s2, s1 end
    return "udp:" .. s1 .. "-" .. s2
end

-- Return a key identifying the SENDER side (src) of the current packet on its
-- stream. Used to scope per-direction state such as the D_KEYEXPR table.
local function get_sender_dir_key(pinfo)
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
end

-- Return a key identifying the RECEIVER side (dst) of the current packet on its
-- stream.
local function get_receiver_dir_key(pinfo)
    return tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
end

-- Record the ZID bytes seen in INIT / JOIN / SCOUT / HELLO into the stream table.
-- Only writes on the first dissection pass (pinfo.visited == false).
-- The first distinct ZID on a stream is "src"; the second distinct one is "dst".
local function record_peer_zid(pinfo, tvb, offset, zid_bytes)
    if pinfo.visited then return end
    local key = get_stream_key(pinfo)
    if not stream_zid_table[key] then stream_zid_table[key] = {} end
    local entry = stream_zid_table[key]
    local ba = tvb(offset, zid_bytes):bytes()
    if not entry.src then
        entry.src = ba
    elseif not entry.dst then
        -- Only store as dst if genuinely different from src
        if tostring(ba) ~= tostring(entry.src) then
            entry.dst = ba
        end
    end
end

-- Read a variable-length encoded (LEB128) integer from tvb at offset.
-- Returns (value, bytes_consumed).  Handles up to 9 bytes (z64).
local function read_vle(tvb, offset, limit)
    local value    = 0
    local consumed = 0
    local shift    = 0
    local maxoff   = math.min(offset + 9, limit or tvb:len())
    for i = offset, maxoff - 1 do
        local b  = tvb(i, 1):uint()
        consumed = consumed + 1
        value    = value + (b % 128) * (2 ^ shift) -- bit.band(b,0x7F) × 2^shift
        shift    = shift + 7
        if b < 128 then break end                  -- bit 7 = 0 → last byte
    end
    return value, consumed
end

-- Safe byte read that returns 0 if out-of-range
local function safe_byte(tvb, offset)
    if offset >= tvb:len() then return 0 end
    return tvb(offset, 1):uint()
end

-- Return a nil-safe name from a lookup table
local function lookup(tbl, val)
    return tbl[val] or string.format("Unknown(0x%02x)", val)
end

-- Add a VLE field to a tree node; returns new offset.
local function add_vle(tree, field, tvb, offset, limit)
    local maxoff   = limit or tvb:len()
    local val, len = read_vle(tvb, offset, maxoff)
    local actual   = math.min(len, math.max(0, maxoff - offset))
    if actual > 0 then
        tree:add(field, tvb(offset, actual), val)
    end
    return math.min(offset + len, maxoff), val, len
end

-- Parse a UTF-8 string: z16-length prefix + bytes.
-- Returns (string_value, new_offset).
local function read_z16_string(tvb, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return "", offset end
    local slen, llen = read_vle(tvb, offset, maxoff) -- z16 length
    offset = math.min(offset + llen, maxoff)
    if slen == 0 then return "", offset end
    local actual = math.min(slen, math.max(0, maxoff - offset))
    local s = actual > 0 and tvb(offset, actual):string() or ""
    return s, math.min(offset + slen, maxoff)
end

-- Parse a z8-prefixed byte string. Returns (bytes_tvbrange_or_nil, new_offset).
local function read_z8_bytes(tvb, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return nil, offset end
    local blen, llen = read_vle(tvb, offset, maxoff) -- z8 length
    offset = math.min(offset + llen, maxoff)
    if blen == 0 then return nil, offset end
    local actual = math.min(blen, math.max(0, maxoff - offset))
    local r = actual > 0 and tvb(offset, actual) or nil
    return r, math.min(offset + blen, maxoff)
end

-- Parse WireExpr into a tree node. Returns new offset.
-- n_flag: suffix present; m_flag: mapping (1=sender, 0=receiver)
-- raw_suffix: when true the suffix is raw bytes to limit (WireExpr extension body
--   encoding); when false (default) the suffix is a z16-length-prefixed string
--   (standard on-wire encoding used everywhere else).
local function parse_wire_expr(tvb, pinfo, tree, offset, n_flag, m_flag, limit, raw_suffix)
    local maxoff   = limit or tvb:len()
    local we_start = offset
    local we_tree  = tree:add(zenoh_proto, tvb(offset, 0), "WireExpr")
    local scope_val, slen = read_vle(tvb, offset, maxoff)
    local scope_actual = math.min(slen, math.max(0, maxoff - offset))
    if scope_actual > 0 then
        we_tree:add(pf.key_scope, tvb(offset, scope_actual), scope_val)
    end
    offset = math.min(offset + slen, maxoff)

    local suffix = ""
    if n_flag then
        if raw_suffix then
            -- Extension-body encoding: suffix fills all remaining bytes in the zbuf
            -- (the outer zbuf length already bounds the extent; no inner length prefix).
            local suf_len = math.max(0, maxoff - offset)
            if suf_len > 0 then
                suffix = tvb(offset, suf_len):string()
                we_tree:add(pf.key_suffix, tvb(offset, suf_len), suffix)
            end
            offset = maxoff
        else
            local new_off
            suffix, new_off = read_z16_string(tvb, offset, maxoff)
            if #suffix > 0 then
                local avail = math.min(new_off - offset, math.max(0, maxoff - offset))
                if avail > 0 then
                    we_tree:add(pf.key_suffix, tvb(offset, avail), suffix)
                end
            end
            offset = new_off
        end
    end

    -- Resolve the full key expression from declarations seen earlier on this stream.
    -- scope==0: suffix is the absolute key.
    -- scope!=0: look up the declared base expression and append suffix.
    local resolved = nil
    if scope_val == 0 and #suffix > 0 then
        resolved = suffix
    elseif scope_val ~= 0 then
        local sk    = get_stream_key(pinfo)
        -- mapping=sender (m_flag=true)  → look up in the sender's own declarations
        -- mapping=receiver (m_flag=false) → look up in the receiver's declarations
        --   (which were sent on the opposite direction of this stream)
        local dir   = m_flag and get_sender_dir_key(pinfo) or get_receiver_dir_key(pinfo)
        local stbl  = keyexpr_table[sk]
        local tbl   = stbl and stbl[dir]
        local base  = tbl and tbl[scope_val]
        if base then
            -- The wire suffix already contains the leading separator when present;
            -- do not add an extra "/" between base and suffix.
            resolved = (#suffix > 0) and (base .. suffix) or base
        end
    end
    if resolved then
        -- Cache the result for stability across Wireshark's re-dissection passes.
        if not pinfo.visited then
            if not packet_keyexpr_cache[pinfo.number] then
                packet_keyexpr_cache[pinfo.number] = {}
            end
            packet_keyexpr_cache[pinfo.number][scope_val] = resolved
        else
            local c = packet_keyexpr_cache[pinfo.number]
            if c and c[scope_val] then resolved = c[scope_val] end
        end
        we_tree:add(pf.keyexpr, tvb(we_start, math.max(0, offset - we_start)), resolved)
        we_tree:append_text(string.format(" [key=%s]", resolved))
    end

    local mapping = m_flag and "sender" or "receiver"
    we_tree:append_text(string.format(" scope=%d mapping=%s", scope_val, mapping))
    we_tree:set_len(offset - we_start)
    return offset, resolved, scope_val, suffix
end

-- Parse a Timestamp field (HLC NTP64 + ZenohID). Returns new_offset.
local function parse_timestamp(tvb, pinfo, tree, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return offset end
    local ts_start = offset
    local ts_tree = tree:add(zenoh_proto, tvb(offset, 0), "Timestamp")

    -- NTP64 (z64 VLE)
    local _, ntp_len = read_vle(tvb, offset, maxoff)
    local ntp_actual = math.min(ntp_len, math.max(0, maxoff - offset))
    if ntp_actual > 0 then
        ts_tree:add(pf.ts_ntp, tvb(offset, ntp_actual))
    end
    offset = math.min(offset + ntp_len, maxoff)

    -- ZID: z8-prefixed
    if offset < maxoff then
        local zid_len, ll = read_vle(tvb, offset, maxoff)
        offset = math.min(offset + ll, maxoff)
        local zid_actual = math.min(zid_len, math.max(0, maxoff - offset))
        if zid_actual > 0 then
            ts_tree:add(pf.ts_zid, tvb(offset, zid_actual))
        end
        offset = math.min(offset + zid_len, maxoff)
    end

    ts_tree:set_len(offset - ts_start)
    return offset
end

-- Parse an Encoding field (z32 packed: bits[0]=schema_present, bits[31:1]=id).
-- Returns new_offset.
local function parse_encoding(tvb, pinfo, tree, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return offset end
    local raw_val, vlen = read_vle(tvb, offset, maxoff)
    local enc_id        = math.floor(raw_val / 2) -- raw_val >> 1
    local has_schema    = (raw_val % 2) == 1      -- raw_val & 1
    local enc_actual    = math.min(vlen, math.max(0, maxoff - offset))
    local enc_tree      = tree:add(pf.encoding_id, tvb(offset, enc_actual), enc_id)
    enc_tree:append_text(string.format(" (0x%x)", enc_id))
    offset = math.min(offset + vlen, maxoff)

    if has_schema then
        local schema_bytes, new_off = read_z8_bytes(tvb, offset, maxoff)
        if schema_bytes then
            enc_tree:add(pf.encoding_schema, schema_bytes)
        end
        offset = new_off
    end
    return offset
end

local function add_omitted_payload(tree, tvb, offset, payload_len, limit)
    local maxoff = limit or tvb:len()
    local actual = math.min(payload_len, math.max(0, maxoff - offset))
    if actual <= 0 then return math.min(offset + payload_len, maxoff) end

    if zenoh_proto.prefs.show_payload then
        -- Try to determine encoding from the raw bytes and render accordingly.
        local ok, raw = pcall(function() return tvb(offset, actual):string() end)
        if ok and raw then
            local first = tvb(offset, 1):uint()
            if first == 0x7B or first == 0x5B then  -- '{' or '['
                -- Likely JSON: show as string on a single line
                tree:add(pf.payload_data, tvb(offset, actual)):append_text(
                    " [JSON: " .. raw:gsub("[\r\n]+", " ") .. "]")
            elseif raw:match("^[\t\n\r\32-\126]+$") then
                -- Printable ASCII / UTF-8 text
                tree:add(pf.payload_data, tvb(offset, actual)):append_text(
                    " [Text: " .. raw .. "]")
            else
                -- Binary: show raw bytes (default ProtoField.bytes display)
                tree:add(pf.payload_data, tvb(offset, actual)):append_text(
                    string.format(" [Binary: %d bytes]", actual))
            end
        else
            tree:add(pf.payload_data, tvb(offset, actual))
        end
    else
        tree:add(pf.payload_data, tvb(offset, actual)):append_text(
            string.format(" [%d byte(s) not shown]", payload_len))
    end
    return math.min(offset + payload_len, maxoff)
end

local function append_info(pinfo, text)
    if not text or text == "" then return end
    local current = tostring(pinfo.cols.info)
    if current == "" then
        pinfo.cols.info:set(text)
    else
        pinfo.cols.info:append(" | " .. text)
    end
end

local function summarize_keyexpr(resolved, suffix)
    if resolved and resolved ~= "" then
        return resolved
    end
    if suffix and suffix ~= "" then
        return suffix
    end
    return nil
end

local function parse_entity_global_id(tvb, tree, offset, limit, zid_field, eid_field, label)
    local maxoff   = limit or tvb:len()
    local eg_start = offset
    local eg_tree  = tree:add(zenoh_proto, tvb(offset, 0), label or "Entity Global ID")

    if offset >= maxoff then
        eg_tree:set_len(0)
        return offset
    end

    local packed      = safe_byte(tvb, offset)
    local zid_len_enc = math.floor(packed / 16) % 16
    local zid_bytes   = 1 + zid_len_enc
    eg_tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Packed: zid_len=%d", zid_bytes))
    offset = offset + 1

    local zid_actual = math.min(zid_bytes, math.max(0, maxoff - offset))
    if zid_actual > 0 then
        eg_tree:add(zid_field or pf.zid, tvb(offset, zid_actual))
    end
    offset = math.min(offset + zid_bytes, maxoff)

    if offset < maxoff then
        local eid, eid_len = read_vle(tvb, offset, maxoff)
        local eid_actual   = math.min(eid_len, math.max(0, maxoff - offset))
        if eid_actual > 0 then
            eg_tree:add(eid_field or pf.entity_id, tvb(offset, eid_actual), eid)
        end
        offset = math.min(offset + eid_len, maxoff)
    end

    eg_tree:set_len(offset - eg_start)
    return offset
end

local function parse_source_info_body(tvb, tree, offset, limit)
    local maxoff   = limit or tvb:len()
    local si_start = offset
    local si_tree  = tree:add(zenoh_proto, tvb(offset, math.max(0, maxoff - offset)), "SourceInfo")

    offset = parse_entity_global_id(tvb, si_tree, offset, maxoff, pf.source_zid, pf.source_eid, "Source")
    if offset < maxoff then
        local sn, sn_len = read_vle(tvb, offset, maxoff)
        local sn_actual   = math.min(sn_len, math.max(0, maxoff - offset))
        if sn_actual > 0 then
            si_tree:add(pf.source_sn, tvb(offset, sn_actual), sn)
        end
        offset = math.min(offset + sn_len, maxoff)
    end

    si_tree:set_len(offset - si_start)
    return offset
end

local function parse_attachment_body(tvb, tree, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return offset end

    local count, count_len = read_vle(tvb, offset, maxoff)
    local count_actual = math.min(count_len, math.max(0, maxoff - offset))
    if count_actual > 0 then
        tree:add(pf.attachment_count, tvb(offset, count_actual), count)
    end
    offset = math.min(offset + count_len, maxoff)

    for i = 1, count do
        if offset >= maxoff then break end
        local entry_start = offset
        local entry_tree = tree:add(zenoh_proto, tvb(offset, 0),
            string.format("Attachment Entry [%d]", i - 1))

        local key, new_off = read_z16_string(tvb, offset, maxoff)
        local key_actual = math.min(new_off - offset, math.max(0, maxoff - offset))
        if key_actual > 0 then
            entry_tree:add(pf.attachment_key, tvb(offset, key_actual), key)
        end
        offset = new_off

        local val_bytes, val_off = read_z8_bytes(tvb, offset, maxoff)
        if val_bytes then
            entry_tree:add(pf.attachment_val, val_bytes)
        end
        offset = val_off
        entry_tree:set_len(offset - entry_start)
    end

    return offset
end

local function parse_query_body_ext(tvb, pinfo, tree, offset, limit)
    local maxoff   = limit or tvb:len()
    local body_len = math.max(0, maxoff - offset)
    local qb_tree  = tree:add(zenoh_proto, tvb(offset, body_len), "Query Body")

    offset = parse_encoding(tvb, pinfo, qb_tree, offset, maxoff)
    local payload_len = math.max(0, maxoff - offset)
    if payload_len > 0 then
        qb_tree:add(pf.query_body_len, tvb(offset, payload_len), payload_len)
        qb_tree:add(zenoh_proto, tvb(offset, payload_len),
            string.format("Query Body Payload [%d bytes]", payload_len))
        offset = add_omitted_payload(qb_tree, tvb, offset, payload_len, maxoff)
    end
    qb_tree:set_len(body_len)
    return offset
end

local function parse_wireexpr_ext_body(tvb, pinfo, tree, offset, limit)
    local maxoff = limit or tvb:len()
    if offset >= maxoff then return offset end
    -- First byte is a flags byte (not a message header): bit 0 = suffix present, bit 1 = Sender mapping.
    -- The Rust encoder writes the suffix as raw bytes to end-of-zbuf (no length prefix),
    -- so pass raw_suffix=true to parse_wire_expr.
    local flags  = safe_byte(tvb, offset)
    tree:add(pf.header, tvb(offset, 1))
    offset = offset + 1
    local flag_n = (flags % 2 == 1)
    local flag_m = (math.floor(flags / 2) % 2 == 1)
    return (parse_wire_expr(tvb, pinfo, tree, offset, flag_n, flag_m, maxoff, true))
end

local function decode_ext_z64(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.ext_z64_val, tvb(offset, vlen), val)
end

local function decode_transport_qos(ext_tree, tvb, _, offset, vlen, val)
    local prio = val % 8
    ext_tree:add(pf.ext_qos_prio, tvb(offset, math.min(vlen, 1)), prio)
    ext_tree:append_text(string.format(" priority=%s", lookup(vs_priority, prio)))
end

local function decode_network_qos(ext_tree, tvb, _, offset, vlen, val)
    local prio = val % 8
    local drop_first = (math.floor(val / 32) % 2) == 1
    local congestion = (math.floor(val / 8) % 2 == 1) and 1 or (drop_first and 2 or 0)
    ext_tree:add(pf.ext_qos_prio, tvb(offset, math.min(vlen, 1)), prio)
    ext_tree:add(pf.ext_qos_cong, tvb(offset, math.min(vlen, 1)), congestion)
    ext_tree:add(pf.ext_qos_express, tvb(offset, math.min(vlen, 1)))
    ext_tree:add(pf.ext_qos_drop_first, tvb(offset, math.min(vlen, 1)))
    ext_tree:append_text(string.format(" priority=%s congestion=%s express=%s",
        lookup(vs_priority, prio),
        lookup(vs_qos_congestion, congestion),
        (math.floor(val / 16) % 2 == 1) and "Y" or "N"))
end

local function decode_patch_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.ext_patch, tvb(offset, vlen), val)
end

local function decode_remote_bound_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.ext_remote_bound, tvb(offset, vlen), val)
end

local function decode_node_id_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.net_node_id, tvb(offset, vlen), val)
end

local function decode_request_target_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.request_target, tvb(offset, vlen), val)
end

local function decode_request_budget_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.request_budget, tvb(offset, vlen), val)
end

local function decode_request_timeout_ext(ext_tree, tvb, _, offset, vlen, val)
    ext_tree:add(pf.request_timeout, tvb(offset, vlen), val)
end

local function decode_queryable_info_ext(ext_tree, tvb, _, offset, vlen, val)
    local distance = math.floor(val / 256) % 65536
    ext_tree:add(pf.queryable_complete, tvb(offset, math.min(vlen, 1)))
    ext_tree:add(pf.queryable_distance, tvb(offset, vlen), distance)
    ext_tree:append_text(string.format(" complete=%s distance=%d",
        (val % 2 == 1) and "Y" or "N", distance))
end

local function decode_string_zbuf_ext(ext_tree, tvb, _, offset, actual, _, field)
    if actual <= 0 then return end
    ext_tree:add(field, tvb(offset, actual), tvb(offset, actual):string())
end

local function decode_timestamp_zbuf_ext(ext_tree, tvb, pinfo, offset, actual)
    if actual <= 0 then return end
    local ts_tree = ext_tree:add(zenoh_proto, tvb(offset, actual), "Timestamp")
    parse_timestamp(tvb, pinfo, ts_tree, offset, offset + actual)
end

local function decode_sourceinfo_zbuf_ext(ext_tree, tvb, _, offset, actual)
    if actual <= 0 then return end
    local si_tree = ext_tree:add(zenoh_proto, tvb(offset, actual), "SourceInfo")
    parse_source_info_body(tvb, si_tree, offset, offset + actual)
end

local function decode_responder_zbuf_ext(ext_tree, tvb, _, offset, actual)
    if actual <= 0 then return end
    local rid_tree = ext_tree:add(zenoh_proto, tvb(offset, actual), "Responder ID")
    parse_entity_global_id(tvb, rid_tree, offset, offset + actual, pf.responder_zid, pf.responder_eid, "Responder")
end

local function decode_attachment_zbuf_ext(ext_tree, tvb, _, offset, actual)
    if actual <= 0 then return end
    local att_tree = ext_tree:add(zenoh_proto, tvb(offset, actual), "Attachment")
    parse_attachment_body(tvb, att_tree, offset, offset + actual)
end

local function decode_query_body_zbuf_ext(ext_tree, tvb, pinfo, offset, actual)
    if actual <= 0 then return end
    parse_query_body_ext(tvb, pinfo, ext_tree, offset, offset + actual)
end

local function decode_wireexpr_zbuf_ext(ext_tree, tvb, pinfo, offset, actual)
    if actual <= 0 then return end
    local we_tree = ext_tree:add(zenoh_proto, tvb(offset, actual), "WireExprExt")
    parse_wireexpr_ext_body(tvb, pinfo, we_tree, offset, offset + actual)
end

-- Parse extension chain. Returns new_offset.
-- spec     (optional): table [id] = { name = string|fn(enc), unit=fn, z64=fn, zbuf=fn }
-- seen_ids (optional): output table; seen_ids[ext_id] = true for every ID encountered
local function parse_extensions(tvb, pinfo, tree, offset, spec, seen_ids)
    while offset < tvb:len() do
        local hdr       = safe_byte(tvb, offset)
        local ext_z     = (hdr >= 0x80)            -- bit 7
        local ext_enc   = math.floor(hdr / 32) % 4 -- bits 6:5
        local ext_m     = (hdr % 32 >= 16)         -- bit 4
        local ext_id    = hdr % 16                 -- bits 3:0
        local ext_spec  = spec and spec[ext_id]
        if seen_ids then seen_ids[ext_id] = true end

        local ext_start = offset
        local ext_tree  = tree:add(pf.extension, tvb(offset, 1))
        local name      = nil
        if ext_spec then
            if type(ext_spec.name) == "function" then
                name = ext_spec.name(ext_enc)
            else
                name = ext_spec.name
            end
        end
        local name_str  = name and string.format(" (%s)", name) or ""
        ext_tree:append_text(string.format(" ID=0x%x%s %s %s",
            ext_id, name_str,
            ext_enc == 0 and "Unit" or
            ext_enc == 1 and "Z64" or
            ext_enc == 2 and "ZBuf" or "Rsv",
            ext_m and "(Mandatory)" or ""))
        ext_tree:add(pf.ext_id, tvb(offset, 1), ext_id)
        ext_tree:add(pf.ext_m, tvb(offset, 1))
        ext_tree:add(pf.ext_enc, tvb(offset, 1), ext_enc)
        offset = offset + 1

        if ext_enc == 1 then
            -- Z64: VLE value
            local val, vlen = read_vle(tvb, offset)
            if ext_spec and ext_spec.z64 then
                ext_spec.z64(ext_tree, tvb, pinfo, offset, vlen, val)
            else
                ext_tree:add(pf.ext_z64_val, tvb(offset, vlen), val)
            end
            offset = offset + vlen
        elseif ext_enc == 2 then
            -- ZBuf: VLE length + bytes
            local blen, llen = read_vle(tvb, offset)
            offset = offset + llen
            local actual = math.min(blen, tvb:len() - offset)
            if ext_spec and ext_spec.zbuf then
                ext_spec.zbuf(ext_tree, tvb, pinfo, offset, actual, blen)
            elseif actual > 0 then
                ext_tree:add(pf.ext_zbuf, tvb(offset, actual))
            end
            offset = offset + blen
        elseif ext_enc == 0 and ext_spec and ext_spec.unit then
            ext_spec.unit(ext_tree, tvb, pinfo, offset)
        end
        -- ext_enc == 0: Unit → no body bytes

        ext_tree:set_len(offset - ext_start)

        if not ext_z then break end -- no more extensions
    end
    return offset
end

-- Pure-Lua LZ4 block-format decompressor.
-- Input : src_ba  – Wireshark ByteArray (compressed payload)
-- Output: a new ByteArray with decompressed bytes, or raises an error string on failure.
-- Implements the LZ4 block format as used by lz4_flex::block::{compress,decompress}_into.
local function lz4_block_decompress(src_ba)
    local src_len = src_ba:len()
    local out     = {}   -- decompressed bytes (1-indexed Lua table)
    local si      = 0    -- 0-indexed read cursor into src_ba

    local function read_byte()
        if si >= src_len then error("LZ4: unexpected end of input") end
        local b = src_ba:get_index(si)
        si = si + 1
        return b
    end

    while si < src_len do
        local token   = read_byte()
        local lit_len = math.floor(token / 16)   -- high nibble

        -- Extended literal length: keep adding while extra == 255
        if lit_len == 15 then
            while true do
                local extra = read_byte()
                lit_len = lit_len + extra
                if extra ~= 255 then break end
            end
        end

        -- Copy literal bytes directly to output
        for _ = 1, lit_len do out[#out + 1] = read_byte() end

        -- The last sequence of an LZ4 block has no match copy
        if si >= src_len then break end

        -- Match offset: little-endian u16
        local off_lo = read_byte()
        local off_hi = read_byte()
        local moff   = off_lo + off_hi * 256
        if moff == 0 then error("LZ4: zero match offset") end

        -- Match length: low nibble + 4; extended if nibble == 15
        local mlen_nibble = token % 16
        local mlen        = mlen_nibble + 4
        if mlen_nibble == 15 then
            while true do
                local extra = read_byte()
                mlen = mlen + extra
                if extra ~= 255 then break end
            end
        end

        -- Copy match bytes (sequential single-byte copy handles overlapping runs)
        local mpos = #out - moff
        for _ = 1, mlen do
            mpos = mpos + 1
            out[#out + 1] = out[mpos]
        end
    end

    -- Pack result into a Wireshark ByteArray so it can become a Tvb
    local ba = ByteArray.new()
    ba:set_size(#out)
    for i, v in ipairs(out) do ba:set_index(i - 1, v) end
    return ba
end

-- Convert a pinfo NSTime absolute timestamp to seconds (float).
-- Handles both NSTime objects (with .secs/.nsecs fields) and plain numbers.
local function ts_secs(ts)
    if type(ts) == "number" then
        return ts
    end
    return ts.secs + ts.nsecs * 1e-9
end

-- Record a Declare (D_*) event and optionally link it to an earlier declaration.
-- dtype: "sub"|"qbl"|"tok"|"ke"   eid: entity/expr id   is_undecl: true for U_* messages
local function track_decl(pinfo, tvb, dtype, eid, is_undecl, d_tree)
    local sk = get_stream_key(pinfo)
    if not decl_state[sk]        then decl_state[sk]        = {} end
    if not decl_state[sk][dtype] then decl_state[sk][dtype] = {} end
    local tbl = decl_state[sk][dtype]

    if not pinfo.visited then
        if not is_undecl then
            tbl[eid] = { decl_frame = pinfo.number, decl_time_s = ts_secs(pinfo.abs_ts) }
        else
            local entry = tbl[eid]
            if entry and not entry.undecl_frame then
                local now_s    = ts_secs(pinfo.abs_ts)
                local delta_ms = (now_s - entry.decl_time_s) * 1000
                entry.undecl_frame  = pinfo.number
                entry.undecl_time_s = now_s
                -- Cache for the U_ packet
                pkt_decl_cache[pinfo.number] = { partner_frame = entry.decl_frame, delta_ms = delta_ms, is_undecl = true }
                -- Back-annotate the D_ packet
                if not pkt_decl_cache[entry.decl_frame] then
                    pkt_decl_cache[entry.decl_frame] = { partner_frame = pinfo.number, delta_ms = delta_ms, is_undecl = false }
                end
            end
        end
    end

    -- Add cross-reference items from cache
    local c = pkt_decl_cache[pinfo.number]
    if c then
        if c.is_undecl then
            -- This is a U_ packet: show where it was declared and how long it was active
            local fi = d_tree:add(pf.decl_declared_frame, tvb(0, 0), c.partner_frame)
            fi:set_generated(true)
            local ai = d_tree:add(pf.decl_active_ms, tvb(0, 0), c.delta_ms)
            ai:set_generated(true)
        else
            -- This is a D_ packet: show where it was undeclared
            local fi = d_tree:add(pf.decl_undeclared_frame, tvb(0, 0), c.partner_frame)
            fi:set_generated(true)
            local ai = d_tree:add(pf.decl_active_ms, tvb(0, 0), c.delta_ms)
            ai:set_generated(true)
        end
    end
end

local function parse_transport_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset)
end
local function parse_network_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset)
end

local extspec_init = {
    [0x01] = { name = function(enc) return enc == 1 and "QoSLink" or "QoS" end, z64 = decode_ext_z64 },
    [0x02] = { name = "Shm" },
    [0x03] = { name = "Auth" },
    [0x04] = { name = "MultiLink" },
    [0x05] = { name = "LowLatency" },
    [0x06] = { name = "Compression" },
    [0x07] = { name = "Patch", z64 = decode_patch_ext },
    [0x08] = { name = "RegionName", zbuf = function(...) return decode_string_zbuf_ext(..., pf.ext_region_name) end },
}
local extspec_open = {
    [0x01] = { name = "QoS" },
    [0x02] = { name = "Shm" },
    [0x03] = { name = "Auth" },
    [0x04] = { name = function(enc) return enc == 0 and "MultiLinkAck" or "MultiLinkSyn" end },
    [0x05] = { name = "LowLatency" },
    [0x06] = { name = "Compression" },
    [0x07] = { name = "RemoteBound", z64 = decode_remote_bound_ext },
}
local extspec_join = {
    [0x01] = { name = "QoS Sn Table" },
    [0x02] = { name = "Shm" },
    [0x07] = { name = "Patch", z64 = decode_patch_ext },
}
local extspec_frame = {
    [0x01] = { name = "QoS", z64 = decode_transport_qos },
}
local extspec_fragment = {
    [0x01] = { name = "QoS", z64 = decode_transport_qos },
    [0x02] = { name = "First" },
    [0x03] = { name = "Drop" },
}
local extspec_net_common = {
    [0x01] = { name = "QoS", z64 = decode_network_qos },
    [0x02] = { name = "Timestamp", zbuf = decode_timestamp_zbuf_ext },
    [0x03] = { name = "NodeId", z64 = decode_node_id_ext },
}
local extspec_net_qos_tstamp = {
    [0x01] = { name = "QoS", z64 = decode_network_qos },
    [0x02] = { name = "Timestamp", zbuf = decode_timestamp_zbuf_ext },
}
local extspec_request = {
    [0x01] = { name = "QoS", z64 = decode_network_qos },
    [0x02] = { name = "Timestamp", zbuf = decode_timestamp_zbuf_ext },
    [0x03] = { name = "NodeId", z64 = decode_node_id_ext },
    [0x04] = { name = "Target", z64 = decode_request_target_ext },
    [0x05] = { name = "Budget", z64 = decode_request_budget_ext },
    [0x06] = { name = "Timeout", z64 = decode_request_timeout_ext },
}
local extspec_response = {
    [0x01] = { name = "QoS", z64 = decode_network_qos },
    [0x02] = { name = "Timestamp", zbuf = decode_timestamp_zbuf_ext },
    [0x03] = { name = "ResponderId", zbuf = decode_responder_zbuf_ext },
}
local extspec_put = {
    [0x01] = { name = "SourceInfo", zbuf = decode_sourceinfo_zbuf_ext },
    [0x02] = { name = "Shm" },
    [0x03] = { name = "Attachment", zbuf = decode_attachment_zbuf_ext },
}
local extspec_del = {
    [0x01] = { name = "SourceInfo", zbuf = decode_sourceinfo_zbuf_ext },
    [0x02] = { name = "Attachment", zbuf = decode_attachment_zbuf_ext },
}
local extspec_query = {
    [0x01] = { name = "SourceInfo", zbuf = decode_sourceinfo_zbuf_ext },
    [0x03] = { name = "QueryBody", zbuf = decode_query_body_zbuf_ext },
    [0x04] = { name = "QueryBodyShm" },
    [0x05] = { name = "Attachment", zbuf = decode_attachment_zbuf_ext },
}
local extspec_err = {
    [0x01] = { name = "SourceInfo", zbuf = decode_sourceinfo_zbuf_ext },
    [0x02] = { name = "Shm" },
}
local extspec_decl_queryable = {
    [0x01] = { name = "QueryableInfo", z64 = decode_queryable_info_ext },
}
local extspec_decl_undeclare = {
    [0x0F] = { name = "WireExpr", zbuf = decode_wireexpr_zbuf_ext },
}

local function parse_init_exts(tvb, pinfo, tree, offset, seen_ids)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_init, seen_ids)
end

local function parse_open_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_open)
end

local function parse_join_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_join)
end

local function parse_frame_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_frame)
end

local function parse_fragment_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_fragment)
end

local function parse_push_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_net_common)
end

local function parse_declare_msg_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_net_common)
end

local function parse_interest_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_net_common)
end

local function parse_request_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_request)
end

local function parse_response_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_response)
end

local function parse_response_final_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_net_qos_tstamp)
end

local function parse_oam_net_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_net_qos_tstamp)
end

local function parse_put_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_put)
end

local function parse_del_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_del)
end

local function parse_query_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_query)
end

local function parse_err_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_err)
end

local function parse_decl_queryable_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_decl_queryable)
end

local function parse_decl_undeclare_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, extspec_decl_undeclare)
end

-- ──────────────────────────────────────────────────────────────
-- 4.5  Statistics accumulator (defined here so dissectors can call it)
-- ──────────────────────────────────────────────────────────────

local zenoh_stats = {
    transport     = {},   -- [name] = count
    network       = {},   -- [name] = count
    scouting      = {},   -- [name] = count
    bytes         = 0,
    sessions      = 0,
    resp_times_ms = {},   -- list of floats for min/avg/max
}

local function stat_count_transport(name)
    zenoh_stats.transport[name] = (zenoh_stats.transport[name] or 0) + 1
end
local function stat_count_network(name)
    zenoh_stats.network[name] = (zenoh_stats.network[name] or 0) + 1
end
local function stat_count_scouting(name)
    zenoh_stats.scouting[name] = (zenoh_stats.scouting[name] or 0) + 1
end
local function stat_record_resp_time(delta_ms)
    zenoh_stats.resp_times_ms[#zenoh_stats.resp_times_ms + 1] = delta_ms
end

-- ──────────────────────────────────────────────────────────────
-- 5.  Data sub-message parsers  (PUT / DEL / QUERY / REPLY / ERR)
-- ──────────────────────────────────────────────────────────────

local function dissect_put(tvb, pinfo, tree, offset, hdr)
    local flag_t = (hdr % 64 >= 32)  -- bit 5
    local flag_e = (hdr % 128 >= 64) -- bit 6
    local flag_z = (hdr >= 128)      -- bit 7

    if flag_t then offset = parse_timestamp(tvb, pinfo, tree, offset) end
    if flag_e then offset = parse_encoding(tvb, pinfo, tree, offset) end
    if flag_z then offset = parse_put_exts(tvb, pinfo, tree, offset) end

    -- Payload length (z32) – content NOT shown per design
    if offset < tvb:len() then
        local plen, pl = read_vle(tvb, offset)
        tree:add(pf.payload_len, tvb(offset, pl), plen)
        offset = offset + pl
        offset = add_omitted_payload(tree, tvb, offset, plen)
    end
    return offset
end

local function dissect_del(tvb, pinfo, tree, offset, hdr)
    local flag_t = (hdr % 64 >= 32)
    local flag_z = (hdr >= 128)

    if flag_t then offset = parse_timestamp(tvb, pinfo, tree, offset) end
    if flag_z then offset = parse_del_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_query(tvb, pinfo, tree, offset, hdr)
    local flag_c = (hdr % 64 >= 32)  -- bit 5 Consolidation
    local flag_p = (hdr % 128 >= 64) -- bit 6 Parameters
    local flag_z = (hdr >= 128)      -- bit 7

    if flag_c then
        tree:add(pf.consolidation, tvb(offset, 1))
        offset = offset + 1
    end
    if flag_p then
        local ps, new_off = read_z16_string(tvb, offset)
        tree:add(pf.query_params, tvb(offset, new_off - offset), ps)
        offset = new_off
    end
    if flag_z then offset = parse_query_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_reply(tvb, pinfo, tree, offset, hdr)
    local flag_c = (hdr % 64 >= 32)
    local flag_z = (hdr >= 128)

    if flag_c then
        tree:add(pf.consolidation, tvb(offset, 1))
        offset = offset + 1
    end
    if flag_z then offset = parse_network_exts(tvb, pinfo, tree, offset) end

    -- ReplyBody = PUT or DEL
    if offset < tvb:len() then
        local body_hdr   = safe_byte(tvb, offset)
        local body_id    = body_hdr % 32
        local body_name  = lookup(vs_data_id, body_id)
        local body_start = offset
        local body_tree  = tree:add(zenoh_proto, tvb(offset, 0),
            string.format("Reply Body: %s", body_name))
        body_tree:add(pf.header, tvb(offset, 1))
        body_tree:add(pf.data_msg_id, tvb(offset, 1), body_id)
        offset = offset + 1
        if body_id == 0x01 then
            offset = dissect_put(tvb, pinfo, body_tree, offset, body_hdr)
        elseif body_id == 0x02 then
            offset = dissect_del(tvb, pinfo, body_tree, offset, body_hdr)
        end
        body_tree:set_len(offset - body_start)
    end
    return offset
end

local function dissect_err(tvb, pinfo, tree, offset, hdr)
    local flag_e = (hdr % 128 >= 64)
    local flag_z = (hdr >= 128)

    if flag_e then offset = parse_encoding(tvb, pinfo, tree, offset) end
    if flag_z then offset = parse_err_exts(tvb, pinfo, tree, offset) end

    if offset < tvb:len() then
        local plen, pl = read_vle(tvb, offset)
        tree:add(pf.payload_len, tvb(offset, pl), plen)
        offset = offset + pl
        offset = add_omitted_payload(tree, tvb, offset, plen)
    end
    return offset
end

-- ──────────────────────────────────────────────────────────────
-- 6.  Declaration sub-message parsers
-- ──────────────────────────────────────────────────────────────

local function parse_wire_expr_from_hdr(tvb, pinfo, tree, offset, hdr)
    local n_flag = (hdr % 64 >= 32)  -- bit 5
    local m_flag = (hdr % 128 >= 64) -- bit 6
    return parse_wire_expr(tvb, pinfo, tree, offset, n_flag, m_flag)
end

local function dissect_declaration(tvb, pinfo, tree, offset)
    if offset >= tvb:len() then return offset end

    local hdr     = safe_byte(tvb, offset)
    local decl_id = hdr % 32 -- bits 4:0
    local flag_z  = (hdr >= 128)
    local name    = lookup(vs_decl_id, decl_id)
    local d_start = offset
    local info    = name

    local d_tree  = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Declaration: %s", name))
    d_tree:add(pf.header, tvb(offset, 1))
    d_tree:add(pf.decl_id, tvb(offset, 1), decl_id)
    d_tree:add(pf.flag_z, tvb(offset, 1))
    offset = offset + 1

    -- ── D_KEYEXPR (0x00) ─────────────────────────────────────
    if decl_id == 0x00 then
        local flag_n = (hdr % 64 >= 32) -- bit 5: named
        local eid_val, eid_len = read_vle(tvb, offset)
        d_tree:add(pf.expr_id, tvb(offset, eid_len), eid_val)
        offset = offset + eid_len

        -- Peek at the WireExpr to store the key expression in the lookup table.
        -- Only on first pass to avoid redundant work.
        if flag_n and not pinfo.visited then
            local scope_v, sl   = read_vle(tvb, offset)
            local decl_suffix, _ = read_z16_string(tvb, offset + sl)
            if #decl_suffix > 0 then
                local sk  = get_stream_key(pinfo)
                -- D_KEYEXPR carries declarations from the SENDER. Index the
                -- table by the sender's direction so the opposite peer's
                -- identically numbered ExprIds do not collide with these.
                local dir = get_sender_dir_key(pinfo)
                if not keyexpr_table[sk] then keyexpr_table[sk] = {} end
                if not keyexpr_table[sk][dir] then keyexpr_table[sk][dir] = {} end
                local dtbl = keyexpr_table[sk][dir]
                -- If scope_v == 0, decl_suffix is the full absolute key expression.
                -- If scope_v != 0, store the composed key by resolving the base
                -- against the SAME direction's table (the declarer references
                -- only its own previously declared ExprIds).
                if scope_v == 0 then
                    dtbl[eid_val] = decl_suffix
                else
                    local base = dtbl[scope_v]
                    if base then
                        dtbl[eid_val] = base .. decl_suffix
                    else
                        dtbl[eid_val] = decl_suffix
                    end
                end
            end
        end

        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, false)
        track_decl(pinfo, tvb, "ke", eid_val, false, d_tree)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
        local key_summary = summarize_keyexpr(resolved, suffix)
        if key_summary then
            info = string.format("%s %s", name, key_summary)
        else
            info = string.format("%s id=%d", name, eid_val)
        end

        -- ── U_KEYEXPR (0x01) ─────────────────────────────────────
    elseif decl_id == 0x01 then
        local eid_val, eid_len = read_vle(tvb, offset)
        d_tree:add(pf.expr_id, tvb(offset, eid_len), eid_val)
        offset = offset + eid_len
        track_decl(pinfo, tvb, "ke", eid_val, true, d_tree)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
        info = string.format("%s id=%d", name, eid_val)

        -- ── D_SUBSCRIBER (0x02) ──────────────────────────────────
    elseif decl_id == 0x02 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        track_decl(pinfo, tvb, "sub", entity_id, false, d_tree)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
        local key_summary = summarize_keyexpr(resolved, suffix)
        if key_summary then
            info = string.format("%s %s", name, key_summary)
        else
            info = string.format("%s entity=%d", name, entity_id)
        end

        -- ── U_SUBSCRIBER (0x03) ──────────────────────────────────
    elseif decl_id == 0x03 then
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        track_decl(pinfo, tvb, "sub", entity_id, true, d_tree)
        if flag_z then offset = parse_decl_undeclare_exts(tvb, pinfo, d_tree, offset) end
        info = string.format("%s entity=%d", name, entity_id)

        -- ── D_QUERYABLE (0x04) ───────────────────────────────────
    elseif decl_id == 0x04 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        track_decl(pinfo, tvb, "qbl", entity_id, false, d_tree)
        if flag_z then offset = parse_decl_queryable_exts(tvb, pinfo, d_tree, offset) end
        local key_summary = summarize_keyexpr(resolved, suffix)
        if key_summary then
            info = string.format("%s %s", name, key_summary)
        else
            info = string.format("%s entity=%d", name, entity_id)
        end

        -- ── U_QUERYABLE (0x05) ───────────────────────────────────
    elseif decl_id == 0x05 then
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        track_decl(pinfo, tvb, "qbl", entity_id, true, d_tree)
        if flag_z then offset = parse_decl_undeclare_exts(tvb, pinfo, d_tree, offset) end
        info = string.format("%s entity=%d", name, entity_id)

        -- ── D_TOKEN (0x06) ───────────────────────────────────────
    elseif decl_id == 0x06 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        track_decl(pinfo, tvb, "tok", entity_id, false, d_tree)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
        local key_summary = summarize_keyexpr(resolved, suffix)
        if key_summary then
            info = string.format("%s %s", name, key_summary)
        else
            info = string.format("%s entity=%d", name, entity_id)
        end

        -- ── U_TOKEN (0x07) ───────────────────────────────────────
    elseif decl_id == 0x07 then
        local entity_id, entity_len = read_vle(tvb, offset)
        d_tree:add(pf.entity_id, tvb(offset, entity_len), entity_id)
        offset = offset + entity_len
        track_decl(pinfo, tvb, "tok", entity_id, true, d_tree)
        if flag_z then offset = parse_decl_undeclare_exts(tvb, pinfo, d_tree, offset) end
        info = string.format("%s entity=%d", name, entity_id)

        -- ── D_FINAL (0x1A) ───────────────────────────────────────
    elseif decl_id == 0x1A then
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
    end

    d_tree:set_len(offset - d_start)
    return offset, info
end

-- Decode a LinkStateList from tvb[offset..body_end).
-- Wire format (from zenoh-rust linkstate codec):
--   VLE count
--   per entry: VLE options | VLE psid | VLE sn
--              | [u8 zid_len + bytes  if PID(0x01)]
--              | [u8 whatami          if WAI(0x02)]
--              | [VLE loc_count + (u8 str_len + bytes)* if LOC(0x04)]
--              | VLE links_count + VLE link_id*
--              | [u16le weight*       if WGT(0x08)]
local function parse_link_state_list(tvb, tree, offset, body_end)
    local count, clen = read_vle(tvb, offset)
    if offset + clen > body_end then return offset end
    tree:add(zenoh_proto, tvb(offset, clen),
        string.format("LinkStateList count: %d", count))
    offset = offset + clen

    for i = 1, count do
        if offset >= body_end then break end
        local ls_start = offset
        local ls_tree  = tree:add(zenoh_proto, tvb(offset, 0),
            string.format("LinkState [%d]", i - 1))

        local opts, olen = read_vle(tvb, offset)
        if offset + olen > body_end then ls_tree:set_len(1); break end
        offset = offset + olen

        -- Peek ahead to detect v3 locator-only LinkState format.
        -- In v3, a locator-only entry has no opts/psid/sn/ZenohId header; instead
        -- it encodes directly as: u8 locator_count | (u8 str_len + bytes)* | VLE links.
        -- When the v9 parser reads such an entry it interprets the locator_count as
        -- opts (with PID=1 set) and the first locator's length as psid, so the
        -- would-be ZenohId length (the first byte of the locator string) exceeds 16.
        -- Detect this and fall back to v3 locator-only parsing.
        local v3_locators = false
        if (opts % 2 == 1) and offset < body_end then
            -- Skip over psid and sn VLEs to reach the would-be zid_len byte.
            local peek = offset
            local _, plen2 = read_vle(tvb, peek); peek = peek + plen2
            local _, snlen2 = read_vle(tvb, peek); peek = peek + snlen2
            if peek < body_end then
                local would_be_zid_len = safe_byte(tvb, peek)
                if would_be_zid_len > 16 then
                    -- v3 locator-only: opts holds the locator count, offset
                    -- already points at the first locator's length byte.
                    v3_locators = true
                end
            end
        end

        if v3_locators then
            -- v3 locator-only LinkState: opts = locator count, no other header fields.
            local lcount = opts
            ls_tree:add(zenoh_proto, tvb(ls_start, olen),
                string.format("Locator count (v3): %d", lcount))
            for j = 1, lcount do
                if offset >= body_end then break end
                local slen      = safe_byte(tvb, offset)
                local loc_start = offset
                offset = offset + 1
                local avail = math.min(slen, body_end - offset)
                if avail > 0 then
                    ls_tree:add(pf.locator, tvb(loc_start, 1 + avail),
                        tvb(offset, avail):string())
                end
                offset = offset + slen
            end
        else
            -- Normal v9 LinkState: opts | psid | sn | [ZenohId] | [WhatAmI] | [Locators]
            ls_tree:add(zenoh_proto, tvb(ls_start, olen),
                string.format("Options: 0x%02x (PID=%d WAI=%d LOC=%d WGT=%d GWY=%d)",
                    opts,
                    opts % 2,
                    math.floor(opts / 2) % 2,
                    math.floor(opts / 4) % 2,
                    math.floor(opts / 8) % 2,
                    math.floor(opts / 16) % 2))

            local psid, plen = read_vle(tvb, offset)
            if offset + plen > body_end then ls_tree:set_len(offset - ls_start); break end
            ls_tree:add(zenoh_proto, tvb(offset, plen), string.format("PSID: %d", psid))
            offset = offset + plen

            local sn, snlen = read_vle(tvb, offset)
            if offset + snlen > body_end then ls_tree:set_len(offset - ls_start); break end
            ls_tree:add(zenoh_proto, tvb(offset, snlen), string.format("SN: %d", sn))
            offset = offset + snlen

            -- ZenohID: u8 length + bytes  (PID flag = bit 0)
            if (opts % 2 == 1) and offset < body_end then
                local zid_len   = safe_byte(tvb, offset)
                local zid_start = offset
                offset = offset + 1
                if offset + zid_len <= body_end then
                    ls_tree:add(pf.zid, tvb(zid_start, 1 + zid_len))
                    offset = offset + zid_len
                end
            end

            -- WhatAmI: u8  (WAI flag = bit 1)
            -- Wire value is the Rust enum repr: Router=1, Peer=2, Client=4.
            if (math.floor(opts / 2) % 2 == 1) and offset < body_end then
                local wai = safe_byte(tvb, offset)
                ls_tree:add(zenoh_proto, tvb(offset, 1),
                    string.format("WhatAmI: %s", lookup(vs_wai_bitmask, wai)))
                offset = offset + 1
            end

            -- Locators: VLE count + (u8 str_len + bytes)*  (LOC flag = bit 2)
            if (math.floor(opts / 4) % 2 == 1) and offset < body_end then
                local lcount, lclen = read_vle(tvb, offset)
                if offset + lclen <= body_end then
                    ls_tree:add(zenoh_proto, tvb(offset, lclen),
                        string.format("Locator count: %d", lcount))
                    offset = offset + lclen
                    for j = 1, lcount do
                        if offset >= body_end then break end
                        local slen      = safe_byte(tvb, offset)
                        local loc_start = offset
                        offset = offset + 1
                        local avail = math.min(slen, body_end - offset)
                        if avail > 0 then
                            ls_tree:add(pf.locator, tvb(loc_start, 1 + avail),
                                tvb(offset, avail):string())
                        end
                        offset = offset + slen
                    end
                end
            end
        end

        -- Links: VLE count + VLE link_id*  (present in both v3 and v9)
        local llinks, lllen = read_vle(tvb, offset)
        if offset + lllen <= body_end then
            ls_tree:add(zenoh_proto, tvb(offset, lllen),
                string.format("Links count: %d", llinks))
            offset = offset + lllen
            for k = 1, llinks do
                if offset >= body_end then break end
                local lid, lilen = read_vle(tvb, offset)
                ls_tree:add(zenoh_proto, tvb(offset, lilen),
                    string.format("Link: %d", lid))
                offset = offset + lilen
            end

            -- Weights: u16le per link  (WGT flag = bit 3, v9 only)
            if not v3_locators and (math.floor(opts / 8) % 2 == 1) then
                for k = 1, llinks do
                    if offset + 2 > body_end then break end
                    ls_tree:add(zenoh_proto, tvb(offset, 2),
                        string.format("Link weight: %d", tvb(offset, 2):le_uint()))
                    offset = offset + 2
                end
            end
        end

        ls_tree:set_len(offset - ls_start)
    end
    return offset
end

-- Parse an OAM body based on ENC bits (bits 6:5 of the OAM header).
-- ENC=0 (Unit): no body.  ENC=1 (Z64): VLE u64.
-- ENC=2 (ZBuf): VLE-len + bytes decoded as a LinkStateList.
local function parse_oam_body(tvb, tree, offset, hdr)
    -- ENC is in bit 6 (ZBuf) and bit 5 (Z64), but bit 5 doubles as the T flag in
    -- network OAM headers — check each bit independently so 0x7f is read as ZBuf.
    local enc_zbuf = (math.floor(hdr / 64) % 2 == 1)           -- bit 6
    local enc_z64  = (not enc_zbuf) and (math.floor(hdr / 32) % 2 == 1)  -- bit 5, bit 6 clear

    if enc_z64 then                         -- Z64: VLE u64 value
        local val, vlen = read_vle(tvb, offset)
        tree:add(zenoh_proto, tvb(offset, vlen),
            string.format("OAM Z64 Value: %d", val))
        offset = offset + vlen

    elseif enc_zbuf then                    -- ZBuf: LinkStateList
        local blen, bvlen = read_vle(tvb, offset)
        local body_start  = offset
        local body_end    = math.min(offset + bvlen + blen, tvb:len())
        local body_tree   = tree:add(zenoh_proto, tvb(body_start, body_end - body_start),
            string.format("OAM Body [%d bytes]", blen))
        offset = offset + bvlen

        if offset < body_end then
            offset = parse_link_state_list(tvb, body_tree, offset, body_end)
        end
        -- Always advance past the full OAM body regardless of decoding path
        offset = body_end
    end
    -- Unit (bits 6:5 = 00) and Reserved (bits 6:5 = 11): no body bytes
    return offset
end

-- ──────────────────────────────────────────────────────────────
-- 7.  Network message parsers
-- ──────────────────────────────────────────────────────────────

local function dissect_network_msg(tvb, pinfo, tree, offset)
    if offset >= tvb:len() then return offset end

    local hdr      = safe_byte(tvb, offset)
    local msg_id   = hdr % 32          -- bits 4:0
    local flag_fl1 = (hdr % 64 >= 32)  -- bit 5
    local flag_fl2 = (hdr % 128 >= 64) -- bit 6
    local flag_z   = (hdr >= 128)      -- bit 7
    local name     = lookup(vs_network_id, msg_id)
    if not pinfo.visited then stat_count_network(name) end
    local nm_start = offset

    local nm_tree  = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Network: %s", name))
    local hdr_tree = nm_tree:add(pf.header, tvb(offset, 1))
    hdr_tree:add(pf.flag_z, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl2, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl1, tvb(offset, 1))
    hdr_tree:add(pf.msg_id, tvb(offset, 1), msg_id)
    hdr_tree:add(pf.net_msg_id, tvb(offset, 1), msg_id) -- dedicated network-layer filter
    offset = offset + 1

    -- ── PUSH (0x1D) ──────────────────────────────────────────
    if msg_id == 0x1D then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_push_exts(tvb, pinfo, nm_tree, offset) end

        -- PushBody = PUT or DEL
        if offset < tvb:len() then
            local body_hdr  = safe_byte(tvb, offset)
            local body_id   = body_hdr % 32
            local body_name = lookup(vs_data_id, body_id)
            local pb_start  = offset
            local pb_tree   = nm_tree:add(zenoh_proto, tvb(offset, 0),
                string.format("Push Body: %s", body_name))
            pb_tree:add(pf.header, tvb(offset, 1))
            pb_tree:add(pf.data_msg_id, tvb(offset, 1), body_id)
            offset = offset + 1
            if body_id == 0x01 then
                offset = dissect_put(tvb, pinfo, pb_tree, offset, body_hdr)
            elseif body_id == 0x02 then
                offset = dissect_del(tvb, pinfo, pb_tree, offset, body_hdr)
            end
            pb_tree:set_len(offset - pb_start)
            append_info(pinfo, string.format("PUSH %s %s",
                summarize_keyexpr(resolved, suffix) or "<?>",
                body_name))
        end

        -- ── DECLARE (0x1E) ───────────────────────────────────────
    elseif msg_id == 0x1E then
        local flag_i = flag_fl1
        local interest_id = nil
        if flag_i then
            local interest_len
            interest_id, interest_len = read_vle(tvb, offset)
            nm_tree:add(pf.decl_interest_id, tvb(offset, interest_len), interest_id)
            offset = offset + interest_len
        end
        if flag_z then offset = parse_declare_msg_exts(tvb, pinfo, nm_tree, offset) end
        local decl_info
        offset, decl_info = dissect_declaration(tvb, pinfo, nm_tree, offset)
        if interest_id then
            append_info(pinfo, string.format("DECLARE iid=%d %s", interest_id, decl_info or ""))
        else
            append_info(pinfo, string.format("DECLARE %s", decl_info or ""))
        end

        -- ── REQUEST (0x1C) ───────────────────────────────────────
    elseif msg_id == 0x1C then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        local request_id, request_len = read_vle(tvb, offset)
        nm_tree:add(pf.request_id, tvb(offset, request_len), request_id)
        offset = offset + request_len
        do
            local sk = get_stream_key(pinfo)
            if not pinfo.visited then
                if not req_table[sk] then req_table[sk] = {} end
                req_table[sk][request_id] = { frame = pinfo.number, time_s = ts_secs(pinfo.abs_ts) }
            end
            -- Show correlation on re-dissection (back-annotated by RESPONSE handler)
            local rrc = pkt_req_resp_cache[pinfo.number]
            if rrc then
                local ri = nm_tree:add(pf.req_response_frame, tvb(0, 0), rrc.resp_frame)
                ri:set_generated(true)
                local ti = nm_tree:add(pf.req_response_time_ms, tvb(0, 0), rrc.delta_ms)
                ti:set_generated(true)
            end
        end
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_request_exts(tvb, pinfo, nm_tree, offset) end
        -- RequestBody = QUERY
        if offset < tvb:len() then
            local body_hdr = safe_byte(tvb, offset)
            local body_id  = body_hdr % 32
            if body_id == 0x03 then
                local qb_start = offset
                local qb_tree = nm_tree:add(zenoh_proto, tvb(offset, 0), "Request Body: QUERY")
                qb_tree:add(pf.header, tvb(offset, 1))
                qb_tree:add(pf.data_msg_id, tvb(offset, 1), body_id)
                offset = offset + 1
                offset = dissect_query(tvb, pinfo, qb_tree, offset, body_hdr)
                qb_tree:set_len(offset - qb_start)
                append_info(pinfo, string.format("REQUEST rid=%d %s",
                    request_id,
                    summarize_keyexpr(resolved, suffix) or "<?>"))
            end
        end

        -- ── RESPONSE (0x1B) ──────────────────────────────────────
    elseif msg_id == 0x1B then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        local request_id, request_len = read_vle(tvb, offset)
        nm_tree:add(pf.request_id, tvb(offset, request_len), request_id)
        offset = offset + request_len
        do
            local sk = get_stream_key(pinfo)
            if not pinfo.visited then
                local req = req_table[sk] and req_table[sk][request_id]
                if req then
                    local delta_ms = (ts_secs(pinfo.abs_ts) - req.time_s) * 1000
                    if not pkt_resp_req_cache[pinfo.number] then pkt_resp_req_cache[pinfo.number] = {} end
                    pkt_resp_req_cache[pinfo.number][request_id] = { req_frame = req.frame, delta_ms = delta_ms }
                    -- Back-annotate the REQUEST packet
                    if not pkt_req_resp_cache[req.frame] then
                        pkt_req_resp_cache[req.frame] = { resp_frame = pinfo.number, delta_ms = delta_ms }
                    end
                    stat_record_resp_time(delta_ms)
                end
            end
            local rrc = pkt_resp_req_cache[pinfo.number]
            local rr  = rrc and rrc[request_id]
            if rr then
                local ri = nm_tree:add(pf.resp_request_frame, tvb(0, 0), rr.req_frame)
                ri:set_generated(true)
                local ti = nm_tree:add(pf.req_response_time_ms, tvb(0, 0), rr.delta_ms)
                ti:set_generated(true)
            end
        end
        local resolved, suffix
        offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_response_exts(tvb, pinfo, nm_tree, offset) end
        -- ResponseBody = REPLY or ERR
        if offset < tvb:len() then
            local body_hdr = safe_byte(tvb, offset)
            local body_id  = body_hdr % 32
            local rb_name  = lookup(vs_data_id, body_id)
            local rb_start = offset
            local rb_tree  = nm_tree:add(zenoh_proto, tvb(offset, 0),
                string.format("Response Body: %s", rb_name))
            rb_tree:add(pf.header, tvb(offset, 1))
            rb_tree:add(pf.data_msg_id, tvb(offset, 1), body_id)
            offset = offset + 1
            if body_id == 0x04 then
                offset = dissect_reply(tvb, pinfo, rb_tree, offset, body_hdr)
            elseif body_id == 0x05 then
                offset = dissect_err(tvb, pinfo, rb_tree, offset, body_hdr)
            end
            rb_tree:set_len(offset - rb_start)
            append_info(pinfo, string.format("RESPONSE rid=%d %s %s",
                request_id,
                summarize_keyexpr(resolved, suffix) or "<?>",
                rb_name))
        end

        -- ── RESPONSE_FINAL (0x1A) ────────────────────────────────
    elseif msg_id == 0x1A then
        local request_id, request_len = read_vle(tvb, offset)
        nm_tree:add(pf.request_id, tvb(offset, request_len), request_id)
        offset = offset + request_len
        do
            local sk = get_stream_key(pinfo)
            if not pinfo.visited then
                local req = req_table[sk] and req_table[sk][request_id]
                if req then
                    local delta_ms = (ts_secs(pinfo.abs_ts) - req.time_s) * 1000
                    if not pkt_resp_req_cache[pinfo.number] then pkt_resp_req_cache[pinfo.number] = {} end
                    pkt_resp_req_cache[pinfo.number][request_id] = { req_frame = req.frame, delta_ms = delta_ms }
                    -- Back-annotate the REQUEST packet
                    if not pkt_req_resp_cache[req.frame] then
                        pkt_req_resp_cache[req.frame] = { resp_frame = pinfo.number, delta_ms = delta_ms }
                    end
                    stat_record_resp_time(delta_ms)
                end
            end
            local rrc = pkt_resp_req_cache[pinfo.number]
            local rr  = rrc and rrc[request_id]
            if rr then
                local ri = nm_tree:add(pf.resp_request_frame, tvb(0, 0), rr.req_frame)
                ri:set_generated(true)
                local ti = nm_tree:add(pf.req_response_time_ms, tvb(0, 0), rr.delta_ms)
                ti:set_generated(true)
            end
        end
        if flag_z then offset = parse_response_final_exts(tvb, pinfo, nm_tree, offset) end
        append_info(pinfo, string.format("RESPONSE_FINAL rid=%d", request_id))

        -- ── INTEREST (0x19) ──────────────────────────────────────
    elseif msg_id == 0x19 then
        local mod = math.floor(hdr / 32) % 4 -- bits 6:5: 0=Final 1=Current 2=Future 3=CurrentFuture
        local interest_id, interest_len = read_vle(tvb, offset)
        nm_tree:add(pf.interest_id, tvb(offset, interest_len), interest_id)
        offset = offset + interest_len
        nm_tree:add(pf.interest_mod, tvb(nm_start, 1), mod) -- mode lives in the header byte
        local interest_key = nil
        if mod ~= 0 then -- not Final → options byte + optional WireExpr
            if offset < tvb:len() then
                nm_tree:add(pf.interest_options, tvb(offset, 1))
                local opts   = safe_byte(tvb, offset)
                nm_tree:add(pf.interest_opt_keyexprs, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_subscribers, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_queryables, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_tokens, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_restricted, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_named, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_mapping, tvb(offset, 1))
                nm_tree:add(pf.interest_opt_aggregate, tvb(offset, 1))
                offset       = offset + 1
                local flag_r = (math.floor(opts / 16) % 2 == 1) -- bit 4: R (Restricted, WireExpr present)
                local flag_n = (math.floor(opts / 32) % 2 == 1) -- bit 5: N (Named, key suffix present)
                local flag_m = (math.floor(opts / 64) % 2 == 1) -- bit 6: M (Mapping)
                if flag_r then
                    local resolved, suffix
                    offset, resolved, _, suffix = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
                    interest_key = summarize_keyexpr(resolved, suffix)
                end
            end
        end
        if flag_z then offset = parse_interest_exts(tvb, pinfo, nm_tree, offset) end
        if interest_key then
            append_info(pinfo, string.format("INTEREST id=%d %s %s",
                interest_id,
                lookup(vs_interest_mode, mod),
                interest_key))
        else
            append_info(pinfo, string.format("INTEREST id=%d %s",
                interest_id,
                lookup(vs_interest_mode, mod)))
        end

        -- ── OAM (0x1F) ───────────────────────────────────────────
    elseif msg_id == 0x1F then
        local oam_id, oam_len = read_vle(tvb, offset)
        nm_tree:add(pf.oam_id, tvb(offset, oam_len), oam_id)
        offset = offset + oam_len
        if flag_z then offset = parse_oam_net_exts(tvb, pinfo, nm_tree, offset) end
        offset = parse_oam_body(tvb, nm_tree, offset, hdr)
        append_info(pinfo, string.format("OAM id=%d", oam_id))

    else
        -- Unknown network message: consume extensions to maintain stream alignment.
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end
        if zenoh_proto.prefs.expert_unknown then
            nm_tree:add_expert_info(PI_UNDECODED, PI_WARN,
                string.format("Unknown network message ID 0x%02x", msg_id))
        end
    end

    nm_tree:set_len(offset - nm_start)
    return offset
end

-- ──────────────────────────────────────────────────────────────
-- 8.  Transport message parsers
-- ──────────────────────────────────────────────────────────────

local function dissect_init(tvb, pinfo, tree, offset, hdr)
    local flag_a = (hdr % 64 >= 32)  -- bit 5: Ack → InitAck
    local flag_s = (hdr % 128 >= 64) -- bit 6: Size fields present
    local flag_z = (hdr >= 128)      -- bit 7

    tree:append_text(flag_a and " (InitAck)" or " (InitSyn)")
    append_info(pinfo, flag_a and "INIT Ack" or "INIT Syn")

    -- version
    if offset >= tvb:len() then return offset end
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1
    do
        local sk = get_stream_key(pinfo)
        if not session_ver[sk] then
            session_ver[sk] = safe_byte(tvb, offset - 1)
        end
    end

    -- packed byte: zid_len(7:4) | X | X | WhatAmI(1:0)
    if offset >= tvb:len() then return offset end
    local packed      = safe_byte(tvb, offset)
    local zid_len_enc = math.floor(packed / 16) % 16 -- bits 7:4
    local zid_bytes   = 1 + zid_len_enc
    local wai         = packed % 4                   -- bits 1:0
    local packed_tree = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Packed: zid_len=%d WhatAmI=%s", zid_bytes, lookup(vs_wai, wai)))
    packed_tree:add(pf.wai, tvb(offset, 1), wai)
    offset = offset + 1

    -- ZID
    if offset + zid_bytes <= tvb:len() then
        tree:add(pf.zid, tvb(offset, zid_bytes))
        record_peer_zid(pinfo, tvb, offset, zid_bytes)
        offset = offset + zid_bytes
    end

    -- resolution + batch size (if S=1)
    if flag_s and offset < tvb:len() then
        local res = safe_byte(tvb, offset)
        local res_tree = tree:add(pf.resolution, tvb(offset, 1))
        res_tree:add(pf.res_fsn, tvb(offset, 1), res % 4)
        res_tree:add(pf.res_rid, tvb(offset, 1), math.floor(res / 4) % 4)
        offset = offset + 1
        if offset + 2 <= tvb:len() then
            tree:add_le(pf.batch_size, tvb(offset, 2))
            offset = offset + 2
        end
    end

    -- cookie (InitAck only): <u8;z16>
    if flag_a and offset < tvb:len() then
        local clen, ll = read_vle(tvb, offset)
        local cookie_range = tvb(offset, ll + math.min(clen, tvb:len() - offset - ll))
        local ck_tree = tree:add(pf.cookie, tvb(offset + ll,
            math.min(clen, tvb:len() - offset - ll)))
        ck_tree:prepend_text(string.format("Cookie [%d bytes]: ", clen))
        offset = offset + ll + clen
    end

    if flag_z then
        local seen = {}
        offset = parse_init_exts(tvb, pinfo, tree, offset, seen)
        -- Record that compression was agreed when both sides echoed extension 0x6.
        -- The acceptor only echoes it in InitAck (flag_a = true) when both sides agree.
        if flag_a and seen[0x6] and not pinfo.visited then
            stream_compress_init[get_stream_key(pinfo)] = true
        end
    end
    return offset
end

local function dissect_open(tvb, pinfo, tree, offset, hdr)
    local flag_a = (hdr % 64 >= 32)  -- bit 5: Ack → OpenAck
    local flag_t = (hdr % 128 >= 64) -- bit 6: T=1 seconds, T=0 milliseconds
    local flag_z = (hdr >= 128)

    tree:append_text(flag_a and " (OpenAck)" or " (OpenSyn)")
    append_info(pinfo, flag_a and "OPEN Ack" or "OPEN Syn")

    -- lease (VLE)
    local lease_val, lease_len = read_vle(tvb, offset)
    tree:add(pf.lease, tvb(offset, lease_len), lease_val):append_text(
        flag_t and " s" or " ms")
    offset = offset + lease_len

    -- initial_sn (VLE)
    offset = add_vle(tree, pf.initial_sn, tvb, offset)

    -- cookie: present in OpenSyn (A=0); <u8;z16>
    if not flag_a and offset < tvb:len() then
        local clen, ll = read_vle(tvb, offset)
        local ck_tree = tree:add(pf.cookie,
            tvb(offset + ll, math.min(clen, tvb:len() - offset - ll)))
        ck_tree:prepend_text(string.format("Cookie [%d bytes]: ", clen))
        offset = offset + ll + clen
    end

    if flag_z then offset = parse_open_exts(tvb, pinfo, tree, offset) end
    -- OpenAck completes the Zenoh handshake. From the very next batch onwards,
    -- every batch on this stream will be prefixed by a 1-byte BatchHeader.
    if flag_a and not pinfo.visited then
        local sk = get_stream_key(pinfo)
        if stream_compress_init[sk] and not stream_compress_from[sk] then
            stream_compress_from[sk] = pinfo.number
        end
    end
    return offset
end

local function dissect_close(tvb, pinfo, tree, offset, hdr)
    local flag_s = (hdr % 64 >= 32) -- bit 5: S=1 session, S=0 link
    local flag_z = (hdr >= 128)

    tree:append_text(flag_s and " (Session)" or " (Link)")
    if offset < tvb:len() then
        local reason = safe_byte(tvb, offset)
        tree:add(pf.close_reason, tvb(offset, 1))
        append_info(pinfo, string.format("CLOSE %s %s",
            flag_s and "session" or "link",
            lookup(vs_close_reason, reason)))
        offset = offset + 1
    end
    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_keep_alive(tvb, pinfo, tree, offset, hdr)
    local flag_z = (hdr >= 128)
    append_info(pinfo, "KEEP_ALIVE")
    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_join(tvb, pinfo, tree, offset, hdr)
    local flag_t = (hdr % 64 >= 32)  -- bit 5: time unit
    local flag_s = (hdr % 128 >= 64) -- bit 6: size fields
    local flag_z = (hdr >= 128)
    append_info(pinfo, "JOIN")

    -- version
    if offset >= tvb:len() then return offset end
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1
    do
        local sk = get_stream_key(pinfo)
        if not session_ver[sk] then
            session_ver[sk] = safe_byte(tvb, offset - 1)
        end
    end

    -- packed byte
    if offset >= tvb:len() then return offset end
    local packed      = safe_byte(tvb, offset)
    local zid_len_enc = math.floor(packed / 16) % 16
    local zid_bytes   = 1 + zid_len_enc
    local wai         = packed % 4
    local p_tree      = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Packed: zid_len=%d WhatAmI=%s", zid_bytes, lookup(vs_wai, wai)))
    p_tree:add(pf.wai, tvb(offset, 1), wai)
    offset = offset + 1

    -- ZID
    if offset + zid_bytes <= tvb:len() then
        tree:add(pf.zid, tvb(offset, zid_bytes))
        record_peer_zid(pinfo, tvb, offset, zid_bytes)
        offset = offset + zid_bytes
    end

    -- resolution + batch size (if S=1)
    if flag_s and offset < tvb:len() then
        local res = safe_byte(tvb, offset)
        local res_tree = tree:add(pf.resolution, tvb(offset, 1))
        res_tree:add(pf.res_fsn, tvb(offset, 1), res % 4)
        res_tree:add(pf.res_rid, tvb(offset, 1), math.floor(res / 4) % 4)
        offset = offset + 1
        if offset + 2 <= tvb:len() then
            tree:add_le(pf.batch_size, tvb(offset, 2))
            offset = offset + 2
        end
    end

    -- lease
    local lease_val, lease_len = read_vle(tvb, offset)
    tree:add(pf.join_lease, tvb(offset, lease_len), lease_val):append_text(
        flag_t and " s" or " ms")
    offset = offset + lease_len

    -- next_sn_re, next_sn_be
    offset = add_vle(tree, pf.next_sn_re, tvb, offset)
    offset = add_vle(tree, pf.next_sn_be, tvb, offset)

    if flag_z then offset = parse_join_exts(tvb, pinfo, tree, offset) end
    return offset
end

-- ──────────────────────────────────────────────────────────────
-- 9.  Transport-layer batch dissector
-- ──────────────────────────────────────────────────────────────

-- Dissect one transport message starting at offset.
-- batch_end marks the last byte (exclusive) of this batch.
-- Returns new offset (or batch_end on FRAME/FRAGMENT which consume the rest).
local function dissect_transport_msg(tvb, pinfo, batch_tree, offset, batch_end)
    if offset >= batch_end then return offset end

    local hdr      = safe_byte(tvb, offset)
    local msg_id   = hdr % 32
    local flag_z   = (hdr >= 128)
    local name     = lookup(vs_transport_id, msg_id)
    if not pinfo.visited then stat_count_transport(name) end
    local tm_start = offset

    local tm_tree  = batch_tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Transport: %s", name))
    local hdr_tree = tm_tree:add(pf.header, tvb(offset, 1))
    hdr_tree:add(pf.flag_z, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl2, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl1, tvb(offset, 1))
    hdr_tree:add(pf.msg_id, tvb(offset, 1), msg_id)
    offset = offset + 1

    if msg_id == 0x01 then
        offset = dissect_init(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x02 then
        offset = dissect_open(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x03 then
        offset = dissect_close(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x04 then
        offset = dissect_keep_alive(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x05 then          -- FRAME
        local flag_r = (hdr % 64 >= 32) -- bit 5: Reliable
        tm_tree:add(pf.frame_reliable, tvb(offset - 1, 1))
        tm_tree:append_text(flag_r and " (Reliable)" or " (BestEffort)")

        -- sequence number (VLE)
        local sn_val, sn_len = read_vle(tvb, offset)
        tm_tree:add(pf.seq_num, tvb(offset, sn_len), sn_val)
        offset = offset + sn_len

        -- SN gap detection: check for non-sequential SN on this channel
        do
            local sk = get_stream_key(pinfo)
            local ch = flag_r and "R" or "B"
            if not pinfo.visited then
                if not sn_state[sk] then sn_state[sk] = {} end
                local last = sn_state[sk][ch]
                if last ~= nil and sn_val ~= last + 1 then
                    pkt_sn_cache[pinfo.number] = { expected = last + 1, got = sn_val, channel = ch }
                end
                sn_state[sk][ch] = sn_val
            end
            local sc = pkt_sn_cache[pinfo.number]
            if sc then
                tm_tree:add_expert_info(PI_SEQUENCE, PI_WARN,
                    string.format("SN gap on %s channel: expected %d got %d (%d missing)",
                        sc.channel == "R" and "reliable" or "best-effort",
                        sc.expected, sc.got, sc.got - sc.expected))
                local gi = tm_tree:add(pf.sn_gap,      tvb(offset - sn_len, sn_len), true)
                gi:set_generated(true)
                local si = tm_tree:add(pf.sn_gap_size, tvb(offset - sn_len, sn_len), sc.got - sc.expected)
                si:set_generated(true)
            end
        end

        -- optional extensions
        if flag_z then offset = parse_frame_exts(tvb, pinfo, tm_tree, offset) end

        -- network messages fill the rest of the batch
        local net_tree = tm_tree:add(zenoh_proto, tvb(offset, 0), "Network Messages")
        local net_start = offset
        while offset < batch_end and offset < tvb:len() do
            offset = dissect_network_msg(tvb, pinfo, net_tree, offset)
        end
        net_tree:set_len(offset - net_start)
        offset = batch_end     -- consume remaining
    elseif msg_id == 0x06 then -- FRAGMENT
        local flag_r = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        tm_tree:add(pf.frame_reliable, tvb(offset - 1, 1))
        tm_tree:add(pf.fragment_more, tvb(offset - 1, 1))
        tm_tree:append_text(string.format(" (Reliable=%s More=%s)",
            flag_r and "Y" or "N", flag_m and "Y" or "N"))

        local sn_val, sn_len = read_vle(tvb, offset)
        tm_tree:add(pf.seq_num, tvb(offset, sn_len), sn_val)
        offset = offset + sn_len

        if flag_z then offset = parse_fragment_exts(tvb, pinfo, tm_tree, offset) end

        local frag_len = batch_end - offset
        if frag_len > 0 and offset < tvb:len() then
            tm_tree:add(zenoh_proto, tvb(offset, frag_len),
                string.format("Fragment Data [%d bytes]", frag_len))
        end

        -- Track fragment chains across packets so Wireshark's tree can show
        -- which sequence numbers belong together and whether the chain is complete.
        local sk      = get_stream_key(pinfo)
        local ch_key  = flag_r and "R" or "B"
        if not pinfo.visited then
            if not frag_table[sk] then frag_table[sk] = {} end
            local ch = frag_table[sk][ch_key]
            if not ch or not flag_m then
                -- flag_m == true: more fragments follow (this is either the first or a middle fragment)
                -- flag_m == false: this is the last fragment of a chain
                -- When we see a fragment that IS the last (flag_m=false) or if no chain exists yet,
                -- start/close the chain entry.
                frag_table[sk][ch_key] = {
                    first_sn    = ch and ch.first_sn or sn_val,
                    last_sn     = sn_val,
                    count       = ch and (ch.count + 1) or 1,
                    total_bytes = ch and (ch.total_bytes + frag_len) or frag_len,
                    complete    = not flag_m,
                }
            else
                ch.last_sn     = sn_val
                ch.count       = ch.count + 1
                ch.total_bytes = ch.total_bytes + frag_len
                ch.complete    = not flag_m
            end
            packet_frag_cache[pinfo.number] = {
                first_sn    = frag_table[sk][ch_key].first_sn,
                last_sn     = sn_val,
                count       = frag_table[sk][ch_key].count,
                total_bytes = frag_table[sk][ch_key].total_bytes,
                complete    = not flag_m,
            }
            -- Reset chain on last fragment so the next FRAGMENT starts fresh.
            if not flag_m then frag_table[sk][ch_key] = nil end
        end
        local fc = packet_frag_cache[pinfo.number]
        if fc then
            local status = fc.complete and "complete" or "incomplete"
            tm_tree:add(zenoh_proto, tvb(tm_start, 0),
                string.format("Fragment chain: SN %d–%d  %d fragment(s)  %d bytes  [%s]",
                    fc.first_sn, fc.last_sn, fc.count, fc.total_bytes, status))
            append_info(pinfo, string.format("FRAGMENT sn=%d [%s/%d]",
                sn_val, status, fc.count))
        else
            append_info(pinfo, string.format("FRAGMENT sn=%d", sn_val))
        end

        offset = batch_end
    elseif msg_id == 0x07 then -- JOIN
        offset = dissect_join(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x00 then -- OAM (transport)
        offset = add_vle(tm_tree, pf.oam_id, tvb, offset)
        if flag_z then offset = parse_frame_exts(tvb, pinfo, tm_tree, offset) end
        offset = parse_oam_body(tvb, tm_tree, offset, hdr)
    else
        -- Unknown transport message ID: consume extensions so the byte stream
        -- stays aligned for the next message.
        if flag_z then offset = parse_transport_exts(tvb, pinfo, tm_tree, offset) end
        if zenoh_proto.prefs.expert_unknown then
            tm_tree:add_expert_info(PI_UNDECODED, PI_WARN,
                string.format("Unknown transport message ID 0x%02x", msg_id))
        end
    end

    tm_tree:set_len(offset - tm_start)
    return offset
end

-- Dissect a Zenoh frame (batch contents, without the 2-byte length prefix).
local function dissect_zenoh_frame(tvb, pinfo, root_tree, batch_start, batch_end)
    local btree = root_tree:add(zenoh_proto, tvb(batch_start, batch_end - batch_start),
        string.format("Zenoh Frame [%d bytes]", batch_end - batch_start))

    local offset = batch_start
    while offset < batch_end and offset < tvb:len() do
        local prev = offset
        local ok, err = pcall(function()
            offset = dissect_transport_msg(tvb, pinfo, btree, offset, batch_end)
        end)
        if not ok then
            btree:add_expert_info(PI_MALFORMED, PI_ERROR,
                string.format("Dissect error at offset %d: %s", offset, tostring(err)))
            break
        end
        if offset == prev then break end -- guard against infinite loop
    end
end

-- ──────────────────────────────────────────────────────────────
-- 10.  Scouting message parsers
-- ──────────────────────────────────────────────────────────────

local function dissect_scout(tvb, pinfo, tree, offset, hdr)
    local flag_z = (hdr >= 128)

    -- version
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1

    -- packed byte: zid_len(7:4) | I(3) | WhatAmIMatcher(2:0)
    if offset >= tvb:len() then return offset end
    local packed      = safe_byte(tvb, offset)
    local zid_len_enc = math.floor(packed / 16) % 16
    local zid_bytes   = 1 + zid_len_enc
    local has_id      = (packed % 16 >= 8) -- bit 3
    local wai_mask    = packed % 8         -- bits 2:0
    local pk_tree     = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Packed: I=%s WhatAmIMatcher=0x%x", has_id and "Y" or "N", wai_mask))
    pk_tree:add(pf.scout_id_flag, tvb(offset, 1))
    pk_tree:add(pf.scout_wai_matcher, tvb(offset, 1), wai_mask)
    offset = offset + 1

    if has_id and offset + zid_bytes <= tvb:len() then
        tree:add(pf.zid, tvb(offset, zid_bytes))
        record_peer_zid(pinfo, tvb, offset, zid_bytes)
        offset = offset + zid_bytes
    end

    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_hello(tvb, pinfo, tree, offset, hdr)
    local flag_l = (hdr % 64 >= 32) -- bit 5: locator list present
    local flag_z = (hdr >= 128)

    -- version
    if offset >= tvb:len() then return offset end
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1

    -- packed byte: zid_len(7:4) | X | X | WhatAmI(1:0)
    if offset >= tvb:len() then return offset end
    local packed      = safe_byte(tvb, offset)
    local zid_len_enc = math.floor(packed / 16) % 16
    local zid_bytes   = 1 + zid_len_enc
    local wai         = packed % 4
    local pk_tree     = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Packed: zid_len=%d WhatAmI=%s", zid_bytes, lookup(vs_wai, wai)))
    pk_tree:add(pf.wai, tvb(offset, 1), wai)
    offset = offset + 1

    if offset + zid_bytes <= tvb:len() then
        tree:add(pf.zid, tvb(offset, zid_bytes))
        record_peer_zid(pinfo, tvb, offset, zid_bytes)
        offset = offset + zid_bytes
    end

    -- locators (if L=1): z8 count, then count × <utf8;z8>
    if flag_l and offset < tvb:len() then
        local lcount, ll = read_vle(tvb, offset)
        tree:add(pf.locator_count, tvb(offset, ll), lcount)
        offset = offset + ll
        for i = 1, lcount do
            if offset >= tvb:len() then break end
            local loc_len, loc_ll = read_vle(tvb, offset)
            offset = offset + loc_ll
            local loc_actual = math.min(loc_len, tvb:len() - offset)
            if loc_actual > 0 then
                local loc_str = tvb(offset, loc_actual):string()
                tree:add(pf.locator, tvb(offset, loc_actual), loc_str)
            end
            offset = offset + loc_len
        end
    end

    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

-- ──────────────────────────────────────────────────────────────
-- 11.  Main dissector entry points
-- ──────────────────────────────────────────────────────────────

-- TCP dissector with frame-length desegmentation
function zenoh_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol:set("Zenoh")
    pinfo.cols.info:set("")

    local total = tvb:len()
    if total == 0 then return 0 end

    -- Determine transport type from registered port table
    local is_tcp      = (pinfo.port_type == 2) -- Port.TCP = 2
    local is_scouting = (pinfo.dst_port == 7446 or pinfo.src_port == 7446)

    -- Build the Zenoh subtree.  Note: Wireshark's Lua dispatch adds a sibling
    -- "Wireshark Lua fake item" node before calling this function; that item is
    -- hidden automatically in Wireshark >= 4.2 but visible in older builds.
    -- There is no Lua API to suppress it — it is a framework artifact.
    local root = tree:add(zenoh_proto, tvb(), "Zenoh Protocol")

    -- Inject session ZID virtual fields onto every packet of the stream.
    -- ZIDs are recorded when INIT/JOIN/SCOUT/HELLO messages are parsed.
    do
        local sk     = get_stream_key(pinfo)
        local zentry = stream_zid_table[sk]
        if zentry then
            if not pinfo.visited then
                packet_zid_cache[pinfo.number] = { src = zentry.src, dst = zentry.dst }
            end
            local zc = packet_zid_cache[pinfo.number]
            if zc then
                if zc.src then root:add(pf.session_src_zid, zc.src:tvb("src_zid")(0)) end
                if zc.dst then root:add(pf.session_dst_zid, zc.dst:tvb("dst_zid")(0)) end
            end
        end
    end

    -- Session summary: show protocol version + declaration state
    do
        local sk    = get_stream_key(pinfo)
        local ver   = session_ver[sk]
        local dtbl  = decl_state[sk]
        local ke_count  = 0
        local sub_count = 0
        local qbl_count = 0
        local tok_count = 0
        if dtbl then
            for _ in pairs(dtbl["ke"]  or {}) do ke_count  = ke_count  + 1 end
            for _ in pairs(dtbl["sub"] or {}) do sub_count = sub_count + 1 end
            for _ in pairs(dtbl["qbl"] or {}) do qbl_count = qbl_count + 1 end
            for _ in pairs(dtbl["tok"] or {}) do tok_count = tok_count + 1 end
        end
        if ver or ke_count > 0 or sub_count > 0 or qbl_count > 0 or tok_count > 0 then
            local ss = root:add(zenoh_proto, tvb(), "Session State")
            ss:set_generated(true)
            if ver then
                local vi = ss:add(pf.session_version, tvb(0,0), ver)
                vi:set_generated(true)
            end
            local ki = ss:add(pf.session_ke_count,  tvb(0,0), ke_count)
            ki:set_generated(true)
            local si = ss:add(pf.session_sub_count, tvb(0,0), sub_count)
            si:set_generated(true)
            local qi = ss:add(pf.session_qbl_count, tvb(0,0), qbl_count)
            qi:set_generated(true)
            local ti = ss:add(pf.session_tok_count, tvb(0,0), tok_count)
            ti:set_generated(true)
        end
    end

    -- ── Scouting (UDP 7446) ──────────────────────────────────
    if is_scouting and not is_tcp then
        local offset = 0
        while offset < total do
            if offset >= total then break end
            local hdr    = safe_byte(tvb, offset)
            local msg_id = hdr % 32
            local name   = lookup(vs_scout_id, msg_id)
            if not pinfo.visited then stat_count_scouting(name) end
            append_info(pinfo, name)

            local sm_start = offset
            local sm_tree  = root:add(zenoh_proto, tvb(offset, 1),
                string.format("Scouting: %s", name))
            sm_tree:add(pf.header, tvb(offset, 1))
            sm_tree:add(pf.flag_z, tvb(offset, 1))
            sm_tree:add(pf.msg_id, tvb(offset, 1), msg_id)
            offset = offset + 1

            local ok, err = pcall(function()
                if msg_id == 0x01 then
                    offset = dissect_scout(tvb, pinfo, sm_tree, offset, hdr)
                elseif msg_id == 0x02 then
                    offset = dissect_hello(tvb, pinfo, sm_tree, offset, hdr)
                else
                    offset = total -- skip unknown
                end
            end)
            if not ok then
                sm_tree:add_expert_info(PI_MALFORMED, PI_ERROR, tostring(err))
                break
            end
            sm_tree:set_len(offset - sm_start)
        end
        if tostring(pinfo.cols.info) == "" then
            pinfo.cols.info:set("Zenoh")
        end
        return total
    end

    -- ── TCP  (with 2-byte LE frame-length prefix) ────────────
    if is_tcp then
        local offset        = 0
        local sk            = get_stream_key(pinfo)
        local compress_from = stream_compress_from[sk]  -- nil or OpenAck frame number

        while offset < total do
            if total - offset < 2 then
                -- Not enough bytes for the length prefix; request more
                pinfo.desegment_offset = offset
                pinfo.desegment_len    = DESEGMENT_ONE_MORE_SEGMENT
                return
            end

            local frame_len = tvb(offset, 2):le_uint()

            if total - offset < 2 + frame_len then
                -- Incomplete frame; request reassembly
                pinfo.desegment_offset = offset
                pinfo.desegment_len    = (2 + frame_len) - (total - offset)
                return
            end

            root:add_le(pf.frame_len, tvb(offset, 2))
            local batch_start = offset + 2
            local batch_end   = batch_start + frame_len

            -- Post-handshake batches on compressed streams start with a 1-byte BatchHeader.
            -- The header is present in every frame whose number is STRICTLY after the
            -- OpenAck (INIT/OPEN themselves are never compressed).
            if compress_from and pinfo.number > compress_from and frame_len >= 1 then
                local bh_byte  = tvb(batch_start, 1):uint()
                local is_compr = (bh_byte % 2 == 1)   -- bit 0

                root:add(pf.batch_header,     tvb(batch_start, 1))
                root:add(pf.batch_compressed, tvb(batch_start, 1))
                batch_start = batch_start + 1  -- consume the BatchHeader byte

                if is_compr then
                    -- LZ4-block-compressed batch: decompress, then dissect the result.
                    local comp_len = batch_end - batch_start
                    if comp_len > 0 then
                        local ok, result = pcall(lz4_block_decompress,
                                                 tvb(batch_start, comp_len):bytes())
                        if ok and result then
                            local decomp_tvb = result:tvb("Zenoh [decompressed]")
                            local decomp_len = decomp_tvb:len()
                            local btree = root:add(zenoh_proto, tvb(batch_start, comp_len),
                                string.format("Zenoh Frame [%d bytes, decompressed from %d]",
                                    decomp_len, comp_len))
                            local di = btree:add(zenoh_proto, tvb(batch_start, 0),
                                string.format("Decompressed: %d bytes", decomp_len))
                            di:set_generated(true)
                            -- Parse all transport messages from the decompressed Tvb.
                            local doff = 0
                            while doff < decomp_len do
                                local prev = doff
                                local ok2, err2 = pcall(function()
                                    doff = dissect_transport_msg(
                                        decomp_tvb, pinfo, btree, doff, decomp_len)
                                end)
                                if not ok2 then
                                    btree:add_expert_info(PI_MALFORMED, PI_ERROR,
                                        string.format("Decompress/dissect error at %d: %s",
                                            doff, tostring(err2)))
                                    break
                                end
                                if doff == prev then break end
                            end
                        else
                            root:add_expert_info(PI_MALFORMED, PI_ERROR,
                                "LZ4 decompression failed: " .. tostring(result))
                        end
                    end
                else
                    -- Compression enabled but this batch was sent uncompressed
                    -- (LZ4 did not reduce its size — normal for small or random data).
                    dissect_zenoh_frame(tvb, pinfo, root, batch_start, batch_end)
                end
            else
                -- Pre-handshake or non-compressed stream: no BatchHeader.
                dissect_zenoh_frame(tvb, pinfo, root, batch_start, batch_end)
            end

            offset = batch_end
        end
        if tostring(pinfo.cols.info) == "" then
            pinfo.cols.info:set("Zenoh")
        end
        return total
    end

    -- ── UDP (datagram = one batch, no length prefix) ─────────
    dissect_zenoh_frame(tvb, pinfo, root, 0, total)
    if tostring(pinfo.cols.info) == "" then
        pinfo.cols.info:set("Zenoh")
    end
    return total
end

-- ──────────────────────────────────────────────────────────────
-- 12.  Port registration
-- ──────────────────────────────────────────────────────────────

-- TCP 7447: unicast transport
DissectorTable.get("tcp.port"):add(7447, zenoh_proto)

-- UDP 7447: unicast transport (JOIN etc.)
DissectorTable.get("udp.port"):add(7447, zenoh_proto)

-- UDP 7446: scouting (SCOUT / HELLO)
DissectorTable.get("udp.port"):add(7446, zenoh_proto)

-- Also handle the IANA-registered port 7447 on any variant
-- Some implementations use different scouting ports
DissectorTable.get("udp.port"):add(7448, zenoh_proto)

-- ──────────────────────────────────────────────────────────────
-- 13.  Heuristic dissection (non-standard ports)
-- ──────────────────────────────────────────────────────────────
-- These heuristics fire only on ports not already claimed by section 12.
-- Once a packet is accepted, pinfo.conversation = zenoh_proto locks all
-- subsequent packets on that TCP connection / UDP 4-tuple to this dissector.

local function zenoh_heuristic_tcp(tvb, pinfo, tree)
    -- Minimum: 2-byte LE frame-length prefix + 1-byte message header
    if tvb:len() < 3 then return false end
    local frame_len = tvb(0, 2):le_uint()
    -- frame_len == 0 is meaningless; > 65535 is implausible
    if frame_len == 0 or frame_len > 65535 then return false end
    local hdr    = tvb(2, 1):uint()
    local msg_id = hdr % 32   -- bits 4:0
    -- Valid transport IDs: 0x01–0x07 (exclude 0x00 / OAM — too ambiguous)
    if msg_id == 0 or msg_id > 0x07 then return false end
    -- For INIT and JOIN the first data byte is the protocol version.
    -- Reject version==0 (null byte common in non-Zenoh protocols) but accept
    -- any non-zero value so the heuristic works across Zenoh releases.
    if (msg_id == 0x01 or msg_id == 0x07) and tvb:len() >= 4 then
        if tvb(3, 1):uint() == 0 then return false end
    end
    zenoh_proto.dissector(tvb, pinfo, tree)
    pinfo.conversation = zenoh_proto
    return true
end

local function zenoh_heuristic_udp(tvb, pinfo, tree)
    -- Minimum: 1-byte message header
    if tvb:len() < 1 then return false end
    local hdr    = tvb(0, 1):uint()
    local msg_id = hdr % 32
    -- Valid transport IDs: 0x01–0x07
    if msg_id == 0 or msg_id > 0x07 then return false end
    -- For INIT and JOIN the first data byte is the protocol version.
    -- Reject version==0 but accept any other value.
    if (msg_id == 0x01 or msg_id == 0x07) and tvb:len() >= 2 then
        if tvb(1, 1):uint() == 0 then return false end
    end
    zenoh_proto.dissector(tvb, pinfo, tree)
    pinfo.conversation = zenoh_proto
    return true
end

zenoh_proto:register_heuristic("tcp", zenoh_heuristic_tcp)
zenoh_proto:register_heuristic("udp", zenoh_heuristic_udp)

-- ──────────────────────────────────────────────────────────────
-- 14.  Statistics tap
-- ──────────────────────────────────────────────────────────────
-- Accumulate per-message-type counters updated during dissection (first pass only).
-- View via tshark: -z zenoh,stat
-- Wireshark: Statistics → Zenoh Protocol Statistics (when available)

local tap_zenoh = nil
do
    local ok, _ = pcall(function() tap_zenoh = Listener.new("zenoh") end)
    if not ok then tap_zenoh = nil end
end

if tap_zenoh then
    tap_zenoh.packet = function(pinfo, tvb)
        if not pinfo.visited then
            zenoh_stats.bytes = zenoh_stats.bytes + tvb:len()
        end
    end

    tap_zenoh.draw = function()
        local function sorted_pairs(t)
            local keys = {}
            for k in pairs(t) do keys[#keys+1] = k end
            table.sort(keys)
            local i = 0
            return function()
                i = i + 1
                return keys[i], t[keys[i]]
            end
        end

        print(string.rep("=", 60))
        print("Zenoh Protocol Statistics")
        print(string.rep("=", 60))
        print(string.format("  Total bytes decoded : %d", zenoh_stats.bytes))
        print("")

        print("  Transport messages:")
        for name, cnt in sorted_pairs(zenoh_stats.transport) do
            print(string.format("    %-20s : %d", name, cnt))
        end

        print("")
        print("  Network messages:")
        for name, cnt in sorted_pairs(zenoh_stats.network) do
            print(string.format("    %-20s : %d", name, cnt))
        end

        if next(zenoh_stats.scouting) then
            print("")
            print("  Scouting messages:")
            for name, cnt in sorted_pairs(zenoh_stats.scouting) do
                print(string.format("    %-20s : %d", name, cnt))
            end
        end

        local rt = zenoh_stats.resp_times_ms
        if #rt > 0 then
            local sum, mn, mx = 0, rt[1], rt[1]
            for _, v in ipairs(rt) do
                sum = sum + v
                if v < mn then mn = v end
                if v > mx then mx = v end
            end
            print("")
            print("  Query response times:")
            print(string.format("    Samples : %d", #rt))
            print(string.format("    Min     : %.3f ms", mn))
            print(string.format("    Avg     : %.3f ms", sum / #rt))
            print(string.format("    Max     : %.3f ms", mx))
        end

        print(string.rep("=", 60))
    end

    tap_zenoh.reset = function()
        zenoh_stats.transport     = {}
        zenoh_stats.network       = {}
        zenoh_stats.scouting      = {}
        zenoh_stats.bytes         = 0
        zenoh_stats.sessions      = 0
        zenoh_stats.resp_times_ms = {}
    end
end
