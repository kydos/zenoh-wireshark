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
local zenoh_proto      = Proto("Zenoh", "Zenoh Protocol")

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
-- Extension ID names (transport-layer context)
local vs_transport_ext_id = {
    [0x01] = "QoS",
    [0x02] = "Auth",
    [0x03] = "MultiLink",
    [0x04] = "LowLatency",
    [0x05] = "Compression",
    [0x07] = "Patch",
    [0x09] = "RegionName",
}
-- Extension ID names (network-layer context)
local vs_network_ext_id = {
    [0x01] = "QoS",
    [0x02] = "Timestamp",
    [0x03] = "NodeId",
    [0x04] = "RecvTimestamp",
    [0x05] = "Attachment",
}

-- ──────────────────────────────────────────────────────────────
-- 3.  ProtoField definitions
-- ──────────────────────────────────────────────────────────────

local pf               = {}
local F                = zenoh_proto.fields -- must assign all pf.*  values here

-- framing
pf.frame_len           = ProtoField.uint16("zenoh.frame_len", "Frame Length", base.DEC)

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

-- DECLARE / declarations
pf.decl_interest_id    = ProtoField.uint32("zenoh.decl_interest_id", "Interest ID", base.DEC)

-- Extensions
pf.extension           = ProtoField.uint8("zenoh.extension", "Extension Header", base.HEX)
pf.ext_id              = ProtoField.uint8("zenoh.ext_id", "  ID", base.HEX)
pf.ext_m               = ProtoField.bool("zenoh.ext_m", "  Mandatory", 8, { "Yes", "No" }, 0x10)
pf.ext_enc             = ProtoField.uint8("zenoh.ext_enc", "  Encoding", base.DEC, vs_enc_type)
pf.ext_z64_val         = ProtoField.uint32("zenoh.ext_z64", "  Value (Z64)", base.DEC)
pf.ext_zbuf            = ProtoField.bytes("zenoh.ext_zbuf", "  Body (ZBuf)")
pf.ext_qos_prio        = ProtoField.uint8("zenoh.ext_qos_prio", "  QoS Priority", base.DEC, vs_priority)

-- SCOUT / HELLO
pf.scout_wai_matcher   = ProtoField.uint8("zenoh.scout_matcher", "WhatAmI Matcher", base.HEX)
pf.locator_count       = ProtoField.uint32("zenoh.locator_count", "Locator Count", base.DEC)
pf.locator             = ProtoField.string("zenoh.locator", "Locator")
pf.scout_id_flag       = ProtoField.bool("zenoh.scout_id_flag", "I (ZID Present)", 8, { "Yes", "No" }, 0x08)

-- OAM
pf.oam_id              = ProtoField.uint32("zenoh.oam_id", "OAM ID", base.DEC)

-- INTEREST
pf.interest_options    = ProtoField.uint8("zenoh.interest_options", "Options Byte", base.HEX)
pf.interest_mod        = ProtoField.uint8("zenoh.interest_mod", "Mode", base.HEX)

-- Assign all fields to the protocol
for _, v in pairs(pf) do
    F[#F + 1] = v
end

-- ──────────────────────────────────────────────────────────────
-- 4.  Helper functions
-- ──────────────────────────────────────────────────────────────

-- Read a variable-length encoded (LEB128) integer from tvb at offset.
-- Returns (value, bytes_consumed).  Handles up to 9 bytes (z64).
local function read_vle(tvb, offset)
    local value    = 0
    local consumed = 0
    local shift    = 0
    local maxoff   = math.min(offset + 9, tvb:len())
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
local function add_vle(tree, field, tvb, offset)
    local val, len = read_vle(tvb, offset)
    tree:add(field, tvb(offset, len), val)
    return offset + len
end

-- Parse a UTF-8 string: z16-length prefix + bytes.
-- Returns (string_value, new_offset).
local function read_z16_string(tvb, offset)
    if offset >= tvb:len() then return "", offset end
    local slen, llen = read_vle(tvb, offset) -- z16 length
    offset = offset + llen
    if slen == 0 then return "", offset end
    local s = tvb(offset, math.min(slen, tvb:len() - offset)):string()
    return s, offset + slen
end

-- Parse a z8-prefixed byte string. Returns (bytes_tvbrange_or_nil, new_offset).
local function read_z8_bytes(tvb, offset)
    if offset >= tvb:len() then return nil, offset end
    local blen, llen = read_vle(tvb, offset) -- z8 length
    offset = offset + llen
    if blen == 0 then return nil, offset end
    local r = tvb(offset, math.min(blen, tvb:len() - offset))
    return r, offset + blen
end

-- Parse WireExpr into a tree node. Returns new offset.
-- n_flag: suffix present; m_flag: mapping (1=sender, 0=receiver)
local function parse_wire_expr(tvb, pinfo, tree, offset, n_flag, m_flag)
    local we_tree = tree:add(zenoh_proto, tvb(offset, 0), "WireExpr")
    local scope_val, slen = read_vle(tvb, offset)
    we_tree:add(pf.key_scope, tvb(offset, slen), scope_val)
    offset = offset + slen

    if n_flag then
        local suffix, new_off = read_z16_string(tvb, offset)
        if #suffix > 0 then
            we_tree:add(pf.key_suffix, tvb(offset, new_off - offset), suffix)
        end
        offset = new_off
    end

    local mapping = m_flag and "sender" or "receiver"
    we_tree:append_text(string.format(" scope=%d mapping=%s", scope_val, mapping))
    return offset
end

-- Parse a Timestamp field (HLC NTP64 + ZenohID). Returns new_offset.
local function parse_timestamp(tvb, pinfo, tree, offset)
    if offset + 8 > tvb:len() then return offset end
    local ts_start = offset
    local ts_tree = tree:add(zenoh_proto, tvb(offset, 0), "Timestamp")

    -- NTP64 (z64 VLE)
    local ntp_val, ntp_len = read_vle(tvb, offset)
    ts_tree:add(pf.ts_ntp, tvb(offset, ntp_len))
    offset = offset + ntp_len

    -- ZID: z8-prefixed
    local zid_len, ll = read_vle(tvb, offset)
    offset = offset + ll
    if zid_len > 0 and offset + zid_len <= tvb:len() then
        ts_tree:add(pf.ts_zid, tvb(offset, zid_len))
        offset = offset + zid_len
    end

    ts_tree:set_len(offset - ts_start)
    return offset
end

-- Parse an Encoding field (z32 packed: bits[0]=schema_present, bits[31:1]=id).
-- Returns new_offset.
local function parse_encoding(tvb, pinfo, tree, offset)
    if offset >= tvb:len() then return offset end
    local raw_val, vlen = read_vle(tvb, offset)
    local enc_id        = math.floor(raw_val / 2) -- raw_val >> 1
    local has_schema    = (raw_val % 2) == 1      -- raw_val & 1
    local enc_tree      = tree:add(pf.encoding_id, tvb(offset, vlen), enc_id)
    enc_tree:append_text(string.format(" (0x%x)", enc_id))
    offset = offset + vlen

    if has_schema then
        local schema_bytes, new_off = read_z8_bytes(tvb, offset)
        if schema_bytes then
            enc_tree:add(pf.encoding_schema, schema_bytes)
        end
        offset = new_off
    end
    return offset
end

-- Parse extension chain.  Returns new_offset.
-- ext_names (optional): lookup table [id] = "Name" for this message's extensions.
local function parse_extensions(tvb, pinfo, tree, offset, ext_names)
    while offset < tvb:len() do
        local hdr       = safe_byte(tvb, offset)
        local ext_z     = (hdr >= 0x80)            -- bit 7
        local ext_enc   = math.floor(hdr / 32) % 4 -- bits 6:5
        local ext_m     = (hdr % 32 >= 16)         -- bit 4
        local ext_id    = hdr % 16                 -- bits 3:0

        local ext_start = offset
        local ext_tree  = tree:add(pf.extension, tvb(offset, 1))
        local name      = ext_names and ext_names[ext_id]
        local name_str  = name and string.format(" (%s)", name) or ""
        ext_tree:append_text(string.format(" ID=0x%x%s %s %s",
            ext_id, name_str,
            ext_enc == 0 and "Unit" or
            ext_enc == 1 and "Z64" or
            ext_enc == 2 and "ZBuf" or "Rsv",
            ext_m and "(Mandatory)" or ""))
        ext_tree:add(pf.ext_id, tvb(offset, 1), ext_id)
        ext_tree:add(pf.ext_m, tvb(offset, 1))
        offset = offset + 1

        if ext_enc == 1 then
            -- Z64: VLE value
            local val, vlen = read_vle(tvb, offset)
            -- Decode QoS extension (ID=0x01) priority
            if ext_id == 0x01 then
                local prio = val % 8 -- bits 2:0
                ext_tree:add(pf.ext_qos_prio, tvb(offset, vlen), prio)
                ext_tree:append_text(string.format(" priority=%s", lookup(vs_priority, prio)))
            else
                ext_tree:add(pf.ext_z64_val, tvb(offset, vlen), val)
            end
            offset = offset + vlen
        elseif ext_enc == 2 then
            -- ZBuf: VLE length + bytes
            local blen, llen = read_vle(tvb, offset)
            offset = offset + llen
            local actual = math.min(blen, tvb:len() - offset)
            if actual > 0 then
                ext_tree:add(pf.ext_zbuf, tvb(offset, actual))
            end
            offset = offset + blen
        end
        -- ext_enc == 0: Unit → no body bytes

        ext_tree:set_len(offset - ext_start)

        if not ext_z then break end -- no more extensions
    end
    return offset
end

-- Convenience shims: forward the right name table for the protocol layer.
local function parse_transport_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, vs_transport_ext_id)
end
local function parse_network_exts(tvb, pinfo, tree, offset)
    return parse_extensions(tvb, pinfo, tree, offset, vs_network_ext_id)
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
    if flag_z then offset = parse_network_exts(tvb, pinfo, tree, offset) end

    -- Payload length (z32) – content NOT shown per design
    if offset < tvb:len() then
        local plen, pl = read_vle(tvb, offset)
        tree:add(pf.payload_len, tvb(offset, pl), plen)
        offset = offset + pl
        local actual = math.min(plen, tvb:len() - offset)
        if actual > 0 then
            tree:add(pf.payload_data, tvb(offset, actual)):append_text(
                string.format(" [%d byte(s) not shown]", plen))
        end
        offset = offset + plen
    end
    return offset
end

local function dissect_del(tvb, pinfo, tree, offset, hdr)
    local flag_t = (hdr % 64 >= 32)
    local flag_z = (hdr >= 128)

    if flag_t then offset = parse_timestamp(tvb, pinfo, tree, offset) end
    if flag_z then offset = parse_network_exts(tvb, pinfo, tree, offset) end
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
    if flag_z then offset = parse_network_exts(tvb, pinfo, tree, offset) end
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
    if flag_z then offset = parse_network_exts(tvb, pinfo, tree, offset) end

    if offset < tvb:len() then
        local plen, pl = read_vle(tvb, offset)
        tree:add(pf.payload_len, tvb(offset, pl), plen)
        offset = offset + pl
        local actual = math.min(plen, tvb:len() - offset)
        if actual > 0 then
            tree:add(pf.payload_data, tvb(offset, actual)):append_text(
                string.format(" [%d byte(s) not shown]", plen))
        end
        offset = offset + plen
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

    local d_tree  = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Declaration: %s", name))
    d_tree:add(pf.header, tvb(offset, 1))
    d_tree:add(pf.flag_z, tvb(offset, 1))
    offset = offset + 1

    -- ── D_KEYEXPR (0x00) ─────────────────────────────────────
    if decl_id == 0x00 then
        local flag_n = (hdr % 64 >= 32) -- bit 5: named
        local eid_val, eid_len = read_vle(tvb, offset)
        d_tree:add(pf.expr_id, tvb(offset, eid_len), eid_val)
        offset = offset + eid_len
        offset = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, false)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── U_KEYEXPR (0x01) ─────────────────────────────────────
    elseif decl_id == 0x01 then
        local eid_val, eid_len = read_vle(tvb, offset)
        d_tree:add(pf.expr_id, tvb(offset, eid_len), eid_val)
        offset = offset + eid_len
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── D_SUBSCRIBER (0x02) ──────────────────────────────────
    elseif decl_id == 0x02 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        offset = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── U_SUBSCRIBER (0x03) ──────────────────────────────────
    elseif decl_id == 0x03 then
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── D_QUERYABLE (0x04) ───────────────────────────────────
    elseif decl_id == 0x04 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        offset = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── U_QUERYABLE (0x05) ───────────────────────────────────
    elseif decl_id == 0x05 then
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── D_TOKEN (0x06) ───────────────────────────────────────
    elseif decl_id == 0x06 then
        local flag_n = (hdr % 64 >= 32)
        local flag_m = (hdr % 128 >= 64)
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        offset = parse_wire_expr(tvb, pinfo, d_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── U_TOKEN (0x07) ───────────────────────────────────────
    elseif decl_id == 0x07 then
        offset = add_vle(d_tree, pf.entity_id, tvb, offset)
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end

        -- ── D_FINAL (0x1A) ───────────────────────────────────────
    elseif decl_id == 0x1A then
        if flag_z then offset = parse_network_exts(tvb, pinfo, d_tree, offset) end
    end

    d_tree:set_len(offset - d_start)
    return offset
end

-- Parse an OAM body based on ENC bits (bits 6:5 of the OAM header).
-- ENC=0 (Unit): no body.  ENC=1 (Z64): VLE u64.
-- ENC=2 (ZBuf): VLE-len + bytes decoded as a sequence of Zenoh z-strings.
local function parse_oam_body(tvb, tree, offset, hdr)
    local enc = math.floor(hdr / 32) % 4   -- bits 6:5
    if enc == 1 then                        -- Z64: VLE u64 value
        local val, vlen = read_vle(tvb, offset)
        tree:add(zenoh_proto, tvb(offset, vlen),
            string.format("OAM Z64 Value: %d", val))
        offset = offset + vlen

    elseif enc == 2 then                    -- ZBuf: sequence of Zenoh strings
        local blen, bvlen = read_vle(tvb, offset)
        local body_start  = offset
        local body_end    = math.min(offset + bvlen + blen, tvb:len())
        local body_tree   = tree:add(zenoh_proto, tvb(body_start, body_end - body_start),
            string.format("OAM Body [%d bytes]", blen))
        offset = offset + bvlen

        -- Try decoding as: VLE count  +  count × (VLE length + UTF-8 string)
        local decoded = false
        if offset < body_end then
            local count, clen = read_vle(tvb, offset)
            if count >= 0 and count <= 256 and offset + clen <= body_end then
                body_tree:add(zenoh_proto, tvb(offset, clen),
                    string.format("Count: %d", count))
                offset = offset + clen
                decoded = true
                for i = 1, count do
                    if offset >= body_end then break end
                    local slen, svlen = read_vle(tvb, offset)
                    local item_start  = offset
                    offset = offset + svlen
                    local avail = math.min(slen, body_end - offset)
                    if avail > 0 then
                        local s = tvb(offset, avail):string()
                        body_tree:add(pf.locator, tvb(item_start, svlen + avail), s)
                    end
                    offset = offset + slen
                end
            end
        end
        if not decoded then
            -- Fall back: show raw bytes
            local raw = body_end - offset
            if raw > 0 then
                body_tree:add(zenoh_proto, tvb(offset, raw),
                    string.format("OAM Payload [%d bytes, raw]", raw))
            end
            offset = body_end
        end
    end
    -- enc == 0 (Unit) and enc == 3 (Reserved): no body bytes
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
    local nm_start = offset

    local nm_tree  = tree:add(zenoh_proto, tvb(offset, 1),
        string.format("Network: %s", name))
    local hdr_tree = nm_tree:add(pf.header, tvb(offset, 1))
    hdr_tree:add(pf.flag_z, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl2, tvb(offset, 1))
    hdr_tree:add(pf.flag_fl1, tvb(offset, 1))
    hdr_tree:add(pf.msg_id, tvb(offset, 1), msg_id)
    offset = offset + 1

    -- ── PUSH (0x1D) ──────────────────────────────────────────
    if msg_id == 0x1D then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        offset = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end

        -- PushBody = PUT or DEL
        if offset < tvb:len() then
            local body_hdr  = safe_byte(tvb, offset)
            local body_id   = body_hdr % 32
            local body_name = lookup(vs_data_id, body_id)
            local pb_start  = offset
            local pb_tree   = nm_tree:add(zenoh_proto, tvb(offset, 0),
                string.format("Push Body: %s", body_name))
            pb_tree:add(pf.header, tvb(offset, 1))
            offset = offset + 1
            if body_id == 0x01 then
                offset = dissect_put(tvb, pinfo, pb_tree, offset, body_hdr)
            elseif body_id == 0x02 then
                offset = dissect_del(tvb, pinfo, pb_tree, offset, body_hdr)
            end
            pb_tree:set_len(offset - pb_start)
        end

        -- ── DECLARE (0x1E) ───────────────────────────────────────
    elseif msg_id == 0x1E then
        local flag_i = flag_fl1
        if flag_i then
            offset = add_vle(nm_tree, pf.decl_interest_id, tvb, offset)
        end
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end
        offset = dissect_declaration(tvb, pinfo, nm_tree, offset)

        -- ── REQUEST (0x1C) ───────────────────────────────────────
    elseif msg_id == 0x1C then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        offset = add_vle(nm_tree, pf.request_id, tvb, offset)
        offset = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end
        -- RequestBody = QUERY
        if offset < tvb:len() then
            local body_hdr = safe_byte(tvb, offset)
            local body_id  = body_hdr % 32
            if body_id == 0x03 then
                local qb_start = offset
                local qb_tree = nm_tree:add(zenoh_proto, tvb(offset, 0), "Request Body: QUERY")
                qb_tree:add(pf.header, tvb(offset, 1))
                offset = offset + 1
                offset = dissect_query(tvb, pinfo, qb_tree, offset, body_hdr)
                qb_tree:set_len(offset - qb_start)
            end
        end

        -- ── RESPONSE (0x1B) ──────────────────────────────────────
    elseif msg_id == 0x1B then
        local flag_n = flag_fl1
        local flag_m = flag_fl2
        offset = add_vle(nm_tree, pf.request_id, tvb, offset)
        offset = parse_wire_expr(tvb, pinfo, nm_tree, offset, flag_n, flag_m)
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end
        -- ResponseBody = REPLY or ERR
        if offset < tvb:len() then
            local body_hdr = safe_byte(tvb, offset)
            local body_id  = body_hdr % 32
            local rb_name  = lookup(vs_data_id, body_id)
            local rb_start = offset
            local rb_tree  = nm_tree:add(zenoh_proto, tvb(offset, 0),
                string.format("Response Body: %s", rb_name))
            rb_tree:add(pf.header, tvb(offset, 1))
            offset = offset + 1
            if body_id == 0x04 then
                offset = dissect_reply(tvb, pinfo, rb_tree, offset, body_hdr)
            elseif body_id == 0x05 then
                offset = dissect_err(tvb, pinfo, rb_tree, offset, body_hdr)
            end
            rb_tree:set_len(offset - rb_start)
        end

        -- ── RESPONSE_FINAL (0x1A) ────────────────────────────────
    elseif msg_id == 0x1A then
        offset = add_vle(nm_tree, pf.request_id, tvb, offset)
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end

        -- ── INTEREST (0x19) ──────────────────────────────────────
    elseif msg_id == 0x19 then
        local mod = math.floor(hdr / 32) % 4 -- bits 6:5 of raw header
        offset = add_vle(nm_tree, pf.interest_id, tvb, offset)
        nm_tree:add(pf.interest_mod, tvb(offset - 1, 1), mod)
        if mod ~= 0 then -- not Final → has options + WireExpr
            if offset < tvb:len() then
                nm_tree:add(pf.interest_options, tvb(offset, 1))
                local opts    = safe_byte(tvb, offset)
                offset        = offset + 1
                local has_key = ((opts % 4) >= 2) -- bit R (bit 1)
                local has_n   = (opts >= 128)     -- bit A (bit 7)... simplified
                if has_key then
                    offset = parse_wire_expr(tvb, pinfo, nm_tree, offset,
                        (opts % 8 >= 4), false) -- N flag = bit 2
                end
            end
        end
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end

        -- ── OAM (0x1F) ───────────────────────────────────────────
    elseif msg_id == 0x1F then
        offset = add_vle(nm_tree, pf.oam_id, tvb, offset)
        if flag_z then offset = parse_network_exts(tvb, pinfo, nm_tree, offset) end
        offset = parse_oam_body(tvb, nm_tree, offset, hdr)
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

    -- version
    if offset >= tvb:len() then return offset end
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1

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

    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_open(tvb, pinfo, tree, offset, hdr)
    local flag_a = (hdr % 64 >= 32)  -- bit 5: Ack → OpenAck
    local flag_t = (hdr % 128 >= 64) -- bit 6: T=1 seconds, T=0 milliseconds
    local flag_z = (hdr >= 128)

    tree:append_text(flag_a and " (OpenAck)" or " (OpenSyn)")

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

    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_close(tvb, pinfo, tree, offset, hdr)
    local flag_s = (hdr % 64 >= 32) -- bit 5: S=1 session, S=0 link
    local flag_z = (hdr >= 128)

    tree:append_text(flag_s and " (Session)" or " (Link)")
    if offset < tvb:len() then
        tree:add(pf.close_reason, tvb(offset, 1))
        offset = offset + 1
    end
    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_keep_alive(tvb, pinfo, tree, offset, hdr)
    local flag_z = (hdr >= 128)
    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
    return offset
end

local function dissect_join(tvb, pinfo, tree, offset, hdr)
    local flag_t = (hdr % 64 >= 32)  -- bit 5: time unit
    local flag_s = (hdr % 128 >= 64) -- bit 6: size fields
    local flag_z = (hdr >= 128)

    -- version
    if offset >= tvb:len() then return offset end
    tree:add(pf.version, tvb(offset, 1))
    offset = offset + 1

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

    if flag_z then offset = parse_transport_exts(tvb, pinfo, tree, offset) end
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

        -- optional extensions
        if flag_z then offset = parse_transport_exts(tvb, pinfo, tm_tree, offset) end

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

        if flag_z then offset = parse_transport_exts(tvb, pinfo, tm_tree, offset) end

        local frag_len = batch_end - offset
        if frag_len > 0 and offset < tvb:len() then
            tm_tree:add(zenoh_proto, tvb(offset, frag_len),
                string.format("Fragment Data [%d bytes]", frag_len))
        end
        offset = batch_end
    elseif msg_id == 0x07 then -- JOIN
        offset = dissect_join(tvb, pinfo, tm_tree, offset, hdr)
    elseif msg_id == 0x00 then -- OAM (transport)
        offset = add_vle(tm_tree, pf.oam_id, tvb, offset)
        if flag_z then offset = parse_transport_exts(tvb, pinfo, tm_tree, offset) end
        offset = parse_oam_body(tvb, tm_tree, offset, hdr)
    else
        -- Unknown transport message ID: consume extensions so the byte stream
        -- stays aligned for the next message.
        if flag_z then offset = parse_transport_exts(tvb, pinfo, tm_tree, offset) end
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

    -- ── Scouting (UDP 7446) ──────────────────────────────────
    if is_scouting and not is_tcp then
        local offset = 0
        while offset < total do
            if offset >= total then break end
            local hdr    = safe_byte(tvb, offset)
            local msg_id = hdr % 32
            local name   = lookup(vs_scout_id, msg_id)
            pinfo.cols.info:append(string.format(" [%s]", name))

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
        return total
    end

    -- ── TCP  (with 2-byte LE frame-length prefix) ────────────
    if is_tcp then
        local offset = 0
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

            dissect_zenoh_frame(tvb, pinfo, root, batch_start, batch_end)
            offset = batch_end
        end
        return total
    end

    -- ── UDP (datagram = one batch, no length prefix) ─────────
    dissect_zenoh_frame(tvb, pinfo, root, 0, total)
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
