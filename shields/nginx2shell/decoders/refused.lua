-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo-shields
--
-- The refusals of nginx2shell-contain, as refused_emit_record() writes them.

local RECORD = 128

local KINDS = {
	[1] = "exec",
	[2] = "connect",
	[3] = "sendmsg",
	[4] = "socket",
	[5] = "create",
	[6] = "rename",
	[7] = "write",
	[8] = "truncate",
}

local FAMILIES = { [0] = "unspec", [2] = "inet", [10] = "inet6", [17] = "packet" }

local function header(slot)
	return {
		boot_now_ns = slot:u64(32),
		since_ns = slot:u64(40),
		used = slot:u32(48),
		overflow = slot:u32(52),
		lost = slot:u32(56),
		peek = slot:u32(28) % 2 == 1,
	}
end

local function unix_nano(input, hdr, ts)
	if ts == "0" then
		return nil
	end
	return shirudo.u64_sub(input.timeUnixNano,
		shirudo.u64_sub(hdr.boot_now_ns, ts))
end

local function interval(input, hdr)
	return {
		since_unix_nano = unix_nano(input, hdr, hdr.since_ns),
		used = hdr.used,
		overflow = hdr.overflow,
		lost = hdr.lost,
		peek = hdr.peek,
	}
end

-- The address is in network byte order, IPv4 as ::ffff:a.b.c.d.
local function address(slot, off)
	local mapped = true
	for i = 0, 9 do
		if slot:u8(off + i) ~= 0 then
			mapped = false
		end
	end
	if mapped and slot:u8(off + 10) == 255 and slot:u8(off + 11) == 255 then
		return string.format("%d.%d.%d.%d", slot:u8(off + 12),
			slot:u8(off + 13), slot:u8(off + 14), slot:u8(off + 15))
	end
	local groups = {}
	for i = 0, 7 do
		groups[#groups + 1] = string.format("%x",
			slot:u8(off + 2 * i) * 256 + slot:u8(off + 2 * i + 1))
	end
	return table.concat(groups, ":")
end

-- A socket refusal names the family alone.
local function peer(slot, kind)
	local family = slot:u16(64)
	local item = { family = FAMILIES[family] or family }
	if kind ~= 4 and (family == 2 or family == 10) then
		item.port = slot:u8(66) * 256 + slot:u8(67)
		item.address = address(slot, 72)
	end
	return item
end

local function record(input, hdr, slot)
	local kind = slot:u32(8)
	local item = {
		entry_index = slot:u32(0),
		kind = KINDS[kind] or kind,
		tgid = slot:u32(12),
		pid = slot:u32(16),
		count = slot:u64(24),
		first_seen_unix_nano = unix_nano(input, hdr, slot:u64(32)),
		last_seen_unix_nano = unix_nano(input, hdr, slot:u64(40)),
		comm = slot:cstring(48, 16),
	}
	if kind >= 2 and kind <= 4 then
		item.peer = peer(slot, kind)
	else
		item.name = slot:cstring(64, 48)
	end
	return item
end

function decode(input)
	local records, summary = {}, nil
	for _, page in ipairs(input.data.pages) do
		local slots = shirudo.page_slots(page, RECORD)
		local hdr = slots[1] and header(slots[1])
		if hdr then
			summary = summary or interval(input, hdr)
			for i = 2, #slots do
				if slots[i]:u32(4) % 2 == 1 then
					records[#records + 1] = record(input, hdr, slots[i])
				end
			end
		end
	end
	return {
		schema = 1,
		upatch = input.upatch,
		map = input.map,
		interval = summary,
		records = records,
	}
end
