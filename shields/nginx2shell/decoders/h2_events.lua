-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo-shields
--
-- The hits of nginx2shell-h2guard, and the connections it stopped
-- following, as h2_emit_record() writes them.

local RECORD = 96

local REASONS = {
	[1] = "conn_window_over_max",
	[2] = "stream_window_over_max",
	[3] = "settings_window_over_max",
	[4] = "untracked_table_full",
	[5] = "untracked_desync",
	[6] = "untracked_oversize",
}

local ACTIONS = {
	[0] = "recorded",
	[1] = "killed",
	[2] = "kill_failed",
}

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

-- The window is a signed 64-bit value; a hit is always positive.
local function record(input, hdr, slot)
	local reason = slot:u32(20)
	local item = {
		entry_index = slot:u32(0),
		reason = REASONS[reason] or reason,
		tgid = slot:u32(16),
		pid = slot:u32(28),
		count = slot:u64(32),
		first_seen_unix_nano = unix_nano(input, hdr, slot:u64(40)),
		last_seen_unix_nano = unix_nano(input, hdr, slot:u64(48)),
		comm = slot:cstring(80, 16),
	}
	if reason <= 3 then
		item.conn = slot:u64(8)
		item.stream = slot:u32(24)
		item.window = slot:u64(56)
		item.increment = slot:u32(64)
		item.rst_stream_frames = slot:u32(68)
		item.action = ACTIONS[slot:u32(72)] or slot:u32(72)
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
