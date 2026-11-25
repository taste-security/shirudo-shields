#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Convert a util-linux `script` recording to an asciinema v2 .cast.

usage: script2cast.py <typescript> <timing> <out.cast> [--title T]
                      [--width 120] [--height 40] [--idle-limit 2]

<timing> is what `script --log-timing` wrote, in the classic format
("<delay> <bytes>" per line) or the advanced one ("O <delay> <bytes>",
with I, H and S lines, which are skipped). Output is decoded as UTF-8
across chunk boundaries, so a character split between two writes stays
whole.
"""

import argparse
import codecs
import json
import time


def chunks(timing_path):
    with open(timing_path) as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            if parts[0] in ("O", "I", "H", "S"):
                if parts[0] != "O" or len(parts) < 3:
                    continue
                parts = parts[1:]
            try:
                yield float(parts[0]), int(parts[1])
            except (ValueError, IndexError):
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("typescript")
    ap.add_argument("timing")
    ap.add_argument("out")
    ap.add_argument("--title", default="")
    ap.add_argument("--width", type=int, default=120)
    ap.add_argument("--height", type=int, default=40)
    ap.add_argument("--idle-limit", type=float, default=2.0)
    args = ap.parse_args()

    with open(args.typescript, "rb") as f:
        data = f.read()
    timing = list(chunks(args.timing))
    # script writes a "Script started on ..." line the timing does not count.
    offset = 0
    if data.startswith(b"Script started on"):
        offset = data.find(b"\n") + 1
    if offset and len(data) - offset < sum(n for _, n in timing):
        offset = 0

    header = {
        "version": 2, "width": args.width, "height": args.height,
        "timestamp": int(time.time()), "idle_time_limit": args.idle_limit,
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/sh"},
    }
    if args.title:
        header["title"] = args.title
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    t = 0.0
    pos = offset
    with open(args.out, "w") as out:
        out.write(json.dumps(header) + "\n")
        for delay, n in timing:
            t += delay
            text = decoder.decode(data[pos:pos + n])
            pos += n
            if text:
                out.write(json.dumps([round(t, 6), "o", text]) + "\n")
        rest = decoder.decode(b"", final=True)
        if rest:
            out.write(json.dumps([round(t, 6), "o", rest]) + "\n")


if __name__ == "__main__":
    main()
