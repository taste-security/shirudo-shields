#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Summarize the JSON `shirudo upatch map <upatch> <map> --peek --json`
prints for a map whose decoder returns {"records": [...]}.

Prints one line "total=<n> hits=<h> records=<m>": n is the sum of the
records' count fields (1 for a record without one), h the same over the
records that are hits, that is every record but the h2guard's
"untracked_*" notes of a connection it stopped following. Then one line
per record with the fields that say what was refused. Reads standard
input; empty or unparsable input counts as no records.
"""

import json
import sys

FIELDS = ("reason", "kind", "action", "comm", "pid", "tgid", "count",
          "detail", "path", "address", "port", "errno", "window",
          "increment", "rst_stream_frames")


def find_records(node):
    if isinstance(node, dict):
        if isinstance(node.get("records"), list):
            return node["records"]
        for value in node.values():
            found = find_records(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find_records(value)
            if found is not None:
                return found
    return None


def main():
    records = []
    for line in sys.stdin.read().splitlines():
        line = line.strip()
        if not line.startswith(("{", "[")):
            continue
        try:
            found = find_records(json.loads(line))
        except ValueError:
            continue
        if found:
            records.extend(r for r in found if isinstance(r, dict))
    total = hits = 0
    for r in records:
        try:
            n = int(r.get("count", 1))
        except (TypeError, ValueError):
            n = 1
        total += n
        if not str(r.get("reason", "")).startswith("untracked"):
            hits += n
    print("total=%d hits=%d records=%d" % (total, hits, len(records)))
    for r in records:
        print("  " + " ".join("%s=%s" % (k, r[k]) for k in FIELDS if k in r))


if __name__ == "__main__":
    main()
