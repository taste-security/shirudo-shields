#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""usage: summary.py <shield> <log> [<expected scenario>...]

Reads the log of a shield's scenario run (lines "PASS: <scenario>:
<what>", "FAIL: <scenario>: <what>" and "SCENARIO <name> PASS|FAIL") and
prints a Markdown summary for $GITHUB_STEP_SUMMARY: one row per scenario,
then every failed check. Exits 1 when a check failed, a scenario failed
or an expected scenario did not run at all.
"""

import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    shield, log = sys.argv[1], sys.argv[2]
    expected = sys.argv[3:]
    order, checks, results, failures = [], {}, {}, []
    with open(log, errors="replace") as f:
        for raw in f:
            line = ANSI.sub("", raw).rstrip("\r\n")
            m = re.match(r"^(PASS|FAIL): ([a-z0-9_-]+): (.*)$", line)
            if m:
                verdict, scenario, what = m.groups()
                if scenario not in checks:
                    checks[scenario] = [0, 0]
                    order.append(scenario)
                checks[scenario][verdict == "FAIL"] += 1
                if verdict == "FAIL":
                    failures.append((scenario, what))
                continue
            m = re.match(r"^SCENARIO ([a-z0-9_-]+) (PASS|FAIL)$", line)
            if m:
                results[m.group(1)] = m.group(2)
                if m.group(1) not in order:
                    order.append(m.group(1))
    for name in expected:
        if name not in order:
            order.append(name)

    bad = bool(failures)
    out = ["## %s shield" % shield, "",
           "| # | Scenario | Result | Checks passed | Checks failed |",
           "|---|----------|--------|---------------|---------------|"]
    for i, name in enumerate(order, 1):
        passed, failed = checks.get(name, (0, 0))
        result = results.get(name)
        if result is None:
            result = "NOT RUN" if name not in checks else ("FAIL" if failed else "PASS")
        if result != "PASS":
            bad = True
        mark = "✅" if result == "PASS" else "❌"
        out.append("| %d | `%s` | %s %s | %d | %d |" % (i, name, mark, result, passed, failed))
    if not order:
        out.append("| | (no scenario ran) | ❌ | 0 | 0 |")
        bad = True
    if failures:
        out += ["", "### Failed checks", ""]
        out += ["- `%s`: %s" % (s, w.replace("|", "\\|")) for s, w in failures]
    out.append("")
    print("\n".join(out))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
