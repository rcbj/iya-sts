# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# tests/schemathesis/pep_bodies.py -- THE REMOTE XACML PEP'S TWO INVARIANTS,
# as decisions, for sts_checks.py's no_internal_detail and
# refused_unauthenticated (tests/protocol/schemathesis_pep.js).
#
#   internal_detail(body, sent)   the first stack frame, panic, backtrace,
#                                 traceback, source location or image path in
#                                 a body, or None. A match inside a string this
#                                 very request sent is the caller's own input
#                                 echoed back, and is not one.
#   refusal(route, status, statuses, public)
#                                 why an unauthenticated call was not refused
#                                 as documented, or None: a route the document
#                                 gates must answer one of `statuses`; a route
#                                 in `public` takes no credential and is not
#                                 asked.
#
# No schemathesis import, so tests/schemathesis_plan.js drives this file with
# plain python3 (`python3 pep_bodies.py`, one JSON case per line on stdin),
# as it drives code_members.py and egress_routes.py.
# ===========================================================================

import json
import re
import sys

# Text this repository's code never writes into an answer: a node stack
# frame, a Rust panic or backtrace, a Python traceback, a Rust source
# location, a path inside one of this repository's images.
_INTERNAL_DETAIL = (
    re.compile(r"\bat [^\s(]+ \((?:/|node:)[^)\s]*:\d+:\d+\)"),
    re.compile(r"panicked at"),
    re.compile(r"stack backtrace:"),
    re.compile(r"RUST_BACKTRACE"),
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"[A-Za-z0-9_/.-]+\.rs:\d+:\d+"),
    re.compile(r"(?:/usr/src/sts|/usr/src/app|/app/rust|/rust/bins)/"),
)


def internal_detail(body, sent):
    """The internal detail `body` shows, or None."""
    for pattern in _INTERNAL_DETAIL:
        for found in pattern.finditer(body):
            text = found.group(0)
            if not any(text in one for one in sent):
                return text
    return None


def refusal(route, status, statuses, public):
    """Why this unauthenticated answer is not the documented refusal, or
    None when it is (or the route is not gated)."""
    if route in public:
        return None
    if status in statuses:
        return None
    return ("an unauthenticated " + route + " answered " + str(status)
            + ", where the documented refusal is "
            + "/".join(str(one) for one in sorted(statuses)))


def _main():
    """One JSON case per line in, one JSON answer per line out."""
    for line in sys.stdin:
        case = json.loads(line)
        if case.get("kind") == "refusal":
            print(json.dumps(refusal(case["route"], case["status"],
                                     set(case["statuses"]),
                                     set(case.get("public", ())))))
        else:
            print(json.dumps(internal_detail(case["body"],
                                             case.get("sent", ()))))


if __name__ == "__main__":
    _main()
