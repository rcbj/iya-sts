# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# tests/schemathesis/egress_routes.py -- WHICH ROUTES MAY SHOW A BLOCKED
# OUTBOUND DIAL (#1358), for sts_checks.py's no_outbound_fetch.
#
# A handful of /admin-api operations dial an address AN ADMINISTRATOR
# CONFIGURED -- never one a request names. They are argued, one by one, in
# federation/CLAUDE.md's *The URLs this service dials that a caller's kind of
# URL could name*. On the #1299 fuzz stack the docker network is `internal:
# true` (no egress), so each of those dials fails closed at the network layer
# -- which is the whole guarantee -- and node's failure (getaddrinfo /
# ENOTFOUND / EAI_AGAIN) is carried back in the response body. The
# `no_outbound_fetch` check reads that body for those DNS markers, so without
# this table it fires on a dial WORKING AS DESIGNED.
#
# THREE ROWS ARE READS THAT DIAL NOTHING. GET /admin-api/scim and GET
# /admin-api/scim/clients (#1299, the 6c65a8e2d run) REPORT the stored
# last-error of an administrator's configured outbound SCIM target, which on
# the no-egress network is a getaddrinfo failure a prior reconcile recorded.
# GET /admin-api/audit (#1420, iya-sts-fuzz-1416) is the history read: `q`
# matched event text those same designed dials had already recorded
# (getaddrinfo / EAI_AGAIN). None of the three dials. The marker is in the
# body by design, so they are narrowed the same way; the live dial the SCIM
# reads report is the `reconcile` action below.
#
# SO THE NARROWING IS BY EXACT METHOD AND ROUTE, AND NOTHING ELSE. It is NOT
# keyed on the refusal's text, nor on a code appearing in the body
# (STS-REG-0080 / STS-REG-0081 and their neighbours): a check that passed a
# finding because the body happened to carry a word or a code would be a
# check that stopped checking. The marker STILL FAILS on every other route,
# so an unexpected dial anywhere else is still a finding -- which is the
# behaviour that matters, since the internal network, not this check, is the
# guarantee, and this table only stops the false positive on the designed
# dials.
#
# Each row names its federation/CLAUDE.md list entry, so a reader can find the
# argument for why that route dials. A route is added here only after the dial
# has been read in the code (as code_members.py adds a member only after its
# text has been read): a template's OTHER actions dial nothing and so never
# show a marker, so they are not listed, and listing a whole template would
# allow a marker on an action that should never produce one.
#
# The routes are `:action` style, so the key is METHOD, the path TEMPLATE as
# the OpenAPI document spells it (realm-agnostic: the admin-api schema carries
# no /realm prefix), and the `action` path-parameter VALUE. The admin-api
# resolve, add-subordinate and add-trust-anchor are the administrator's doors
# onto the OpenID Federation fetches (the thirteenth and fourteenth entries);
# the anonymous /oidfed/resolve endpoint starts no fetch and is not here.
#
# A route with NO `{action}` (the two SCIM reads and the audit history read)
# is keyed by the inner key `""`, which `allowed()` reads as "this whole
# route, whatever action sts_checks derived" -- its `_action()` makes a
# pseudo-action from a non-templated path's last segment (`scim`, `clients`,
# `audit`), so the `""` row matches it without this table having to know that
# quirk. An `""` key allows the route whole; the dial rows carry none, so
# their OTHER actions stay findings exactly as before.
#
# No schemathesis import, so tests/schemathesis_plan.js can drive this file
# with plain python3 (`python3 egress_routes.py`, one JSON case per line on
# stdin: {"method","path","action"} -> the reason string, or null).
# ===========================================================================

import json
import sys

# (METHOD, path template) -> { action value: the reason it dials by design }.
ALLOWED = {
    ("GET", "/admin-api/audit"): {
        "": "the audit history read: this READ dials nothing. `q` is a "
            "substring of the summary, the target or the action, so a query "
            "can match event text an earlier designed dial recorded "
            "(getaddrinfo / EAI_AGAIN on the no-egress fuzz network, "
            "#1420). The live dials are the rows below.",
    },
    ("GET", "/admin-api/scim"): {
        "": "the SCIM outbound report (#552): this READ dials nothing; it "
            "echoes the stored last-error of the administrator-configured "
            "outbound SCIM targets, which on the no-egress fuzz network is a "
            "getaddrinfo failure a prior reconcile recorded. The live dial is "
            "the reconcile action below.",
    },
    ("GET", "/admin-api/scim/clients"): {
        "": "the SCIM outbound clients report (#552): this READ dials nothing; "
            "it lists the configured outbound SCIM clients with each one's "
            "stored last-error, a getaddrinfo failure on the no-egress fuzz "
            "network. The live dial is the reconcile action below.",
    },
    ("POST", "/admin-api/claim-providers/{action}"): {
        "add-provider":
            "the twenty-fifth exception (an OpenID Connect claims provider, "
            "#147): registering one fetches the provider's own configured "
            "addresses through federation_http.requestConfigured().",
    },
    ("POST", "/admin-api/secret-destinations/{action}"): {
        "test-push":
            "the seventeenth exception (a secret push destination, #221): "
            "a test push writes a canary to the destination an "
            "administrator configured. common/secrets.js dials that "
            "stored endpoint (pushVault and the other providers), never "
            "a URL this request names. On the no-egress fuzz network the "
            "dial fails closed and the refusal carries getaddrinfo "
            "(#1430). No other action on this route dials.",
    },
    ("POST", "/admin-api/scim/clients/{action}"): {
        "reconcile":
            "the twenty-sixth exception (an outbound SCIM service, #552): a "
            "reconcile dials the SCIM endpoint an administrator configured on "
            "the client's entry, through common/outbound_tls.",
        "test-connection":
            "the twenty-sixth exception (an outbound SCIM service, #552): a "
            "connection test discovers that same configured endpoint and "
            "reads one User from it, through common/outbound_tls. It is not "
            "a URL the request names (#1405).",
    },
    ("POST", "/admin-api/oidfed/{action}"): {
        "resolve":
            "the thirteenth exception (an OpenID Federation Trust Chain): the "
            "administrator's resolve walks towards a configured Trust Anchor.",
        "add-trust-anchor":
            "the thirteenth exception (an OpenID Federation Trust Chain): "
            "adding an anchor fetches its entity configuration.",
        "add-subordinate":
            "the fourteenth exception (the Entity Collection): adding a "
            "subordinate fetches its entity configuration.",
    },
}


def allowed(method, path, action):
    """The reason this (method, route, action) may show a blocked outbound
    dial, or None when it may not. `path` is the OpenAPI path template; `action`
    is the value of its `{action}` path parameter (or '' when there is none)."""
    verb = str(method or "").upper()
    action = str(action or "")
    actions = ALLOWED.get((verb, str(path or "")))
    if actions is None and action and "{" not in str(path or ""):
        # A version that filled the path rather than showing the template:
        # rebuild the `{action}` template from the concrete last segment.
        head = str(path or "").rstrip("/").rsplit("/", 1)
        if len(head) == 2 and head[1] == action:
            actions = ALLOWED.get((verb, head[0] + "/{action}"))
    if not actions:
        return None
    hit = actions.get(action)
    if hit is None:
        # A route keyed `""` is allowed whole, whatever action sts_checks
        # derived for it (the two SCIM reads and the audit history read).
        # The dial rows have no `""` key, so their other actions fall
        # through to None and stay findings.
        hit = actions.get("")
    return hit


def _main():
    """One JSON case per line in, one JSON answer per line out."""
    if sys.argv[1:] == ["--routes"]:
        rows = []
        for (method, path), actions in ALLOWED.items():
            for action in actions:
                rows.append(method + " " + path
                            + ((" " + action) if action else ""))
        print(json.dumps(sorted(rows)))
        return
    for line in sys.stdin:
        case = json.loads(line)
        print(json.dumps(allowed(case["method"], case["path"],
                                 case.get("action", ""))))


if __name__ == "__main__":
    _main()
