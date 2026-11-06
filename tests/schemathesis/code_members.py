# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# tests/schemathesis/code_members.py -- WHERE AN ANSWER MAY NAME AN ERROR CODE
# (#1357), for sts_checks.py's no_error_code_leak.
#
# A code is recorded and never sent, with two exceptions, both rcbj's and both
# confined to a successful answer of /admin-api (root CLAUDE.md, Every failure
# has an error code):
#
#   DIAGNOSTIC_ROUTES  a read that draws recorded failures for an administrator
#                      (#1355). tests/openapi_response_models.js's
#                      DRAWN_CODE_OPERATIONS and DRAWN_PLAIN_CODES say which,
#                      and tests/schemathesis_plan.js holds this table to them.
#   the help text      a sentence this service wrote that tells an
#                      administrator which code to look for ("refused under
#                      hard-fail (STS-PKI-0188)"), rcbj's decision of
#                      2026-11-06. It is the same text whatever the request.
#
# THE HELP TEXT IS LISTED BY ROUTE AND MEMBER, EXACTLY, AND NOT BY A MEMBER'S
# NAME. `description` or `what` allowed everywhere would pass a refusal's
# reason, or a row of live data, that happened to use the word. A code anywhere
# else fails, every code in the answer is read rather than the first, and a
# member that turns up in a run is added here only after somebody has read that
# it is fixed text. Moved or renamed text fails the fuzz run, which is the
# safe direction.
#
# No schemathesis import, so tests/schemathesis_plan.js can drive this file with
# plain python3 (`python3 code_members.py`, one JSON case per line on stdin).
# ===========================================================================

import json
import re
import sys

_CODE = re.compile(r"STS-[A-Z]+-[0-9]{4}")
_INDEX = re.compile(r"\[[0-9]+\]")

# operationId -> the read's path, GET only.
DIAGNOSTIC_ROUTES = {
    "getAcmeMonitor": "/admin-api/acme/monitor",
    "getApplications": "/admin-api/applications",
    "getAttributeSources": "/admin-api/attribute-sources",
    "getAudit": "/admin-api/audit",
    "getErrorCodes": "/admin-api/error-codes",
    "getEstMonitor": "/admin-api/est/monitor",
    "getListeners": "/admin-api/listeners",
    "getLiveSessions": "/admin-api/logout",
    "getMailOutbox": "/admin-api/mail/outbox",
    "getOutboundDeliveries": "/admin-api/deliveries",
    "getProviderCommands": "/admin-api/commands",
    "getRisk": "/admin-api/risk",
    "getScepMonitor": "/admin-api/scep/monitor",
    "getScheduler": "/admin-api/scheduler",
    "getScim": "/admin-api/scim",
    "getScimClients": "/admin-api/scim/clients",
    "getSsf": "/admin-api/ssf",
    "getSsfDeadLetters": "/admin-api/ssf/dead-letters",
    "getUma": "/admin-api/uma",
    "getUsers": "/admin-api/users",
}

# The settings block, which many pages and some acts answer. Its descriptions
# are config.js's rows.
HELP_TEXT_ANYWHERE = frozenset((
    ".groups[].settings[].description",
    ".settings.groups[].settings[].description",
    ".settings[].description",
    ".settingsForms.groups[].settings[].description",
))

HELP_TEXT_BY_ROUTE = {
    "/admin-api/acme": (
        ".mode.product",
    ),
    "/admin-api/applications/new": (
        ".declarations[].what",
        ".fields[].described.description",
        ".fields[].what",
    ),
    "/admin-api/crypto": (
        ".families[].algorithms[].how",
    ),
    "/admin-api/est": (
        ".mode.product",
    ),
    "/admin-api/ldap/applications": (
        ".schema.attributes[].what",
    ),
    "/admin-api/ldap/federations": (
        ".schema.attributes[].what",
    ),
    "/admin-api/mode": (
        ".requirements[].product",
    ),
    "/admin-api/oauth2": (
        ".alsoHtml[]",
        ".notes[]",
    ),
    "/admin-api/policies": (
        ".serviceAccount.fields[].what",
        ".serviceAccount.schema.attributes[].what",
    ),
    "/admin-api/scep": (
        ".mode.requirement.product",
    ),
    "/admin-api/scim/monitor": (
        ".schemes[].description",
    ),
    "/admin-api/sts-metadata": (
        ".endpoints[].description",
        ".rows[].what",
        ".specifications[].coverage",
    ),
}

# The account API's OpenAPI document as the console's page holds it: its
# descriptions, which docs/openapi/ publishes as well.
_DOCUMENT_ROUTE = "/admin-api/account-api"
_DOCUMENT_PREFIX = ".document.paths."


def _strings(value, path):
    """Every string in a parsed answer, keys included, with its member path;
    an array index is written []."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for one in value:
            yield from _strings(one, path + "[]")
    elif isinstance(value, dict):
        for key, one in value.items():
            yield path + "{key}", str(key)
            yield from _strings(one, path + "." + str(key))


def _help_text(path_of_route, member):
    """Is this member fixed text this route may name a code in?"""
    if member in HELP_TEXT_ANYWHERE:
        return True
    if member in HELP_TEXT_BY_ROUTE.get(path_of_route, ()):
        return True
    return (path_of_route == _DOCUMENT_ROUTE
            and member.startswith(_DOCUMENT_PREFIX)
            and member.endswith(".description"))


def leaked(method, path_of_route, status, body):
    """The codes this answer may not carry, as (member, code); empty when it
    is clean. `body` is text. Anything that is not a successful answer of
    /admin-api, or is not JSON, may carry none at all."""
    admin = path_of_route.startswith("/admin-api/")
    success = isinstance(status, int) and 200 <= status < 300
    if not (admin and success):
        return [("(body)", code) for code in _CODE.findall(body)]
    if (method == "GET"
            and path_of_route in DIAGNOSTIC_ROUTES.values()):
        return []
    try:
        answer = json.loads(body)
    except ValueError:
        return [("(body)", code) for code in _CODE.findall(body)]
    found = []
    for member, text in _strings(answer, ""):
        if _CODE.search(text) and not _help_text(path_of_route, member):
            found.extend((member, code) for code in _CODE.findall(text))
    return found


def _main():
    """One JSON case per line in, one JSON answer per line out."""
    if sys.argv[1:] == ["--diagnostic-operations"]:
        print(json.dumps(sorted(DIAGNOSTIC_ROUTES)))
        return
    for line in sys.stdin:
        case = json.loads(line)
        print(json.dumps(leaked(case["method"], case["path"], case["status"],
                                case["body"])))


if __name__ == "__main__":
    _main()
