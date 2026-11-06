# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# tests/schemathesis/sts_checks.py — THIS SERVICE'S OWN FUZZING INVARIANTS
# (#1299), as Schemathesis custom checks.
#
# Loaded by the CLI through SCHEMATHESIS_HOOKS set to this file's path (the v4
# way; the v3 --pre-run flag is gone). Each check is registered with the v4
# @schemathesis.check decorator and raises AssertionError on a violation, which
# Schemathesis reports as a failed check. The built-in not_a_server_error
# covers 5xx; these three are the invariants no off-the-shelf check knows:
#
#   no_error_code_leak      every refusal records an operator error code
#                           STS-<SUBSYSTEM>-<NNNN> and NEVER sends it (root
#                           CLAUDE.md, Every failure has an error code); a code
#                           in a response body is the leak.
#   frame_ancestors_present frame-ancestors is the one CSP clause a page may
#                           not drop (RFC 9700 4.14); every HTML response must
#                           still carry it.
#   no_outbound_fetch       a best-effort signal that the service attempted an
#                           outbound DNS lookup (blocked by the internal, no-
#                           egress network). The network is the guarantee; this
#                           is the backstop.
#
# The Response accessor names (status_code, headers, body) are read
# defensively, because they have moved across Schemathesis majors; confirm them
# against the version tests/schemathesis/requirements.txt pins when the image
# is built.
# ===========================================================================

import json
import os
import re

import schemathesis

# STS-<SUBSYSTEM>-<NNNN>: an uppercase subsystem and four digits. The audit and
# log form; it must never appear in a response body.
_ERROR_CODE = re.compile(rb"STS-[A-Z]+-[0-9]{4}")

# The invariant is "no UNCAUGHT 5xx (the fault boundary holds)". Two 5xx are
# handled refusals rather than faults and are allowed:
#   501 Not Implemented -- a feature this service does not implement or a realm
#     has turned off (the VC API, UMA, EST /fullcmc), each with a marked
#     operator error code; the fault boundary never fires.
#   503 Service Unavailable -- ONLY when it is a documented, handled
#     degradation: it carries a Retry-After header and leaks no operator error
#     code (iya-sts-60's 2026-11-05 rule; e.g. STS-LDAP-0131, a windowed
#     worker's store question failing under load). A 503 WITHOUT Retry-After,
#     or one that leaks an STS code, is still a finding.
# Every other 5xx fails -- a 502 included, which in this harness can only be the
# auth proxy failing to forward (the service gateways nothing), so leaving it
# failing keeps a future proxy regression visible.
_ALLOWED_SERVER_STATUS = frozenset((501,))

# Markers of an attempted outbound DNS lookup that the no-egress network blocks.
# Narrow on purpose: these name resolution failures rather than any error text.
_EGRESS_MARKERS = (b"getaddrinfo", b"ENOTFOUND", b"EAI_AGAIN")


def _header(response, name):
    """The named response header, lower-cased key match, or ''."""
    headers = getattr(response, "headers", None) or {}
    try:
        items = headers.items()
    except AttributeError:
        items = []
    for key, value in items:
        if str(key).lower() == name.lower():
            if isinstance(value, (list, tuple)):
                return ", ".join(str(one) for one in value)
            return str(value)
    return ""


def _body_bytes(response):
    """The response body as bytes, however this version exposes it."""
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text.encode("utf-8", "replace")
    body = getattr(response, "body", None)
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8", "replace")
    return b""


def _route(case):
    """`METHOD /path` for the operation, however this version exposes it. Read
    defensively, as the Response accessors are (schemathesis moves these across
    majors)."""
    operation = getattr(case, "operation", None)
    method = getattr(case, "method", None) or getattr(operation, "method", "")
    path = (getattr(case, "path", None) or getattr(operation, "path", None)
            or getattr(operation, "label", None) or "")
    return (str(method or "").upper() + " " + str(path or "")).strip()


def _record_finding(kind, case, response, detail):
    """Append one finding -- kind, realm, surface, route, status, detail and a
    short body snippet -- as a JSON line to the file named by
    STS_SCHEMATHESIS_FINDINGS, so a run emits the authoritative route->code list
    the per-cell SUMMARY omits (the kit's 40000-char tail drops the per-failure
    detail on a large cell). BEST-EFFORT: a capture failure must never change
    the check's verdict, so everything here is caught and dropped. #1347's
    leak-sink work reads this list."""
    path = os.environ.get("STS_SCHEMATHESIS_FINDINGS")
    if not path:
        return
    try:
        snippet = _body_bytes(response)[:400].decode("utf-8", "replace")
        status = getattr(response, "status_code", None)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None
        row = {
            "kind": kind,
            "realm": os.environ.get("STS_SCHEMA_REALM_PREFIX", ""),
            "surface": os.environ.get("STS_SCHEMA_SURFACE", ""),
            "route": _route(case),
            "status": status,
            "detail": detail,
            "body": snippet,
        }
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
    except Exception:
        pass


@schemathesis.check
def no_uncaught_server_error(ctx, response, case):
    """No uncaught 5xx: the fault boundary holds. A deliberate 501 is allowed,
    and a 503 only when it is a handled degradation -- Retry-After present and
    no leaked error code."""
    status = getattr(response, "status_code", None)
    try:
        status = int(status)
    except (TypeError, ValueError):
        return
    if status < 500 or status in _ALLOWED_SERVER_STATUS:
        return
    if status == 503:
        retry_after = _header(response, "retry-after")
        leaks_code = _ERROR_CODE.search(_body_bytes(response)) is not None
        if retry_after and not leaks_code:
            return
        message = (
            "service unavailable 503 is a finding here: a handled 503 must "
            "carry Retry-After and leak no operator error code"
            + ("" if retry_after else " (no Retry-After)")
            + (" (leaks an STS code)" if leaks_code else "")
        )
        _record_finding("uncaught_server_error", case, response, message)
        raise AssertionError(message)
    message = (
        "server error " + str(status)
        + " (the fault boundary should hold; only a deliberate 501 Not "
        "Implemented, or a handled 503 with Retry-After, is allowed)"
    )
    _record_finding("uncaught_server_error", case, response, message)
    raise AssertionError(message)


@schemathesis.check
def no_error_code_leak(ctx, response, case):
    """No STS error code is ever sent to a client."""
    match = _ERROR_CODE.search(_body_bytes(response))
    if match is not None:
        code = match.group(0).decode("ascii", "replace")
        _record_finding("error_code_leak", case, response, code)
        raise AssertionError(
            "response body leaks the operator error code "
            + code
            + " (it is recorded, never sent)"
        )


@schemathesis.check
def frame_ancestors_present(ctx, response, case):
    """Every HTML response still carries the frame-ancestors CSP clause."""
    content_type = _header(response, "content-type").lower()
    if "text/html" not in content_type:
        return
    policy = _header(response, "content-security-policy").lower()
    if "frame-ancestors" not in policy:
        message = ("an HTML response dropped the frame-ancestors CSP clause "
                   "(it has no fallback from default-src)")
        _record_finding("frame_ancestors_dropped", case, response, message)
        raise AssertionError(message)


@schemathesis.check
def no_outbound_fetch(ctx, response, case):
    """Best-effort: the service did not try to resolve an outbound host."""
    body = _body_bytes(response)
    for marker in _EGRESS_MARKERS:
        if marker in body:
            message = ("response suggests an attempted outbound DNS lookup ("
                       + marker.decode("ascii", "replace")
                       + "); the stack must stay on the device")
            _record_finding("outbound_fetch", case, response, message)
            raise AssertionError(message)
