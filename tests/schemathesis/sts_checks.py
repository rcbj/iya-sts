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
#                           in a response body is the leak, outside the
#                           exceptions code_members.py lists (#1355, #1357).
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
import sys

import schemathesis

# Beside this file; the CLI loads this file by path, so its directory is not on
# the import path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_members  # noqa: E402
import egress_routes  # noqa: E402

# THE TWO ARCHIVE BODY TYPES ARE SENT AS BYTES, AS octet-stream IS (fuzz run
# 14, 2026-11-11). POST /admin-api/risk/upload takes its file as
# application/octet-stream, application/gzip or application/zip, and
# Schemathesis 4.33 has a serializer for the first alone: every case drawing
# either of the other two was rejected ("Can't serialize data to
# `application/gzip`"), so about two draws in three were thrown away, neither
# archive type ever reached the service, and in about one run in forty the
# filter_too_much health check failed the operation -- fuzz-9700's admin-api
# cell, with all 70521 of its cases passing. They are a file's bytes like any
# other, which is what the octet-stream serializer sends, so it is reused for
# them; no health check is suppressed and no operation is excluded. These are
# the only request media types in models/api/*.tsp with no built-in serializer.
schemathesis.serializer.alias(["application/gzip", "application/zip"],
                              "application/octet-stream")

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


def _action(case):
    """The value of the route's `{action}` path parameter, or '': the admin-api
    `:action` routes carry the operation there, and egress_routes keys on it.
    Read defensively, as the other case accessors are."""
    params = getattr(case, "path_parameters", None)
    if isinstance(params, dict) and params.get("action") is not None:
        return str(params.get("action"))
    # A fallback for a version that fills the path: the last segment of a
    # concrete route whose template is not shown.
    path = getattr(case, "path", None) or ""
    if "{" not in str(path):
        tail = str(path).rstrip("/").rsplit("/", 1)
        if len(tail) == 2:
            return tail[1]
    return ""


def _request_strings(case):
    """Every string value this request sent -- its JSON or form body, at any
    depth, its query and its path parameters -- for code_members.leaked's
    `echoed`: a member answering one of them whole is the caller's own input.
    Read defensively, as the other case accessors are."""
    out = set()

    def walk(value):
        if isinstance(value, str):
            out.add(value)
        elif isinstance(value, (list, tuple)):
            for one in value:
                walk(one)
        elif isinstance(value, dict):
            for one in value.values():
                walk(one)

    for name in ("body", "query", "path_parameters"):
        walk(getattr(case, name, None))
    return frozenset(out)


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
    """No STS error code is sent to a client, outside code_members.py's
    exceptions. Every code in the answer is read and recorded, where the first
    alone was, because help text early in an answer hid what came after it."""
    route = _route(case).split(" ", 1)
    method = route[0]
    path = route[1] if len(route) > 1 else ""
    status = getattr(response, "status_code", None)
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    body = _body_bytes(response).decode("utf-8", "replace")
    found = code_members.leaked(method, path, status, body,
                                _request_strings(case))
    if found:
        detail = ", ".join(sorted({code + " at " + member
                                   for member, code in found}))
        _record_finding("error_code_leak", case, response, detail)
        raise AssertionError(
            "response body leaks the operator error code "
            + detail
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
    """Best-effort: the service did not try to resolve an outbound host, EXCEPT
    at the handful of routes that dial an administrator-configured address by
    design (egress_routes.py). The marker still fails on every other route."""
    body = _body_bytes(response)
    hit = None
    for marker in _EGRESS_MARKERS:
        if marker in body:
            hit = marker
            break
    if hit is None:
        return
    route = _route(case).split(" ", 1)
    method = route[0] if route else ""
    path = route[1] if len(route) > 1 else ""
    reason = egress_routes.allowed(method, path, _action(case))
    if reason:
        # A designed dial, blocked by the no-egress network: not a finding.
        # Keyed on the exact method and route, never on the body's text.
        return
    message = ("response suggests an attempted outbound DNS lookup ("
               + hit.decode("ascii", "replace")
               + "); the stack must stay on the device")
    _record_finding("outbound_fetch", case, response, message)
    raise AssertionError(message)
