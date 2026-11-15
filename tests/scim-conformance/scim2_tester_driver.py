# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

"""Run python-scim's scim2-tester against one SCIM base URL, print JSON.

The driver tests/protocol/sts_scim_conformance.js runs (#206). It is this
repository's, not the harness's: scim2-tester's own CLI calls discover()
BEFORE its checks, so a service whose discovery documents do not compose
into a coherent description crashes the CLI instead of being reported, and
it prints text, where the job wants every check's status, title, tags and
reason as data. What it runs is scim2-tester's check_server(), unchanged,
with every tag.

Arguments come from the environment so no token is on a command line:
  SCIM_BASE_URL   the /scim/v2 base (a trust realm's).
  SCIM_TOKEN      a bearer access token carrying scim:read and scim:write.
  SCIM_CA_FILE    the PEM anchor for the service's TLS certificate.
  SCIM_FEDERATION_RELATIONSHIP, SCIM_FEDERATION_PEER
                  a service-provider-side federation relationship of the
                  realm and its peer, for the federationLinks member.
  SCIM_POLICY_NAMES
                  "1" in product mode: Users are created with a name, as
                  the realm's attribute policy requires (the fourth
                  adaptation, below).
  SCIM_HOME_CELL  in a service deployed as cells, the id of the cell the
                  job addresses: every homeCell the harness sends (the
                  fifth adaptation, below). Unset elsewhere.

It adapts what scim2-tester SENDS in five places, each argued where it is
made below, and never what it checks.
"""

import json
import os
import sys
import traceback

from httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_models import Path
from scim2_models import Required
from scim2_models import Resource
from scim2_tester import check_server
from scim2_tester import filling
import scim2_tester.checkers  # noqa: F401 -- loaded so its imports are seen

# THE ONE ADAPTATION, and it changes what is SENT, never what is checked.
# scim2-tester fills every string member it has no example for with a bare
# uuid4(), userName included, and this service refuses a UUID-shaped userName
# on every door (400 invalidValue, STS-LDAP-0090): a person's subject is
# urn:uuid:<entryUUID>, and a person NAMED after a UUID would answer to
# somebody else's subject. RFC 7644 section 3.3 lets a service provider refuse
# a value that breaks its own rule, so the refusal is conformant; without this
# every User check (and every Group check, whose members are Users) stops at
# that refusal and nothing else about the resource is exercised. The value
# stays random and unique; it only stops looking like a subject.
_generate = filling.generate_random_value


# THE SECOND, for a Group's `members`: scim2-tester fills a member's `$ref`
# with a User it created and its `type` with a random choice of "User" and
# "Group", so half its members say they are a Group while naming a User.
# This service reports the type of what the member IS, so the harness's own
# comparison failed on whichever half it drew. The type is set to agree
# with the `$ref` the harness itself chose; nothing about the check changes.
def consistent_member(member):
    ref = str(getattr(member, "ref", "") or "")
    for kind in ("Users", "Groups"):
        if "/" + kind + "/" in ref and hasattr(member, "type"):
            member.type = kind[:-1]
    return member


# THE THIRD, for this service's own extension: a federation link names a
# service-provider-side relationship of the realm and that relationship's
# peer (scim/CLAUDE.md, #109), which a harness cannot guess — a random one is
# refused 400 (STS-FED-0105), as it should be. The job creates one in its
# realm and names it here; the subject stays random.
RELATIONSHIP = os.environ.get("SCIM_FEDERATION_RELATIONSHIP", "")
PEER = os.environ.get("SCIM_FEDERATION_PEER", "")


def real_link(link):
    if RELATIONSHIP and hasattr(link, "relationship"):
        link.relationship = RELATIONSHIP
        link.issuer = PEER
    return link


# THE FIFTH, for this service's own extension's `homeCell` (#98), and only
# in a service deployed as cells: the harness fills the write-only string
# with a uuid4(), and a cell id this service does not have is refused 400
# invalidValue (STS-CELL-0140) at a create, and a different one 400
# mutability (STS-CELL-0145) at a PUT or PATCH -- both RFC 7644 section 3.12
# errors, as they should be. GitHub Actions run 43642810770's cells mode
# stopped nine User checks there, the create, list and query checks among
# them. The only valid values are the cell ids, which no document a client
# reads names (a cell is a routing fact), so a harness cannot learn one. The
# job names the cell it addresses, which is also the realm's default home,
# so the person is homed where an absent homeCell would have put them, and
# every check behind the create runs. A single-cell service ignores
# homeCell and the job sets nothing.
HOME_CELL = os.environ.get("SCIM_HOME_CELL", "")


def is_home_cell(text):
    return text.lower().replace("_", "").endswith("homecell")


def real_home(value):
    """Put the job's cell into a homeCell this value carries: on the value
    itself (the extension object) or one level down (a User holding it)."""
    if not HOME_CELL or value is None:
        return value
    for holder in [value] + [getattr(value, f, None) for f in
                             list(getattr(type(value), "model_fields", {})
                                  or {})]:
        for field in list(getattr(type(holder), "model_fields", {}) or {}):
            if (is_home_cell(field) and
                    getattr(holder, field, None) is not None):
                setattr(holder, field, HOME_CELL)
    return value


def generate_named_value(context, path, mutability=None, required=None):
    value = _generate(context, path, mutability=mutability, required=required)
    text = str(path)
    if HOME_CELL and is_home_cell(text) and isinstance(value, str):
        return HOME_CELL
    if HOME_CELL and hasattr(type(value), "model_fields"):
        return real_home(value)
    if text.endswith("userName") and isinstance(value, str):
        return "s2t-" + value
    if text.endswith("members") and isinstance(value, list):
        return [consistent_member(one) for one in value]
    if text.endswith("federationLinks") and isinstance(value, list):
        return [real_link(one) for one in value]
    if text.endswith("federationLinks.relationship") and RELATIONSHIP:
        return RELATIONSHIP
    if text.endswith("federationLinks.issuer") and PEER:
        return PEER
    return value


# THE FOURTH, for a User the harness creates with only its REQUIRED members
# (create_and_register() without fill_all, which is most of its checks):
# RFC 7643 section 4.1 requires only userName, but in product mode a person
# is held to the realm's attribute policy (#396), and `uid`, `cn` and `sn`
# are required by every policy because `person` lists cn and sn as MUST
# (common/CLAUDE.md 3co). Such a create is refused 400 invalidValue
# (STS-LDAP-0162), as it should be, and every User check behind it stops
# there. So the person is given what any real provisioning client sends:
# name.familyName (sn) and name.givenName, from which the service makes the
# cn. The values stay random; the job's realm requires nothing more, and
# what the harness CHECKS is unchanged. /Schemas does not yet publish the
# policy's `required` (scim/CLAUDE.md, *THE ATTRIBUTE POLICY OVER SCIM*), or
# the harness would fill these itself. The job sets SCIM_POLICY_NAMES in
# product mode only; development does not enforce the policy, and its run
# sends what the harness chose.
_fill = filling.fill_with_random_values
POLICY_NAMES = ("name.familyName", "name.givenName")


def fill_with_policy_names(context, obj, paths=None, mutability=None,
                           required=None):
    filled = _fill(context, obj, paths=paths, mutability=mutability,
                   required=required)
    if (paths is None and required == [Required.true] and
            isinstance(filled, Resource) and
            "name" in type(filled).model_fields):
        names = [one for one in Path[type(filled)].iter_paths()
                 if str(one).split(":")[-1] in POLICY_NAMES]
        if names:
            _fill(context, filled, paths=names, mutability=mutability)
    return filled


if os.environ.get("SCIM_POLICY_NAMES") == "1":
    filling.fill_with_random_values = fill_with_policy_names

# The fifth adaptation's half for a resource filled whole: whatever filled
# it, its homeCell is the job's cell.
_filled = filling.fill_with_random_values


def fill_with_home_cell(context, obj, paths=None, mutability=None,
                        required=None):
    return real_home(_filled(context, obj, paths=paths,
                             mutability=mutability, required=required))


if HOME_CELL:
    filling.fill_with_random_values = fill_with_home_cell
    for _name, _module in list(sys.modules.items()):
        if (_name.startswith("scim2_tester") and
                getattr(_module, "fill_with_random_values", None) in
                (_fill, _filled)):
            _module.fill_with_random_values = fill_with_home_cell

# Every module that imported the function by name holds its own reference,
# so each is pointed at the wrapper, not only `filling`.
for _name, _module in list(sys.modules.items()):
    if (_name.startswith("scim2_tester") and
            getattr(_module, "generate_random_value", None) is _generate):
        _module.generate_random_value = generate_named_value


def plain(value):
    """Return value in a form json.dumps accepts, whatever it is."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        dump = getattr(value, "model_dump", None)
        if callable(dump):
            try:
                return dump(mode="json")
            except Exception as e:  # noqa: BLE001 -- reported, not swallowed
                return repr(value) + " (model_dump failed: " + str(e) + ")"
        return repr(value)


def main():
    base = os.environ["SCIM_BASE_URL"]
    token = os.environ["SCIM_TOKEN"]
    verify = os.environ.get("SCIM_CA_FILE") or True
    client = Client(base_url=base, verify=verify, timeout=60.0,
                    headers={"Authorization": "Bearer " + token})
    scim = SyncSCIMClient(client)
    out = {"results": [], "crash": None}
    try:
        results = check_server(scim)
    except Exception:  # noqa: BLE001 -- the crash IS the report
        out["crash"] = traceback.format_exc()
        results = []
    for r in results:
        out["results"].append({
            "status": r.status.name,
            "title": r.title,
            "resourceType": r.resource_type,
            "tags": sorted(r.tags or []),
            "reason": r.reason,
            "data": plain(r.data) if r.status.name in
            ("ERROR", "CRITICAL", "DEVIATION") else None,
        })
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
