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

It adapts what scim2-tester SENDS in four places, each argued where it is
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


def generate_named_value(context, path, mutability=None, required=None):
    value = _generate(context, path, mutability=mutability, required=required)
    text = str(path)
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
