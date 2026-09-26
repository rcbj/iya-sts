"""Run python-scim's scim2-tester against one SCIM base URL, print JSON.

The driver tests/vendored/sts_scim_conformance.js runs (#206). It is this
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
"""

import json
import os
import sys
import traceback

from httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_tester import check_server
from scim2_tester import filling

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


def generate_named_value(context, path, mutability=None, required=None):
    value = _generate(context, path, mutability=mutability, required=required)
    if str(path).endswith("userName") and isinstance(value, str):
        return "s2t-" + value
    return value


filling.generate_random_value = generate_named_value


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
