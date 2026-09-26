#!/usr/bin/python3
# The one page of the Shibboleth peer behind mod_shib (#189): what mod_shib
# put in the environment for this session, as JSON, so the job can assert the
# attributes, the NameID and the identity provider without scraping HTML.
import json
import os

KEEP = ("Shib-", "Shib_", "REMOTE_USER", "AUTH_TYPE")
IDS = ("uid", "mail", "givenName", "sn", "displayName", "cn", "claim-name",
       "claim-email", "persistent-id", "subject-id", "pairwise-id")
out = {k: v for k, v in os.environ.items()
       if k.startswith(KEEP) or k in IDS}
if not os.environ.get("Shib-Session-ID") and \
        not os.environ.get("Shib_Session_ID"):
    print("Status: 401 No Session")
print("Content-Type: application/json")
print("Cache-Control: no-store")
print()
print(json.dumps(out, indent=1, sort_keys=True))
