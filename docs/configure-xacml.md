---
title: "Configuring XACML and ALFA policy"
---

# Configuring XACML and ALFA policy

This page shows how to set up iya-sts's XACML 3.0 Policy Decision Point (PDP)
and the policies around it: writing and loading a policy, admitting a caller
to the PDP, asking for a decision, the Policy Information Point (PIP), the
remote enforcement point (PEP) container, and the policies this service
decides its own issuance, access and delegation with. Each recipe is given
twice: once as steps in the **admin console** and once as **Management API**
calls.

The values come from this repository's test jobs in `tests/protocol/` and
`tests/`, and each recipe names the job it is taken from. How the PDP, the
PIP and the embedded PEPs *behave*, and every setting with its default, are
on [XACML 3.0 and ALFA](xacml.md); the container is on
[Remote PEP](remote-pep.md); who may act for whom is on
[Delegation](delegation.md). This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the console's settings forms.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/xacml` | **Protocols → XACML** | Six tabs: **Metadata**, **Global settings** (every `xacml.*` setting, saved with **Save XACML**), **Policies**, **Policy editor**, **Remote PEPs** and **Try a decision**. |
| `/admin/xacml#xacml-tab-policies` | the **Policies** tab | Create a policy from a template, import ALFA, **Enable** / **Disable** / **Make root** / **Delete**, and **Create an override** of this service's own policies. |
| `/admin/xacml#xacml-tab-editor` | the **Policy editor** tab | Change an existing policy element by element, and read it as ALFA and as stored XML. |
| `/admin/xacml#xacml-tab-peps` | the **Remote PEPs** tab | **Issue certificate**, **Stop nudging** / **Nudge**, **Forget**. |
| `/admin/xacml#xacml-tab-decide` | the **Try a decision** tab | **Ask the PDP** about a subject, an action and a resource. |
| `/admin/roles` | **Directory → Roles** | Make roles, give them to people, groups and applications, and preview **Would this be issued?** |
| `/admin/groups` | **Directory → Groups** | Put an entry in `remote-peps` or `xacml-users`, under **Add a member**. |
| `/admin/tls/trust` | **Protocols → Client-certificate truststore** | **Add anchors**, then **Trust these**: the CA a PEP's or a caller's certificate chains to. |
| `/admin/delegation-settings` | **Protocols → Delegation** | The four `delegation.*` settings, saved with **Save Delegation**. |
| `/admin/xacml/monitor` | **Monitoring → XACML decisions** | Decisions and enforcements per PEP. |

The API equivalents are `GET /admin-api/xacml`, `/xacml/policies`,
`/xacml/editor?policy=<name>`, `/xacml/peps`, `/xacml/decide` and
`/xacml/monitor`, and `POST /admin-api/xacml/{action}` for every policy,
editor and PEP action. The bodies are in `/admin-api/openapi.json`; settings
go through `POST /admin-api/config/set` and `/config/reset`.

**Everything is per [trust realm](trust-realms.md).** The repository
(`ou=policies`), the register of remote PEPs (`ou=peps`), the two role groups
and the settings all belong to the realm a page is shown in, or to
`/realm/<id>/admin-api/…`. **A new realm's repository starts empty**, and an
empty repository answers NotApplicable to everything.

**What development and product mode change.**
* **The two role groups are empty in product mode.** Development mode seeds
  `cn=remote-pep-1` in `remote-peps` and `cn=xacml-user-1` in `xacml-users`,
  and the people alice, bob and carol. Product mode seeds the groups with
  nobody in them, and seeds none of those entries, so every caller of
  `/xacml` needs an entry and a membership you create.
* **A risk Deny and a delegation refusal are enforced only in product mode.**
  Development mode records them ("WOULD HAVE BEEN REFUSED in product") and
  issues anyway.
* **The nudge to a remote PEP must be `https` in product mode.**
  `xacml.pepNotifyAllowHttp` and `xacml.pepNotifySkipTlsVerification` work
  only in development mode.
* **Revocation of a presented certificate** (`pki.revocationCheck=auto`)
  soft-fails in development mode and hard-fails in product mode.

The policies, the four-check gate and the embedded PEPs are the same in both
modes.

---

# Policies

## Create a policy from a template

A template builds a working, valid policy from a few parameters. The first
policy in an empty repository becomes the **root**, the one the PDP starts
from. Taken from `sts_xacml_endpoints.js`, which then asks the PDP about two
people it created with `employeeType` `admin` and `staff`.

**Console:**
1. On **Protocols → XACML**, open the **Policies** tab.
2. Under **Create from a template**, open **Role-based (RBAC)**.
3. Set **Name for the policy** to `rbac-under-test`, and fill in:
   - **The subject attribute holding the role**: `employeeType`
   - **Roles that may do anything**: `admin`
   - **Roles limited to certain actions**: `staff`
   - **The actions those roles may perform**: `GET, HEAD`
4. Click **Create**. The policy appears in the table, marked **(root)** if the
   repository was empty.

**API:**
```bash
api xacml/create-from-template '{"template":"rbac","name":"rbac-under-test",
  "p_roleAttribute":"employeeType","p_adminRoles":"admin",
  "p_readerRoles":"staff","p_readerActions":"GET, HEAD"}'

curl -sk "$BASE/admin-api/xacml/policies" -H "Authorization: Bearer $TOKEN" |
  jq '{root, policies: [.policies[] | {name, enabled, problems}]}'
```

Each parameter is sent as `p_<name>`; anything left out takes the template's
default. `GET /admin-api/xacml/policies` lists the templates and their
parameters under `templates`.

**The eight templates:**

| `template` | Console label | What it builds |
|---|---|---|
| `rbac` | Role-based (RBAC) | one Permit rule per role value of a subject attribute; deny-unless-permit |
| `abac` | Attribute-based (ABAC) | one Permit rule on a resource, its actions and subject attribute tests (`p_resource`, `p_actions`, `p_subjectAttribute`, `p_subjectValue`, `p_clearanceAttribute`, `p_clearanceMinimum`) |
| `blank` | Blank (for the brave) | an empty Policy, or a PolicySet with `p_kind=policyset`. **It denies everything** until you add a rule, so build it before you make it the root |
| `role-issuance` | Role-based issuance (this service's own) | the issuance policy, as an override (below) |
| `access-control` | Access control (this service's own) | the access policy, as an override |
| `risk-response` | Risk response (this service's own) | what a change of a person's risk level leads to |
| `signal-response` | Signal response (received CAEP and RISC events) | what a verified CAEP or RISC event leads to |
| `fga-default` | Application fine-grained authorization (default) | one Permit rule with no Target, PolicyId derived from `p_application`; the policy every application is created with ([fine-grained authorization](fga.md)) |

The [remote PEP's worked example](remote-pep.md#2-deploy-the-policy-at-the-pap)
uses the `abac` template to protect one application.

## Import a policy written in ALFA

ALFA is a short syntax for the same policy. It is parsed, converted and
stored as XACML XML. **Every attribute must be declared before it is used**;
a typo is refused rather than silently matching nothing. The policy below is
`tests/xacml_alfa.js`'s hand-written one: staff or admins may GET, if their
`clearanceLevel` is at least 3.

**Console:** on the **Policies** tab, under **Import ALFA**, set **Name** to
`alfa-import`, paste the policy into the text box, and click **Import**.

**API:**
```bash
ALFA='namespace example {
    attribute role {
        category = subjectCat
        id = "employeeType"
        type = string
    }
    attribute clearance {
        category = subjectCat
        id = "clearanceLevel"
        type = integer
    }
    attribute act {
        category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"
        type = string
    }

    policy handWritten {
        id = "urn:test:hand-written"
        apply denyUnlessPermit
        rule cleared {
            permit
            target clause role == "staff" or role == "admin"
            target clause act == "GET"
            condition integerGreaterThanOrEqual(
                integerOneAndOnly(clearance), 3)
        }
    }
}'
jq -n --arg a "$ALFA" '{name:"alfa-import", alfa:$a}' |
  curl -sk -X POST "$BASE/admin-api/xacml/import-alfa" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary @-
```

`name` is the directory entry; `id = "…"` is the PolicyId inside the
document. ALFA that does not parse is refused and nothing is written. To read
a stored policy back as ALFA, open it on the **Policy editor** tab (**The same
policy as ALFA**) or read `alfa` from `GET /admin-api/xacml/editor?policy=<name>`.

**There is no upload of XACML XML** through the console or the API. A
document written in XML goes in through the template forms, ALFA, or the
editor. The repository *is* `ou=policies` in the embedded directory, so an
`ldapmodify` of an entry's `xacmlPolicyDocument` also changes what the PDP
decides; it is validated the same way.

## Edit a policy, and choose which one decides

**Console:**
* **Policy editor** tab: pick the policy and click **Open**. Each element has
  **Add** and **Remove** controls offering only what XACML allows there; an
  edit that would not type-check is refused and the stored document is left
  as it was. **Editing is live**: there is no draft, so the next decision
  uses the change.
* **Policies** tab: **Disable** takes a policy out of the decision without
  deleting it, **Make root** makes it the one the PDP starts from (the old
  root stops being root), and **Delete** removes it. Deleting the root leaves
  the repository deciding nothing until another policy is made root.

**API** (the PAP actions take `name`, the directory entry):
```bash
api xacml/disable  '{"name":"rbac-under-test"}'
api xacml/enable   '{"name":"rbac-under-test"}'
api xacml/set-root '{"name":"alfa-import"}'
api xacml/delete   '{"name":"alfa-import"}'
```

The editor's actions (`add-rule`, `add-match`, `add-condition`,
`add-rule-obligation`, `edit-policy` and the rest) are
`POST /admin-api/xacml/<action>` too. `GET /admin-api/xacml/editor?policy=<name>`
returns the policy as a tree in which each node lists the additions allowed
at that point; the request bodies are in the OpenAPI document. The
disable/enable pair is what `sts_xacml_editor.js` drives.

**Settings** (console: the **Global settings** tab):

| Setting | Default | Why you would change it |
|---|---|---|
| `xacml.enabled` | `true` | Off makes every `/xacml` endpoint answer 501. The repository is untouched. |
| `xacml.maxPolicies` | `200` | How many policies `ou=policies` may hold. |
| `xacml.returnPolicyIdList` | `false` | Returns the list of applicable policies even when a request does not ask. |

---

# Asking for a decision

## Admit a caller to `/xacml`

Every `/xacml` endpoint requires a client certificate, checked four ways:
the certificate verifies against the truststore, it resolves to a directory
entry — a certificate from your own CA is **stored byte for byte in that
entry's `userCertificate`** and on no other entry ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority)); its common name
and subject are never read — the entry holds the role the endpoint needs, and
the access policy permits it. There are two roles, each granted by a group:

| Endpoints | Role | Group (setting) |
|---|---|---|
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` | `XACML_USER` | `xacml-users` (`roles.xacmlUserGroup`) |
| `/xacml/pep/register`, `/xacml/pep/policies`, `/xacml/pep/heartbeat`, `POST /xacml/pip` | `REMOTE_PEPS` | `remote-peps` (`roles.remotePepGroup`) |

Taken from `sts_xacml_endpoints.js` and `sts_xacml_editor.js`, which use the
common name `xacml-user-1` in the realm's `xacml-users` group.

**Console:**
1. **Protocols → Client-certificate truststore**: under
   **Add anchors**, paste the PEM of the CA that issued the caller's
   certificate and click **Trust these**. The truststore is service-wide.
2. **Directory → Users**: make sure there is an entry for the caller. In
   development mode `xacml-user-1` is seeded; in product mode create it. Its
   name need not match anything in the certificate.
3. On that person's page, under **Stored certificates**, paste the caller's
   leaf certificate (PEM) and click **Store**. A certificate stored on no
   entry is refused (`STS-XACML-0177`), and one stored on two entries too
   (`STS-XACML-0178`). A renewed certificate is stored again.
4. **Directory → Groups → xacml-users**: under **Add a member**, enter the
   entry and click **Add**.

**API:**
```bash
jq -n --rawfile pem ca.crt '{certificates:$pem}' |
  curl -sk -X POST "$BASE/admin-api/tls/trust/add" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' --data-binary @-

# product mode only: the entry is not seeded
api users/create '{"username":"xacml-user-1","invent":false,
  "attributes":{"cn":"xacml-user-1","givenName":"XACML","sn":"User",
                "mail":"xacml-user-1@example.test"}}'

# both modes: the leaf, stored on the entry it is to resolve to
api users/add-certificate "$(jq -n --rawfile pem user.crt \
  '{user:"xacml-user-1", certificate:$pem}')"

api groups/add-member '{"group":"xacml-users","member":"xacml-user-1"}'
```

A runtime anchor is written to `ou=trustAnchors` in the default realm, so it
survives a restart wherever the directory is persisted; `tls.trustAnchorsFile`
names a PEM file read at startup instead. To mint a test certificate and
post its anchor in one step, use `tests/tools/pep-credential.js` as
[Remote PEP → Minting the certificate](remote-pep.md#minting-the-certificate)
shows, with `--subject="CN=xacml-user-1,OU=xacml-users,O=…"`; it posts the
anchor through `/admin-api/tls/trust/add`, so it needs `STS_ADMIN_API_TOKEN`
set to a token. It does not store the leaf: store it as above. `user.crt`
must hold the leaf alone (the first block of what the tool writes).

A certificate that verifies, for an entry outside the group, is refused, and
the refusal says the certificate itself was fine. Membership takes effect on
the caller's next request. Setting `roles.xacmlUserGroup` (or
`roles.remotePepGroup`) to empty closes those endpoints to everyone without
turning `xacml.enabled` off.

## Ask the PDP: `POST /xacml/pdp`

A JSON Profile 1.1 request in, a JSON Profile response out. The request below
is `sts_xacml_endpoints.js`'s, sent with the `xacml-user-1` certificate. It
names only the subject: the PDP asks the PIP for `employeeType`, so with the
RBAC policy above the admin person may DELETE and the staff person may only
GET or HEAD.

```bash
curl -sk --cert user.crt --key user.key \
  -H 'content-type: application/json' -X POST "$BASE/xacml/pdp" -d '{
  "Request": {
    "AccessSubject": {"Attribute": [
      {"AttributeId": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
       "Value": "xacml-staff-person"}]},
    "Action": {"Attribute": [
      {"AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
       "Value": "DELETE"}]},
    "Resource": {"Attribute": [
      {"AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
       "Value": "https://example.test/records", "DataType": "anyURI"}]}
  }}' | jq '.Response[0].Decision'
# "Deny"
```

The two people the job decides about are created like this; `employeeType`
is the attribute the policy reads:

```bash
api users/create '{"username":"xacml-staff-person","invent":false,
  "attributes":{"cn":"XACML Staff Person","givenName":"XACML","sn":"Staff Person",
                "mail":"xacml-staff-person@xacml-endpoints.test","employeeType":"staff"}}'
```

A malformed request is a 400, never an Indeterminate. A person the
directory does not know has no `employeeType`, so the PIP returns an empty
bag and deny-unless-permit answers Deny. In a trust realm the path is
`/realm/<id>/xacml/pdp`.

## Try a decision without a certificate

The console's what-if asks the same PDP about a subject you name, and shows
both what the PDP decided and what a deny-biased and a permit-biased PEP
would do with it. It is not counted as an enforcement.

**Console:** on the **Try a decision** tab, fill in **Subject**
(`xacml-staff-person`), **Action** (`DELETE`) and, optionally, **Resource**,
and click **Ask the PDP**.

**API** (from `sts_xacml_endpoints.js`):
```bash
curl -sk "$BASE/admin-api/xacml/decide?subject=xacml-staff-person&action=DELETE" \
  -H "Authorization: Bearer $TOKEN" | jq '{decision, enforcements}'
```

## The PIP over HTTP: `POST /xacml/pip`

A remote PEP holds the engine but not the directory. `POST /xacml/pip`
resolves the attributes its request did not carry. It takes the
`REMOTE_PEPS` role, not `XACML_USER`, because what it returns is a person's
directory data. Request and response are XACML's own XML in a two-element
envelope. Taken from `sts_xacml_endpoints.js`:

```bash
curl -sk --cert pep.crt --key pep.key -X POST "$BASE/xacml/pip" --data-binary @- <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<PIPRequest xmlns="urn:sts:xacml:pip:1.0">
  <Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
           CombinedDecision="false" ReturnPolicyIdList="false">
    <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
      <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" IncludeInResult="true">
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">xacml-admin-person</AttributeValue>
      </Attribute>
    </Attributes>
  </Request>
  <AttributeDesignator xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
    Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
    AttributeId="mail" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/>
  <AttributeDesignator xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
    Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
    AttributeId="employeeType" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/>
</PIPRequest>
EOF
```

The answer is a `<PIPResponse>` holding `<Attributes>` in the XACML core
namespace, ready to splice into a request, and an `<Unresolved>` element in
this service's namespace saying why any bag came back empty. Only the
access-subject category is resolved. Nothing needs configuring for the
attributes; the limits are:

| Setting | Default | What it does |
|---|---|---|
| `xacml.pipMaxDesignators` | `50` | The most designators one query may name. |
| `xacml.pipMaxPerWindow` | `600` | Queries per PEP and per address in one `security.rateLimitWindowS` window. |
| `xacml.remotePeps` | `true` | Off makes `/xacml/pep/*` **and** `POST /xacml/pip` answer 501. |

---

# The remote PEP container

## Run the container against a realm

[Remote PEP](remote-pep.md) covers the container in full. What the service
needs is the same admission as above, with the `remote-peps` group. The
values are `sts_xacml_remote_pep.js`'s.

**Console:**
1. Trust the PEP certificate's CA on the **Client-certificate truststore**
   page, as above.
2. **Directory → Users**: create an entry for the PEP (`remote-pep-1` is
   seeded in development mode), and under **Stored certificates** on its page
   store the PEP's leaf certificate. Until it is stored the PEP is refused
   (`STS-XACML-0179`; `0180` when it is stored on two entries).
3. **Directory → Groups → remote-peps**: **Add a member** with that entry.
4. Create the policy the PEP will enforce and make it root, as in
   [Create a policy from a template](#create-a-policy-from-a-template).

**API:**
```bash
api users/create '{"username":"my-pep","invent":false,
  "attributes":{"cn":"my-pep","givenName":"Remote","sn":"Remote PEP",
                "mail":"my-pep@xacml-remote-pep.test","displayName":"my-pep"}}'
api users/add-certificate "$(jq -n --rawfile pem pep-leaf.crt \
  '{user:"my-pep", certificate:$pem}')"
api groups/add-member '{"group":"remote-peps","member":"my-pep"}'
```

`pep-leaf.crt` is the leaf alone: `pep.crt` from `pep-credential.js` is the
leaf followed by its Issuing CA, and only the leaf is stored.

`my-pep` stands for the job's per-run name. Then start the container with
the certificate mounted:

```bash
PEP_PDP_URL=https://localhost:8081/realm/<id>   # omit /realm/<id> for the default realm
PEP_TLS_CERT=/certs/pep.crt PEP_TLS_KEY=/certs/pep.key
PEP_RESOURCE=https://example.test/records PEP_BIAS=deny-biased
PEP_TLS_INSECURE=true                            # development: the service's Root changes every start
PEP_NOTIFY_URL=https://my-pep.example.test:9443/notify   # optional: where the nudge goes
```

The PEP registers itself (`POST /xacml/pep/register`), and its row appears on
the **Remote PEPs** tab with whether it holds the current policy. **The row
is named from the entry the certificate is stored on**, not from
`PEP_NAME`, when a certificate is presented. A PEP enforces whether or not it is registered;
the registration buys the row and the nudge.

## Issue the PEP an HTTPS listener certificate

**Console:** on the **Remote PEPs** tab, click **Issue certificate** on the
PEP's row (**Reissue certificate** once it has one).

**API:**
```bash
api xacml/issue-pep-certificate '{"name":"remote-pep-1","dnsNames":["pep.example.test"]}' > issued.json
```

`dnsNames` and `ipAddresses` are added to the names taken from the
registration. **The private key is in this reply and nowhere else.** Write
`fullChainPem` and `privateKeyPem` to the paths in `PEP_HTTPS_CERT` and
`PEP_HTTPS_KEY`; [Remote PEP → An HTTPS listener](remote-pep.md#an-https-listener-certified-by-the-realm-it-registered-to)
has the steps.

## Stop nudging, or forget a PEP

**Console:** **Stop nudging** / **Nudge**, and **Forget**, on the PEP's row.
A PEP you stop nudging keeps enforcing, on its own poll.

**API:**
```bash
api xacml/disable-pep '{"name":"remote-pep-1"}'
api xacml/enable-pep  '{"name":"remote-pep-1"}'
api xacml/forget-pep  '{"name":"remote-pep-1"}'
```

**Settings** for the register and the nudge:

| Setting | Default | Why you would change it |
|---|---|---|
| `xacml.pepRequireCertificate` | `true` | Off lets a PEP register without a certificate; its row is marked unauthenticated. The pull still needs the role. |
| `xacml.maxPeps` | `50` | How many PEPs `ou=peps` may hold. |
| `xacml.pepStaleAfterS` | `300` | When the console calls a PEP stale. |
| `xacml.pepNotify` | `true` | Off stops nudging; PEPs converge on their poll. |
| `xacml.pepNotifyAllowedHosts` | *(empty: any)* | Hosts a nudge may go to. |
| `xacml.pepNotifyCaFile` | *(empty)* | CA certificates a PEP's notify listener may chain to. |
| `xacml.pepNotifyAllowHttp` | `false` | **Development only.** Allows an `http://` notify URL, which the compose demonstration uses. |
| `xacml.pepNotifyTimeoutMs` | `2000` | How long a nudge waits. |

---

# This service's own policies

Four built-in policies decide for this service itself, each named by a
setting. They are **built in and called, not seeded**, so every realm has
them, and none is ever sent to a remote PEP.

| Setting | Default name | Decides |
|---|---|---|
| `xacml.issuancePolicy` | `role-issuance` | every issuance: sessions, tokens, assertions, tickets; which scopes, GNAP rights and delegations are issued |
| `xacml.accessPolicy` | `access-control` | who reaches the console, the management API, the user portal, SCIM, the SPIRE Server API and the debugger |
| `xacml.riskResponsePolicy` | `risk-response` | what a change of a person's risk level leads to |
| `xacml.signalResponsePolicy` | `signal-response` | what this service's console and portal do with a CAEP or RISC event they receive |

## Require a role to use an application

The issuance policy refuses a person who holds none of the roles an
application requires. This is configuration on the entries, not an edit to
the policy. Taken from `sts_roles.js`.

**Console:**
1. **Directory → Roles**: under **Make a role**, set **Name** to `staff`
   and **Description** to `Works here`, and click **Create**.
2. Under **Give a person, a group or an application a role**, give `staff`
   to `roles-holder` (kind user), and click **Add**.
3. On the application's page, **Roles** tab, under **Roles a person must
   hold to use it**, pick `staff` and click **Require**.
4. Check it on **Directory → Roles**, under **Would this be issued?**: enter
   the **Subject**, pick the application under **Issuing**, and click **Ask**.

**API:**
```bash
api roles/create-role '{"role":"staff","description":"Works here"}'
api roles/add-member  '{"role":"staff","kind":"user","member":"roles-holder"}'
api applications/add  '{"application":"roles-narrowed-app","attribute":"appRequiredRole","value":"staff"}'
curl -sk "$BASE/admin-api/roles" -H "Authorization: Bearer $TOKEN" | jq .requiring
```

`kind` is `user`, `group` or `application`. A required role nothing defines
is listed under `unknown`, and refuses everybody. Issued tokens carry the
roles a person holds in the `roles` claim (`roles.claim`,
`roles.claimName`). `roles.enforceIssuance` off issues everything.

## Override a built-in policy in one realm

To change what one of the four decides, write a repository entry with the
name its setting holds. It overrides the built-in policy in that realm only;
delete it and the built-in policy answers again.

**Console:** on the **Policies** tab, under **What this service decides its
own boundaries with**, click **Create an override** on the **Issuance** or
**Access control** row. It is created from that policy's own template under
the name the setting uses, and then opens with **Edit it** in the
**Policy editor** tab. The risk-response and signal-response policies are
created from their templates under **Create from a template**, with **Name
for the policy** left as the template's id.

**API:**
```bash
api xacml/create-from-template '{"template":"role-issuance","name":"role-issuance"}'
api xacml/create-from-template '{"template":"risk-response","name":"risk-response"}'
```

Read these before editing one:
* **Start from the template, not from an empty document.** An override
  replaces the built-in document for the main decision. A document without the
  role rules refuses (or permits) every issuance in the realm. The scope,
  GNAP-right, transfer, passkey and delegation questions fall back to the
  built-in policy only where the override gives no verdict on them.
* **A disabled override does not fall back.** The issuance PEP then has no
  policy: an application that requires only `EVERYBODY` is issued to, and one
  that requires any other role is refused.
* **Pointing the setting at another name works too.**
  `sts_gnap_catalogue.js` imports an ALFA policy as `cat-narrow` and sets
  `xacml.issuancePolicy` to `cat-narrow` in its throwaway realm. Its last rule
  permits everything, which is only right in a test realm.

The template parameters switch whole groups of rules off: `decideScopes`,
`decideGnapRights`, `decideTransfers`, `decidePasskeys`, `decideExchanges`,
`decideRisk` and others, each `yes` or `no`. Where a group is left out, the
built-in policy answers that question instead. `GET /admin-api/xacml/policies`
lists them with their help text.

**Settings:**

| Setting | Default | Why you would change it |
|---|---|---|
| `xacml.enforceAccess` | `true` | Off stops the gated surfaces asking the access policy. The roles the console and SCIM check underneath still apply. |
| `roles.enforceIssuance` | `true` | Off issues everything without asking the issuance policy. |

---

# The delegation policy

Who may act for whom, at an RFC 8693 token exchange, a WS-Trust `OnBehalfOf`
/ `ActAs` and a Kerberos S4U request, is decided by the issuance policy
(#186). You configure it with directory attributes and three settings; you
do not need to edit a policy. [Delegation](delegation.md) has every attribute
and the order the refusals are checked in.

## Let one application hand a subject on to another

Taken from `sts_delegation_policy.js`: `dp-mid` (S) may delegate to
`dp-back` (R), `dp-back` accepts `dp-mid2` and the person `dp-carol` acting
for others, and `dp-mid2` may use both semantics. Each application is a
confidential OAuth client declared for `oauth2`, `oidc` and `wstrust`, with
`oauthAudience` and `wstrustAppliesTo` set to `https://<identifier>.example`.

**Console:** on each application's page, under the **Delegation /
Impersonation** heading of its fields, fill in the attributes below and save.
The search beside `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf` and
`appDelegationSubjectGroup` finds applications and groups by name.

| Application | Attribute | Value |
|---|---|---|
| `dp-mid` | `appAllowedToDelegateTo` | `dp-back` |
| `dp-back` | `appAllowedToActOnBehalfOf` | `dp-mid2`, `dp-carol` |
| `dp-back` | `appAllowedToDelegateTo` | `dp-final` |
| `dp-mid2` | `appDelegationSemantics` | `delegation`, `impersonation` |

**API:**
```bash
api applications/add '{"application":"dp-mid","attribute":"appAllowedToDelegateTo","value":"dp-back"}'
api applications/add '{"application":"dp-back","attribute":"appAllowedToActOnBehalfOf","value":"dp-mid2"}'
api applications/add '{"application":"dp-back","attribute":"appAllowedToActOnBehalfOf","value":"dp-carol"}'
api applications/add '{"application":"dp-mid2","attribute":"appDelegationSemantics","value":"impersonation"}'
```

The job sets these as `fields` on `applications/create` instead. The token
exchange it then sends is:

```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  &client_id=dp-mid&client_secret=<secret>
  &subject_token=<a token about the subject>
  &subject_token_type=urn:ietf:params:oauth:token-type:jwt
  &audience=https://dp-back.example&scope=api
```

## Let a person be the actor

A **person** may act for somebody only while holding the role
`delegation.actorRole` names, `DELEGATION_ACTOR` by default. An application
needs no role. From `sts_delegation_policy.js`:

**Console:** **Directory → Roles**: make the role `DELEGATION_ACTOR`, then
give it to `dp-carol` (kind user).

**API:**
```bash
api roles/create-role '{"role":"DELEGATION_ACTOR"}'
api roles/add-member  '{"role":"DELEGATION_ACTOR","kind":"user","member":"dp-carol"}'
```

## Protect people from being acted for

**Console:**
* For one person: **Directory → Users**, the person's page, **Who may act
  for them**. The not-delegated control writes `stsNotDelegated`; **Set who
  may act for them** writes `stsMayAct` (a **Delegate DN**, empty clears it).
* For a group: **Protocols → Delegation**, set `delegation.protectedGroups`
  to the group's cn or DN, and click **Save Delegation**. The console's
  Admin Read and Admin Write rosters are always protected.

**API:**
```bash
api users/set-not-delegated '{"user":"alice","value":true}'
api users/set-may-act '{"user":"alice","delegate":"uid=bob,ou=users,dc=example,dc=com"}'
api users/set-delegation-semantics '{"user":"alice","semantics":"delegation"}'
api config/set '{"key":"delegation.protectedGroups","value":"dp-protected"}'
```

`alice`, `bob` and the DN are the OpenAPI document's examples; `dp-protected`
is `tests/delegation_policy.js`'s group.

**Settings** (console: **Protocols → Delegation**):

| Setting | Default | Why you would change it |
|---|---|---|
| `delegation.defaultSemantics` | `delegation` | Makes `impersonation` the default where nothing else names one. |
| `delegation.protectedGroups` | *(empty)* | Groups whose members are never acted for, in any protocol. |
| `delegation.actorRole` | `DELEGATION_ACTOR` | The role a person needs to be an actor. |
| `delegation.maxRecords` | `2000` | How many acts **Monitoring → Delegation** keeps. |

**Product mode refuses; development mode issues** and records the act as
"WOULD HAVE BEEN REFUSED in product". A `may_act` that names somebody else,
and a WS-Trust request carrying both `OnBehalfOf` and `ActAs`, are refused in
both modes. The configured pairs are listed at
`GET /admin-api/delegation/policy`, and the acts at `GET /admin-api/delegation`
(`?outcome=refused` for the refusals).

## A rule of your own

A realm's issuance policy is asked first, and the built-in rules answer any
exchange it says nothing about. To refuse more, add a Deny rule on action-id
`exchange-token` carrying the obligation `urn:sts:xacml:obligation:exchange`
with `urn:sts:xacml:exchange-verdict` = `refuse`,
`urn:sts:xacml:exchange-refusal` = `policy` and
`urn:sts:xacml:exchange-enforced` = `true`. The actor is in the
`urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject`
category. `tests/delegation_policy.js` (section I) refuses every exchange
whose actor's `subject-id` is `dp-front` this way, and the client then hears
its protocol's policy refusal.

Add the rule to an override made from the `role-issuance` template (see
[Override a built-in policy](#override-a-built-in-policy-in-one-realm)), in
the **Policy editor**: add a rule with effect Deny, two matches in its
target, and a rule obligation with the three assignments. The test writes
the rule as a policy of its own and points `xacml.issuancePolicy` at it for
the exchange questions alone; in a realm that issues anything else, that
document would refuse every other issuance.

---

# Watching it

* **Monitoring → XACML decisions** (`GET /admin-api/xacml/monitor`):
  decisions and enforcements for the issuance and access PEPs, every remote
  PEP and `POST /xacml/pdp`. The counters start with the process.
* **The audit log** (`/admin/audit`): `xacml.access.refused`,
  `xacml.issuance.refused`, `xacml.policy.write`, `xacml.policy.delete` and
  `xacml.pip.query`.
* **Monitoring → Delegation** (`/admin/delegation`): every act, allowed or
  refused, and what decided it.
* Every failure is recorded under an `STS-XACML-NNNN` code; see
  [error codes](error-codes.md).

## Related

* [XACML 3.0 and ALFA](xacml.md): every feature and setting, and why.
* [Remote PEP](remote-pep.md): the container, with a worked example.
* [Delegation](delegation.md): the parties, the attributes and the order of refusals.
* [Risk scoring](risk-scoring.md) and [Signals received](signals-received.md): what the risk-response and signal-response policies decide.
* [TLS and mutual TLS](tls.md): the truststore behind the gate.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md), [Configuring GNAP](configure-gnap.md) and [Configuring Shared Signals](configure-shared-signals.md).
