---
title: XACML
---

# XACML 3.0 and ALFA

iya-sts contains a **XACML 3.0 Policy Decision Point**
([OASIS XACML 3.0 core](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)).
It accepts requests in the
[JSON Profile 1.1](https://docs.oasis-open.org/xacml/xacml-json-http/v1.1/xacml-json-http-v1.1.html),
and it reads and writes policies as XACML XML and as
[ALFA](https://docs.oasis-open.org/xacml/alfa-for-xacml/v1.0/alfa-for-xacml-v1.0.html).
Around the PDP it has a policy repository (the PAP), a Policy Information
Point backed by the embedded directory, a guided policy editor, and three
**embedded** enforcement points. Two of those embedded PEPs decide this
service's own token issuance and its own access control. It also supplies
policy to **remote** PEPs that run in other processes. Every trust realm has
its own repository, its own register of remote PEPs and its own counters.

Every other protocol family here authenticates or provisions someone. This one
is given a subject that was authenticated elsewhere and asked whether that
subject may do something.

## Features

### The engine, held to the OASIS conformance suite

The engine evaluates the XACML 3.0 core, apart from XPath (see *Not
implemented*):

* the seventeen datatypes and the standard function library, including the
  higher-order functions;
* targets, rules, conditions and variable definitions;
* all twelve combining algorithms;
* obligations and advice;
* policy and policy-set references;
* all seven decisions, including `Indeterminate{P}`, `{D}` and `{DP}`.

A policy that does not typecheck is **refused when it is loaded**, not
evaluated to Indeterminate on every request.

The engine passes **454 of the 455 mandatory cases** of the vendored OASIS
conformance suite. The one exception is `IIE003`, a policy-reference case,
which the suite's manifest records and explains. The suite is Apache-2.0
licensed, unlike this repository.

### Asking for a decision

| Path | What it does |
|---|---|
| `GET /xacml` | describes the surface, including which role each endpoint requires. `?format=json` returns the same as data |
| `POST /xacml/pdp` | a decision: a JSON Profile request in, a JSON Profile response out |
| `GET /xacml/policies` | the repository as the PDP sees it, with the policy documents |
| `GET /xacml/protected` | the demonstration PEP: 200 or 403 for the `?subject=` you name |

In a trust realm every path is under `/realm/{id}`. A malformed request gets a
400, never an Indeterminate. `xacml.returnPolicyIdList` returns the list of
policies that applied, even when the request did not ask for it.

**A PDP is not an authorization boundary.** The subject the decision is about
is in the request. The identity on the connection only decides who may *ask*,
and it never reaches the decision.

### The policy repository (`ou=policies`)

The repository **is** `ou=policies` in the embedded directory. There is no
separate copy. That means policies persist in every persistence mode, each
trust realm has its own repository, and `ldapsearch` or
`/admin/ldap/policies` can inspect them. Each entry holds the document exactly
as it was written, and every write is statically validated first.

A policy can be enabled, disabled without being deleted, deleted, or made the
**root**, which is the policy the PDP starts from. The default realm is seeded
with one role-based policy, `seeded-rbac`. It grants on the `employeeType`
attribute that the seeded people carry: alice and bob are staff, and carol is
an admin. **A new realm's repository starts empty**, and a PDP with an empty
repository answers NotApplicable to everything.

New policies come from five templates: **RBAC**, **ABAC**, this service's own
two (`role-issuance` and `access-control`), and **blank**, an empty `Policy` or
`PolicySet`. A blank `deny-unless-permit` policy **denies everything**, and
the console says so wherever you meet one. You can also import a policy
written in ALFA.

### ALFA

ALFA is a third rendering of the same model. Forty lines of XML become about
eight lines of ALFA:

```
policy staffAccess {
    apply denyUnlessPermit
    rule allowStaff {
        permit
        target clause employeeType == "staff" and actionId == "GET"
    }
}
```

ALFA is an OASIS Committee Specification Draft, not a ratified standard, so
this service makes one promise about it: **anything the emitter writes, the
parser reads back, and the policy decides the same way either way**. ALFA is a
**view**. An imported policy is stored as XACML XML, and the editor renders
the ALFA from that. Where ALFA is vague, this dialect is strict:

* literals of the thirteen datatypes that have no native ALFA syntax are
  typed, for example `date("2026-01-01")`;
* the three target levels map onto `clause`, `or` and `and`;
* **an attribute has to be declared before it is used**. Without this rule, a
  typo in an attribute name gives a policy that silently matches nothing.

A round trip through ALFA changes one thing: a legacy 1.0 or 1.1 combining
algorithm comes back as its 3.0 equivalent.

### The Policy Information Point

The PIP resolves attributes in the access-subject category from **the
subject's own entry in the embedded directory**. A policy can ask about any
attribute the entry holds, such as a title, a department or a group, and
nothing has to be configured first. An attribute that is missing gives an
**empty bag**, never an error and never an invented value. `employeeType` is
answered under its bare name and under `urn:sts:xacml:attribute:employeeType`.

**`POST /xacml/pip`** makes the same PIP available over HTTP, so that a remote
PEP decides with the same attributes the embedded PDP would use. The request
and the response are both **XACML's own XML**, inside a two-element envelope:

```
REQUEST   <PIPRequest xmlns="urn:sts:xacml:pip:1.0">
            <Request …/>                  the request being decided; it names the subject
            <AttributeDesignator …/>      one per attribute wanted
          </PIPRequest>

RESPONSE  <PIPResponse xmlns="urn:sts:xacml:pip:1.0">
            <Attributes Category="…">     XACML core namespace, ready to splice into a request
            <Unresolved>…</Unresolved>    this service's namespace: why a bag came back empty
```

The `<Attributes>` in the response are a request fragment. A PEP can splice
them into its own request, and they are written `IncludeInResult="false"`. An
empty bag is an **absent** `<Attribute>`. `MustBePresent` is read but not
applied here, because the caller's engine is the one that decides what an
empty bag means. `<Unresolved>` gives the reason for each empty bag in this
service's own namespace, where a PEP reading only XACML never sees it. A query
names at most `xacml.pipMaxDesignators` designators, is rate-limited by
`xacml.pipMaxPerWindow`, and is audited as `xacml.pip.query`. Nothing is
cached, so each decision makes a fresh query.

### The embedded PEPs: this service's own issuance and access

Four PEPs are built into the process:

| PEP | Decides | Policy |
|---|---|---|
| **issuance** | every one of the nine kinds of issuance: session, access token, ID token, refresh token, authorization code, SAML assertion, WS-Federation token, WS-Trust token and Kerberos ticket | `xacml.issuancePolicy` (`role-issuance`) |
| **access** | who may reach the admin console, the management API, the User Portal, SCIM, the SPIRE Server API, the embedded debugger and the `/xacml` surface | `xacml.accessPolicy` (`access-control`) |
| **risk response** | what happens when a person's risk level changes: a CAEP announcement, ending everything they hold, a RISC credential-compromise, disabling the account — one question per reaction, a Permit meaning do it ([Risk scoring](risk-scoring.md#when-a-persons-risk-changes)) | `xacml.riskResponsePolicy` (`risk-response`) |
| **demonstration** | `GET /xacml/protected` | the repository root |

The issuance PEP builds a request in which the subject is the party being
authenticated (in a `client_credentials` grant, that is the client). The
request carries the roles the subject holds and any roles found in a token it
presented (the claim named by `roles.claimName`). The resource is the
application, with the roles it requires, and the action is the kind of
issuance. **Nothing else in the service tests roles.** The reason someone was
refused is always a document that you can read, edit, try out and find in the
audit log.

**The request also carries the RISK of the authentication** the issuance
rests on, as four environment attributes (`urn:sts:xacml:risk-level`,
`-score`, `-signal` and `-satisfied`), and the built-in `role-issuance`
policy decides on it in the same evaluation: HIGH is refused, and MEDIUM is
refused until the authentication carries a second factor or, for a signal
about the device, a security key. A risk rule's Deny carries the obligation
`urn:sts:xacml:obligation:risk`, which says whether to refuse or step up and
with what; the doors that can ask a person for that factor do. Product mode
enforces a risk Deny, and development mode records it and lets the issuance
through. [Risk scoring](risk-scoring.md#how-a-score-decides) has the rules and
how to change them.

The three service policies are **built in and called directly, not seeded**. The
same built-in document applies in every realm. A realm that wants something
different writes a repository entry with the name in the setting, and that
override applies only to its own realm. Delete the entry and the built-in
document is used again. **These two policies are never sent to a remote
PEP.**

When there is no issuance policy to decide with, the answer depends on the
application:

* An application that requires only `EVERYBODY`, which is the default for
  every application, is **allowed**. Refusing would lock everyone out,
  including the administrator who needs to restore the policy.
* An application that requires any other role is **refused**. Someone asked
  for that restriction, and silently allowing it would be the worst failure
  this feature could have.

A Deny, NotApplicable or Indeterminate always refuses an issuance.
`xacml.pepBias` does not apply to the issuance PEP.

### The gated surfaces: two roles, two groups

Every `/xacml` endpoint requires a client certificate on the main port. A
caller is admitted through a chain of four checks:

1. the certificate is **verified** against this service's truststore;
2. its subject DN resolves to a **directory entry**;
3. that entry holds the **role** the endpoint requires;
4. the **access policy** permits it.

| Endpoints | Role | Group |
|---|---|---|
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies`, `GET /xacml/protected` | `XACML_USER` | `roles.xacmlUserGroup` (`xacml-users`) |
| `POST /xacml/pep/register`, `GET /xacml/pep/policies`, `POST /xacml/pep/heartbeat`, `POST /xacml/pip` | `REMOTE_PEPS` | `roles.remotePepGroup` (`remote-peps`) |

**The certificate says who the caller is, and the group says whether they get
in.** A valid certificate for an entry outside the group is refused, and the
refusal says the certificate itself was fine. There are **two** groups because
the second set of endpoints hands out the documents this service enforces its
own access with, and a named person's directory attributes. Admitting a caller
to the demonstration endpoints must not admit it to those. `POST /xacml/pip`
is outside `/xacml/pep/`, but it takes the narrower role because what it
returns is personal data. A person is given a role by being added to the
group, and that takes effect on their next request.

### The remote PEPs' PDP side

A remote PEP holds its own copy of the engine and decides in its own process.
[Remote PEP](remote-pep.md) documents the container. On this side:

* **The PEP pulls; this service does not push.** `GET /xacml/pep/policies`
  returns the enabled policies and which one is the root, along with a **sync
  token**. The token is a digest of exactly what would be sent. Editing a
  policy and then editing it back changes nothing. Disabling a policy moves
  the token. So does a change made through any route, including
  `ldapmodify`.
* **Registration** (`POST /xacml/pep/register`) gives the PEP a row in
  `ou=peps`, named from its client certificate. A PEP that registers again
  keeps its counters and its disabled flag. **Registering is not a
  permission**: an unregistered PEP can pull and enforce just as well. A
  registration made without a certificate, which `xacml.pepRequireCertificate`
  off allows, is marked unauthenticated.
* **Heartbeats** (`POST /xacml/pep/heartbeat`) report the PEP's own
  cumulative counts. They *set* the row's counters rather than add to them, so
  a PEP that restarts makes its row go down.
* **The nudge.** When the repository changes, the service POSTs a small
  notice to every registered PEP that gave a notify URL: something changed,
  pull now. The notice carries no policy and no token, so losing one only
  costs a polling interval. It is limited in the same way as Shared Signals
  push: an on/off switch, a host allowlist, https only, and a timeout.
* **An HTTPS listener certificate.** A registered PEP can be issued a
  `serverAuth` key pair from its realm's `pep-tls` Issuing CA. The private key
  appears in one reply and is never stored.

### Not implemented

* **`AttributeSelector` and the XPath functions are not evaluated.** A policy
  that uses one is **Indeterminate**, not silently empty. The editor can still
  build selectors and keeps their namespace bindings.
* **`<PolicyIssuer>`** (the administrative delegation profile) is not
  implemented. `MaxDelegationDepth` is kept on the policy, but nothing reads
  it.
* **The editor offers no way to add combiner parameters.** None of the twelve
  standard algorithms takes one. Parameters that arrive in a document are
  shown and can be removed.
* **Variable names may not contain a dot.** The editor uses dots to address
  elements.
* **The PIP does not cache.**

## Development and product mode

| | Development | Product |
|---|---|---|
| The two XACML role groups | seeded with demonstration members (`remote-pep-1` in `remote-peps`, `xacml-user-1` in `xacml-users`) | exist, but are **empty** |
| Demonstration people (alice, bob, carol) | seeded | not seeded |
| Revocation of a presented certificate (`pki.revocationCheck=auto`) | soft-fail | hard-fail |

The four-check chain, the policies and the embedded PEPs work the same in both
modes. See [What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `xacml.enabled` | `STS_XACML_ENABLED` | `true` | yes | Whether the `/xacml` endpoints answer. When off they answer 501, and the repository is untouched. |
| `xacml.enforceAccess` | `STS_XACML_ENFORCE_ACCESS` | `true` | yes | Whether the gated surfaces ask the embedded PDP. The role checks underneath still apply. |
| `xacml.accessPolicy` | `STS_XACML_ACCESS_POLICY` | `access-control` | yes | The policy the access PEP evaluates. A repository entry with this name overrides the built-in one. |
| `xacml.issuancePolicy` | `STS_XACML_ISSUANCE_POLICY` | `role-issuance` | yes | The policy the issuance PEP evaluates. A repository entry with this name overrides the built-in one. |
| `xacml.riskResponsePolicy` | `STS_XACML_RISK_RESPONSE_POLICY` | `risk-response` | yes | The policy asked what happens when a person's risk level changes. A repository entry with this name overrides the built-in one. |
| `xacml.maxPolicies` | `STS_XACML_MAX_POLICIES` | `200` | yes | How many entries `ou=policies` may hold. A create past the limit is refused, and nothing is evicted. |
| `xacml.pepBias` | `STS_XACML_PEP_BIAS` | `deny-biased` | yes | The demonstration PEP's bias (section 7.2): `deny-biased` or `permit-biased`. |
| `xacml.returnPolicyIdList` | `STS_XACML_RETURN_POLICY_ID_LIST` | `false` | yes | Returns the list of policies that applied, even when the request did not ask for it. |
| `xacml.remotePeps` | `STS_XACML_REMOTE_PEPS` | `true` | yes | Whether `/xacml/pep/*` and `POST /xacml/pip` answer. When off they answer 501. |
| `xacml.pepRequireCertificate` | `STS_XACML_PEP_REQUIRE_CERTIFICATE` | `true` | yes | Whether a PEP registration needs a client certificate. When off, a registration without one is marked unauthenticated. |
| `xacml.pipMaxPerWindow` | `STS_XACML_PIP_MAX_PER_WINDOW` | `600` | yes | `POST /xacml/pip` queries allowed per PEP and per address in one `security.rateLimitWindowS` window. |
| `xacml.pipMaxDesignators` | `STS_XACML_PIP_MAX_DESIGNATORS` | `50` | yes | The most attribute designators one PIP query may name. |
| `xacml.maxPeps` | `STS_XACML_MAX_PEPS` | `50` | yes | How many entries `ou=peps` may hold. A registration past the limit is refused. |
| `xacml.pepStaleAfterS` | `STS_XACML_PEP_STALE_AFTER_S` | `300` | yes | How long after its last heartbeat the console calls a PEP stale. The service behaves no differently. |
| `xacml.pepNotify` | `STS_XACML_PEP_NOTIFY` | `true` | yes | Whether a repository change nudges registered PEPs. When off, changes take up to one poll interval longer to reach them. |
| `xacml.pepNotifyAllowedHosts` | `STS_XACML_PEP_NOTIFY_ALLOWED_HOSTS` | *(empty)* | yes | Hosts that may be nudged. Empty means any host. |
| `xacml.pepNotifyAllowHttp` | `STS_XACML_PEP_NOTIFY_ALLOW_HTTP` | `false` | yes | Allows nudging an `http://` notify URL, in development mode only. |
| `xacml.pepNotifySkipTlsVerification` | `STS_XACML_PEP_NOTIFY_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only — a warning.** Nudges a PEP whose certificate does not verify. Ignored in product, and refused on write there. |
| `xacml.pepNotifyCaFile` | `STS_XACML_PEP_NOTIFY_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates a PEP's notify listener may chain to, beside node's own store. |
| `xacml.pepNotifyTimeoutMs` | `STS_XACML_PEP_NOTIFY_TIMEOUT_MS` | `2000` | yes | How long to wait for a PEP to answer a nudge. |
| `roles.enforceIssuance` | `STS_ROLES_ENFORCE_ISSUANCE` | `true` | yes | Whether issuance asks the issuance PEP. When off, everything is issued. |
| `roles.remotePepGroup` | `STS_ROLES_REMOTE_PEP_GROUP` | `remote-peps` | yes | The group whose members hold `REMOTE_PEPS`. Empty closes those endpoints to everyone. |
| `roles.xacmlUserGroup` | `STS_ROLES_XACML_USER_GROUP` | `xacml-users` | yes | The group whose members hold `XACML_USER`. Empty closes those endpoints to everyone. |
| `roles.claim` | `STS_ROLES_CLAIM` | `true` | yes | Whether issued tokens and assertions name the configured roles their subject holds. |
| `roles.claimName` | `STS_ROLES_CLAIM_NAME` | `roles` | yes | The name of that claim, which is also what the issuance PEP reads from a presented token. |
| `roles.maxRoles` | `STS_ROLES_MAX` | `200` | yes | How many entries `ou=roles` may hold. |

For how a value is resolved and where it can be changed, see
[Configuration](configuration.md). The `xacml.*` settings are on
`/admin/xacml`, and every setting can also be changed with
`POST /admin-api/config/set`.

## Design decisions

* **One model, three renderings.** XML, JSON and ALFA are all read into one
  model, and the evaluator never asks which syntax a policy arrived in.
  Separate readings would be separate chances to disagree with the PDP at the
  other end.
* **The repository is the directory.** `ou=policies` gets persistence,
  per-realm isolation and inspection tools for free, and there is no second
  copy that could drift.
* **A policy that does not typecheck is refused when it is written.** This
  surfaces the error while someone is still looking at it, not as an
  Indeterminate on every request afterwards.
* **Unimplemented XPath is Indeterminate, not an empty bag.** An empty bag is
  an ordinary result that a policy may be written to expect, so returning one
  would make a missing feature look like a decision.
* **Remote PEPs pull.** A push would be an outbound request carrying policy.
  A PEP that pulls knows when it is out of date, and a pull works from behind
  NAT or in another cluster.
* **The nudge only ever speeds things up.** It carries nothing a PEP could
  not get otherwise, so it has no retries and nothing to redeliver, and it can
  be turned off without breaking anything.
* **The PIP protocol uses XACML's own XML.** An invented JSON envelope would
  force the remote PEP to translate, and every translation is a place where
  two engines can disagree about a datatype or an absent value.
* **The PIP rate limit runs before the access check,** so a caller that will
  be refused cannot make the service build certificate chains and evaluate
  policies without limit. It has its own ceiling, because the sign-in limit
  of five would silently shut off the endpoint's only caller.
* **The certificate says who; the group says whether.** Authentication and
  permission are kept separate, and there are two groups so that one surface
  can be granted without the other.
* **This service's own policies are built in, overridable per realm, and
  never pushed.** Seeding them would leave realms created later without them.
  Pushing them would break every remote PEP, because they depend on
  attributes only this process has, and a deny-biased PEP turns the resulting
  NotApplicable into a refusal.
* **A missing issuance policy allows an application with no restriction and
  refuses an application with one.** The first avoids locking everyone out,
  including the administrator. The second avoids silently skipping a
  restriction someone asked for.
* **The policy editor has no JavaScript and no draft state.** Every menu is
  computed on the server by the same code that validates the result, so the
  editor cannot offer something that will then be refused. Every edit changes
  the stored, live policy.
* **A decision is not an enforcement.** The PEP's bias and any obligation it
  cannot discharge sit between the two, so the monitor counts both.

## In the running service

The XACML group under **Protocols** has five pages.

### `/admin/xacml` — XACML settings

What the PDP is, whether it is on, and every `xacml.*` setting. That includes
the one setting that belongs to the enforcement point rather than to the PDP:
a deny-biased PEP refuses an Indeterminate that a permit-biased PEP allows,
and the two agree on everything else.

### `/admin/xacml/policies` — Policies

The repository, which **is** `ou=policies`. From here you can enable,
disable, delete and choose the root. **This is the only page that creates a
policy**, from a template (RBAC, ABAC, the service's own two, blank) or by
importing ALFA. Below the table there is a section on the two built-in
policies that decide this service's issuance and access. Each has a **Create
an override** button, prefilled with the name the setting uses.

### `/admin/xacml/editor` — Policy editor

The guided editor. At each point it offers exactly the elements XACML allows
there. It covers policies and policy sets, targets, matches, conditions,
variables, selectors, obligations, advice and their assignments. It renders
the policy as ALFA alongside. Editing is **live**, with no draft: an edit that
would leave the policy invalid is refused, the refusal names the type error,
and the stored document is left unchanged. Each element costs one round trip,
so the templates are the faster way to start.

### `/admin/xacml/peps` — Remote PEPs

The registered remote PEPs, and whether each is deciding with the **same**
policy this service holds (its sync token compared with the current one),
plus its reported counters, version and last contact. The controls are **stop
nudging** and **resume**, **forget**, and **issue certificate**. Nothing on
this page reaches into another process. A PEP you stop nudging keeps
enforcing, and each disabled row says so.

### `/admin/xacml/decide` — Try a decision

Ask the PDP about a subject. You see the decision, which policies applied,
what the PIP found on the subject's directory entry, and, separately, what
the embedded PEP would do with that decision. When a policy seems not to work,
it is nearly always because only one of those two answers was being looked
at. What the embedded PEP *would* do here is not counted as an enforcement.

### Elsewhere

* **Monitoring → XACML decisions** (`/admin/xacml/monitor`) shows decisions
  and enforcements per PEP: the three embedded PEPs, every remote PEP, and
  `POST /xacml/pdp`. Totals are given for this service, for the remote PEPs
  and combined. The counters start with the process and have no reset. The
  lasting record of a refusal is the audit log (`/admin/audit`), under
  `xacml.access.refused` and `xacml.issuance.refused`.
* **`/admin/roles`**: who holds which role, which roles an application
  requires, and a preview of whether a person would be issued a token. The
  preview is a dry run and is not audited.
* **`/admin/ldap/policies`** and **`/admin/ldap/peps`** show the two
  directory containers.
* **The management API**: `GET /admin-api/xacml`, `/xacml/policies`,
  `/xacml/editor`, `/xacml/peps`, `/xacml/decide` and `/xacml/monitor`, and
  `POST /admin-api/xacml/{action}` for every policy, editor and PEP action
  (for example `create-from-template`, `set-root`, `import-alfa`,
  `issue-pep-certificate`). The request bodies are in
  `/admin-api/openapi.json`.
* Every endpoint is listed live on `/admin/sts-metadata`. Every failure is
  recorded under an `STS-XACML-NNNN` code; see [error codes](error-codes.md).

## Related

* [Remote PEP](remote-pep.md): the `xacml-pep/` container, with a worked
  example
* [TLS and mutual TLS](tls.md) and [PKI](pki.md): the client certificate and
  the truststore behind the gate
* [LDAP](ldap.md): the directory that is the repository and the PIP
* [SCIM](scim.md), [SPIFFE](spiffe.md): surfaces the access PEP decides
* [OAuth 2.0 & OpenID Connect](oauth-oidc.md), [SAML 2.0](saml2-sso.md),
  [Kerberos](kerberos.md): issuance the issuance PEP decides
* [Trust realms](trust-realms.md), [What is not checked](what-is-not-checked.md),
  [Configuration](configuration.md)
