# xacml/ — the XACML 3.0 engine

**All five phases are here: the ENGINE, the STORE, the PIP, a service surface,
the PAP, ALFA and the REMOTE PEP.** `common/protocol_stack.ts` requires
`xacml.ts` at 23c, eight routes answer under `/xacml` (see *The surface*), five
configuration pages under `/admin/xacml` and a sixth, `/admin/xacml/monitor`,
filed under Monitoring, seventeen operations under `/admin-api/xacml`,
policies live in `ou=policies`
in the embedded directory and registered remote enforcement points in
`ou=peps`.

**THE ONLY FAMILY HERE THAT ANSWERS A QUESTION ABOUT SOMEBODY ELSE'S
BOUNDARY** — every other protocol authenticates or provisions somebody, and this
one is handed a subject authenticated elsewhere and asked whether they may.

**The remote PEP is a SECOND CONTAINER and it is not in this directory** — it
is `xacml-pep/`, which has a `CLAUDE.md` of its own and is the only directory
in this repository that is not part of the mock. What is here is the PDP's side
of it: the register, the three endpoints under `/xacml/pep`, the console page
and the nudge.

## What is here

| File | What it is |
|---|---|
| `xacml_model.js` | The vocabulary: the identifiers the specification fixes, the shape of a policy tree, and the seven decision values. **No I/O.** |
| `xacml_request.js` | **The one request builder (#306, part E of #88).** #88 section 7's AuthorizationRequest — principal and its type, roles, client, target, audience, requested action and scopes, protocol, grant type, intermediary — spelt from ONE vocabulary and grouped into XACML's categories. Every PEP builds through it: the issuance, access, risk and signal PEPs, the demonstration PEP at `/xacml/protected`, `/admin/xacml/decide`, and the remote PEP, which copies it beside the engine. It decides nothing; the shared identifiers (`ROLE`, `SUBJECT_KIND`) live here because a remote PEP cannot load `xacml_templates.ts`. `tests/xacml_request.js` fails on a module that goes back to building its own. **No I/O.** |
| `xacml_attribute_rows.ts` | **The attribute-row grammar and value rules (#563, #564)**: the categories and datatypes a row may name, the reserved identifiers no row may name, the member-path grammar, and how a JSON value becomes XACML values under a row. Shared by AuthZEN's catalogue and FGA's `xacml` rows, never copied — see *Fine-grained authorization's request*, rule 3cy. **No I/O.** |
| `fga_map.ts` | **A validated RFC 9396 authorization detail as an XACML request (#564, P2)**: the grammar of a type's `xacml` and `notForPolicy` members, the built-in rows of the common data fields, `uncovered()`, the definition digest, and `request()` through the builder's `fga()`. Rule 3cy. **No I/O.** |
| `xacml_datatypes.js` | The seventeen datatypes — parse, write, equality, ordering. The table every function is generated over. **No I/O.** |
| `xacml_functions.js` | The standard function library: 275 identifiers, about thirty implementations. **No I/O.** |
| `xacml_validate.js` | Static type checking. What a policy is REFUSED for at load, before any request. **No I/O.** |
| `xacml_xml.js` | XACML 3.0 core XML → the model, and a response back. The first of three readers. |
| `xacml_pdp.js` | Evaluation: targets, rules, conditions, the twelve combining algorithms, obligations. **No I/O.** |
| `xacml_json.js` | The JSON Profile 1.1 request and response — what anybody actually sends. The second reader. **No I/O.** |
| `xacml_store.ts` | The repository. Owns the policy schema; `ou=policies` IS the store. |
| `xacml_pip.ts` | Attribute resolution off the subject's own directory entry. |
| `xacml.ts` | The protocol routes: the four under `/xacml` proper, the three under `/xacml/pep` and `POST /xacml/pip`, plus the embedded PEP. |
| `xacml_templates.ts` | The starting points: RBAC, ABAC, this service's own four, **`blank`** — an empty Policy or PolicySet, which is the only way to create a PolicySet from the console without ALFA — and **`fga-default`**, the policy every application is created with (#564). **Adding one is a row in `TEMPLATES` and nothing else.** No DOM. |
| `fga_pep.ts` | **The embedded fine-grained authorization PEP (#564, P3).** One RFC 9396 detail of an application that enforces FGA: the policy resolved, the detail mapped, decided against THAT policy alone (`xacml.ts`'s `decidePolicy()`), deny-biased, audited (`fga.decision`) and counted (the monitor's `fga` row). Fills `common/fga_gate.ts`'s decider when wired at 23c. **Since P4 also `decideAccess()`**: an AuthZEN evaluation about an enforcing application, decided against its policy alone for `authzen/authzen.ts`. A LIBRARY. Rule 3cz. |
| `fga_policies.ts` | **An application's fine-grained authorization policy and its lifecycle (#564).** `ensure`, `enable`, `disable`, `retire`, `resolve`; fills `common/applications.js`'s `setFgaLifecycle()` slot when wired at 23c. A LIBRARY. See *Application-scoped fine-grained authorization* below. |
| `xacml_editor.ts` | The editor's GRAMMAR: what may be added where, and how one edit is applied. **No DOM** — which is what lets the menus be asserted in node. |
| `xacml_alfa.ts` | ALFA read and written — the third rendering, and the one people want to look at. **No DOM.** |
| `xacml_pep_credential.ts` | `issue-pep-credential` (#1827's follow-up, phase 3): the key in a remote PEP's OWN PKCS #10 request certified by the realm's Issuing CA as `urn:sts:sa:<name>` and registered as the entry's RFC 7523 key (`person_assertions.certifyRequest()`); the entry must exist, be a service account and hold REMOTE_PEPS. No private key anywhere. A library; `xacml_admin.ts` routes the act. |
| `pep_token.ts` | A remote PEP's DPoP-bound access token from `sts-remote-pep`, read for the PEP door (`/xacml/pep`, `xacml:pep`) and the AuthZEN door (`/access/v1`, `authzen:evaluate`): ours, the PEP's client, this audience and scope, a DPoP proof that holds, one `ou=users` entry. Writes no response (#1827's follow-up). |
| `xacml_pep_registry.ts` | The register of REMOTE enforcement points. `ou=peps` IS the store, and the sync token is computed here. |
| `xacml_pep_settings.ts` | **A remote PEP's managed settings (#1760)**: the table, `set-pep-settings`' validation, `GET /xacml/pep/settings`' body and the reading of what the PEP reports in force. A LIBRARY. See *A remote PEP's own page* below. |
| `xacml_pep_listeners.ts` | **A remote PEP's listeners (#1760)**: the environment's four, the ones defined on its page (`xacmlPepListeners`), their validation, the pull's section and the reading of what the PEP reports (`xacmlPepListenersInUse`). A LIBRARY. See *A remote PEP's listeners* below. |
| `xacml_pep_route_policies.ts` | **A reverse-proxy route's policy (#1760)**: the save's checks of a route's authorization choice, the simple and public routes' generated policies (ALFA through the store's validating write, marked `xacmlPepRoute`), their removal, the default resource and the application's home page. A LIBRARY. See *A ROUTE'S AUTHORIZATION* below. |
| `xacml_pep_http.ts` | **The THIRD outbound request in this repository** — the nudge. Argued rather than cited. |
| `xacml_pep_tls.ts` | **A remote PEP's HTTPS listener certificate (2026-09-13).** Issues a REGISTERED PEP a `serverAuth` key pair from its realm's `pep-tls` Issuing CA through `common/pki.js`, naming the PEP, the hostname it reports and its notify host, and hands the private key back once. A LIBRARY — `xacml_admin.ts` draws the control and answers the action. See *The remote PEP's HTTPS listener* below. |
| `xacml_admin.ts` | The five `/admin/xacml` console pages and their actions, and `/admin/xacml/monitor`'s body. |
| `web_pep_picture.ts` | **A remote PEP drawn (rcbj, 2026-11-15)**: the Reverse proxy tab's Visual sub-tab, the PEP, its listeners and its routes as a tree by path, laid out in the browser from the PEP page's answer. A `web_` module; see *THE VISUAL SUB-TAB* below. |
| `xacml_monitor.ts` | The decision and enforcement counters behind `/admin/xacml/monitor`. A LEAF. See *`/admin/xacml/monitor`* below. |
| `xacml_access_pep.ts`, `xacml_role_pep.ts` | The two embedded PEPs that decide THIS service's own access and issuance. See *AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE* below. |
| `xacml_risk_pep.ts`, `xacml_signal_pep.ts` | **The two embedded PEPs for REACTIONS (#62, 2026-09-22)**, each asking a built-in policy one question per reaction, where a Permit means do it. `risk-response` covers what a change of a person's risk leads to (`risk/CLAUDE.md`). `signal-response` covers whether this service's own console or portal ends its own sessions on a CAEP or RISC event it RECEIVED and verified, and what a federation partner's verified event does — since #432 including `signal-revoke-grants`, a person's GNAP and OAuth grants and tokens, behind `ssf.signalsRevokeGrants` (`ssf/CLAUDE.md`). Both are libraries, reached lazily and built at 23c. |
| `conformance/` | The vendored OASIS suite. `PROVENANCE.md` is the argument, `MANIFEST.js` the drift check. **Not edited here, ever.** |

Five tests, all in-process, no port, no container:
`tests/xacml_conformance.js` (the engine, against 455 cases somebody else
wrote), `tests/xacml_service.js` (the store, the PIP, the JSON Profile and the
PEP), `tests/xacml_pap.js` (the templates, the editor grammar and the XML
writer), `tests/xacml_alfa.js` (ALFA, both directions) and — since phase five —
`tests/xacml_pep.js`, which is the odd one out: it spawns a CHILD PROCESS in
`xacml-pep/` and asks the container questions this process cannot answer about
itself. Three more have joined them since, each argued in its own header:
`tests/xacml_service_own.js` (the two built-in policies, below),
`tests/xacml_monitor.js` (the monitor's counters) and
`tests/xacml_pep_realms.js` (a remote PEP registered in another realm).

**AND THREE OVER HTTP, WHICH IS WHAT THOSE FIVE COULD NEVER
COVER.** Between them the five hold the ENGINE to 455 cases, the store, the PIP,
the JSON Profile, the editor's grammar and the container's shim — and they make
NOT ONE HTTP REQUEST, so until these existed every route in `xacml.ts` and
every form on the five console pages was uncovered. Since 2026-09-05,
`tests/protocol/`
`sts_xacml_endpoints.js` drives the seven `/xacml` endpoints and
`sts_xacml_editor.js` drives `/admin/xacml/editor` in a real browser; **since
2026-09-06 `sts_xacml_remote_pep.js` DRIVES THE `xacml-pep/` IMAGE AS A SECOND
CONTAINER ON THIS SERVICE'S OWN DOCKER NETWORK — in both launchers' stacks** and asserts that a policy
deployed through `/admin-api/xacml` changes what that container allows — the
seam neither `tests/xacml_pep.js` (which loads the container's modules and makes
no request) nor `sts_xacml_endpoints.js` (where the TEST impersonates a PEP and
nothing evaluates what it pulled) can reach, and the only thing anywhere that
loads `xacml-pep/sync.js`. **It is also the only test of the NUDGE against a
listener that answers**: `xacml_pep_http.ts` is this family's outbound half and
until that file existed nothing had ever delivered one. All three are
this repository's own (`local: true`), and they live there rather than in the
parent project's suite for one reason worth stating here, because it is a fact
about THIS family: **a PDP with an empty repository answers NotApplicable to
everything**, so there is no question worth asking `/xacml/pdp` until a policy
exists, and over HTTP the only way to put one there is `/admin-api/xacml`. Every
assertion in either file therefore spans an authoring door and a deciding door.

All three work in a THROWAWAY TRUST REALM, which is not tidiness: `ou=policies` is
per realm and a new realm's is EMPTY — the seeded policy is written once, in the
default realm, at require time — so a realm gives them a repository whose whole
contents they wrote, makes every count exact rather than "at least", makes the
no-root state reachable at all, and keeps `xacml.enabled`, `xacml.remotePeps`
and `xacml.pepRequireCertificate` off the process while they are turned off and
on. **The remote-PEP job needs it for two reasons of its own**:
it disables every policy in the repository to reach the state where a PEP holds
nothing, and doing that anywhere but a realm of its own would stop every other
job in the run being decided about — and it then turns `xacml.remotePeps` OFF
in that realm while its container is still running (it REMOVED the realm until
2026-09-06, when the suite stopped removing realms), which is how it makes a
PDP outage without stopping the service the rest of the suite is using. **The
editor job needs the realm most**: the draft IS the stored policy, so a job
editing in the default realm would be rewriting the seeded one, live, while
every other job in the run decided against it.

`sts_xacml_editor.js` found the thirteenth defect on its first run and it is
listed below with the twelve.

## Where this family sits in the require order (23c)

**After `admin-ui/admin`**, whose `setXacmlPages()` and `setRolePreviewer()`
slots `xacml_admin.ts` and `xacml_role_pep.ts` fill and whose page shell,
settings block and action responder it requires — so a require the other way
would close a cycle, and one from `mgmt-api/admin_api.ts` would have moved
every `/xacml` route and all six `/admin/xacml*` pages ahead of the management
API's own (since #50's R1 the routes are placed only by
`common/protocol_stack.ts`'s `register()` calls, but that require would still
arm the issuance gate and fill the console's slots at 19 rather than 23c). It
requires `xacml_admin.ts` ITSELF rather than `common/protocol_stack.ts` doing
it, so this family has ONE require in the require order — and two `register()`
calls, `xacml_admin` then `xacml`, because requiring `xacml.ts` used to
register `xacml_admin.ts`'s pages first; that module requires this one back
LAZILY, inside the one function that needs it.

**And after `ldap/ldap_server` (21) in effect** — not as an ordering
constraint, since both registers take their directory across a slot that module
fills, but because a process that loaded this one and not that has an empty
repository and answers NotApplicable to everything. Since 2026-09-05 it also
requires `oauth-oidc/mtls` for the remote PEP's client certificate, which is a
LIBRARY (rule 3) and registers nothing, so it cannot move a route or join a
cycle.

**AND IT REQUIRES `xacml_role_pep.ts`, WHICH IS WHAT ARMS EVERY ISSUANCE SITE IN
THE SERVICE**: that module fills `common/issuance_gate.js`'s decider at require
time, so from this line onward every `gate.check()` call reaches the engine
and before it — in `npm test`, in the parent project's in-process Kerberos
jobs, in the remote PEP container — they answer "allowed". See *AND SINCE
2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE* below.

## The three `/xacml/pep` endpoints are GATED, and the chain has four links

**SINCE 2026-09-06 A REMOTE PEP IS AN IDENTITY RATHER THAN A CONNECTION.** It
was `xacml.pepRequireCertificate` and nothing else: any certificate at all —
self-signed, minted a second ago, naming anything — registered, pulled the
repository and reported counters. That was right while a PEP was a
demonstration and stopped being right when the repository it pulls became the
one this service enforces its own access with.

Four links, and each is checked by the module that owns it:

| # | The question | Answered by |
|---|---|---|
| 1 | Did the certificate build a path to an anchor in this service's truststore? | `oauth-oidc/mtls.js`'s `peerVerified()`, over the truststore `POST /admin-api/tls/trust/add` fills — and the MAIN listener joined that truststore the same day, which is what made the question answerable at all |
| 2 | Which directory entry is that? | For a certificate THIS service issued, `xacml_pep_registry.ts`'s `certificateIdentity()`, across the slot `ldap_server.js` fills (`certificatePlan()`'s CN, which this service's authority wrote as the username). **For one from an outside authority, since #1061, the entry STORING it** in `userCertificate`, through `tls_client_certificates.checkSocket(req.socket, { stored: true })` in `callerIdentity()` — the one mapping every door asks (`common/CLAUDE.md` 3ag) — and NO name when no entry or several store it (`unmapped`, `dn` empty, so link 3 has nobody to ask and the policy refuses; marked `STS-XACML-0177`/`0178` at the XACML gate, `0179`/`0180` at the PEP gate). The subject DN an outside authority wrote is no longer read |
| 3 | What roles does that entry hold? | `common/roles.js`, with the groups LEFT UNRESOLVED so it reads them from the directory. `REMOTE_PEPS` was the first built-in role held through a GROUP rather than computed from what the party is; `XACML_USER` is the second, and the two are deliberately separate |
| 4 | Does the policy allow it? | `common/access_gate.ts` → `xacml_access_pep.ts`, on resource `xacml-pep-api` or `xacml-api` — the same embedded PEP and the same `access-control` document that decide the console and the management API |

**THE CERTIFICATE SAYS WHO AND THE GROUP SAYS WHETHER**, and keeping them apart
is the whole design. A certificate this service verified, naming
`cn=rogue-pep,ou=users,…`, holding `EVERYBODY, ALL_AUTHENTICATED_USERS` and not
`REMOTE_PEPS`, is refused — and the refusal says the certificate was fine,
because somebody debugging it otherwise regenerates a certificate that was
never wrong. `tests/protocol/sts_xacml_endpoints.js` drives exactly that case.

**EVERY CERTIFICATE THESE GATES MEET IN THE SUITE IS AN OUTSIDE ONE**
(`tests/tools/pep-credential.js`'s chain), so since #1061 every job that
presents one has to store the leaf on its entry first, and the launchers the
remote PEP's. The not-stored and stored-twice refusals over the wire are held
only by the protocol jobs (`sts_xacml_endpoints`, `sts_xacml_remote_pep`,
`sts_xacml_editor`), which need a stack and were not run in #1061's session.

**IT IS A POLICY DECISION AND NOT A HARD-CODED ROLE TEST.** The requirement
travels in the REQUEST — `xacml-pep-api` was the first resource that is
restricted by DEFAULT rather than narrowed by an operator and `xacml-api` is
the second, which
`xacml_access_pep.ts` argues where it reads it — so an operator who edits the
access-control document, or points `roles.remotePepGroup` at a group of their
own, changes this answer with everything else. `xacml.enforceAccess` turns the
layer off and the old `xacml.pepRequireCertificate` refusal is what answers
underneath.

### A TOKEN IN PLACE OF THE CERTIFICATE (#1827's follow-up, rcbj-approved plan, 2026-11-16, phase 1)

**Links 1 and 2 have a second answer: a DPoP-bound access token from
`sts-remote-pep`.** The PEP signs an RFC 7523 self-assertion with ONE key,
presents it through that public client with a DPoP proof by the same key,
and is issued, per audience, a token bound to it: `xacml:pep` on
`sts-xacml-pep-api` (audience the realm's `/xacml/pep`) for every
`/xacml/pep/*` call and `POST /xacml/pip`; `xacml:pep-audit` for the push;
`authzen:evaluate` for the forward. REMOTE_PEPS authorizes `xacml:pep` at
issuance (`roles.js`'s row names a list now) and links 3 and 4 decide on
every call, unchanged.

* **ONE READING, `pep_token.ts`**, shared with the AuthZEN door: this
  realm's token, issued to `sts-remote-pep` (`STS-XACML-0294` otherwise),
  for this path (`0293`) and scope while the client holds the grant (`0295`),
  `cnf.jkt` and sent as DPoP (`0292`), a proof `dpop.verifyProof()` accepts
  — replay, `ath`, the server nonce (`0296`, with `use_dpop_nonce` and a
  `DPoP-Nonce` when it wanted one) — and a `sub` that is exactly one
  `ou=users` entry (`0297`). Anything else about the token is `0291`. Each is
  a 401 with a `DPoP` challenge; the policy's refusal stays a 403.
* **`pepIdentity()` IS THE PEP DOOR, `callerIdentity()` STAYS THE
  HANDSHAKE.** `pepAccess()`, `validationDoor()` and the PIP read
  `pepIdentity()`, which reads the token or the certificate as
  `xacml.pepAuthentication` (per realm, `token` by default since phase 4;
  `either` until then) allows, once per request (a proof is good for one
  request). `xacmlAccess()` and the AuthZEN
  certificate door read `callerIdentity()`, which never reads a header.
  **A token, where one is presented and accepted, DECIDES** — a refused one
  is not passed over for the certificate underneath. `token` refuses a
  request carrying none (`0289`); `certificate` does not read the header and
  refuses a token-only request (`0290`).
* **PHASE 4 (rcbj, 2026-11-16): `token` IS THE DEFAULT, `certificate` AND
  `either` ARE OPT-INS FOR GOOD.** The PEP image no longer presents a client
  certificate (`xacml-pep/CLAUDE.md`, `STS-XPEP-0135`), so `certificate`
  admits only an older PEP image or another implementation. **The upgrade is
  the compatibility question**: a 1.0.0 deployment's PEPs authenticate by a
  certificate, and the new default refuses them. A value an operator stored
  (console, `/admin-api/config/set`, a realm's overrides) or set in an
  appconfig file wins as every value does; with neither, the operator sets
  `either` before upgrading (`docs/v1.1.0/release-notes.md`, `docs/v1.1.0/remote-pep.md`
  *Upgrading a deployment whose PEPs use a certificate*), and the upgrade
  script does that for a SQL store (below). So the refusal is
  never silent: where the refused request presented a certificate that
  VERIFIES, `0289`'s description says `either` would accept it and names
  `PEP_ASSERTION_KEY`, and `warnCertificateRefused()` logs a warning under
  `0289` once per realm and process. **The upgrade script writes `either`
  for every realm with a row under its `ou=peps`** (rcbj, 2026-11-16:
  "create a migration script"; `postgres/upgrade-1.0.0.sql`,
  `mariadb/upgrade-1.0.0.sql`, argued in `postgres/CLAUDE.md`), since every
  PEP 1.0.0 registered authenticated by certificate; the manual step is left
  for a store the script does not reach (LDIF, a split cell database). An
  anonymous request is now `0289`'s 401 where it was the policy's 403
  (`STS-XACML-0007`) under `either`.
* **THE NAME IS THE USERNAME**, `commonName` of the identity — what a
  certificate this service issued carried — so the `ou=peps` row, the
  heartbeat's row and a cluster's membership are unchanged; the row's
  `thumbprint` is the DPoP key's RFC 7638 thumbprint, `certificateSubject`
  empty.
* **WHAT IT COSTS** (measured in process by `tests/remote_pep_token_door.js`
  C1): every call verifies one ES256 proof and writes its `jti` — the
  cluster claim `dpop.proofClaims()` takes on arrival and a `dpop.seenJtis`
  row. On a store, the second makes a pull or a PIP query a WRITING response
  that the barrier holds until it commits, where with a certificate it was a
  read.

`tests/remote_pep_token_door.js` drives it in process over plain HTTP (X14
the default, X13/X15 the opt-ins); `tests/authzen_evaluation.js` K0/K0a hold
the default's refusal of a verified certificate over a real handshake, and
K2a/K2b the precedence under `either`. `tests/stored_certificates.js` and
`tests/xacml_pep_proxy.js` opt in to `either`, since they drive the
certificate door.

### PROVISIONING THE KEY: `issue-pep-credential` (phase 3, rcbj 2026-11-16)

**The service never holds the PEP's private key** (rcbj), and the
certificate is **issued by the realm's internal CA** (decision 4). The PEP or
`tests/tools/pep-credential.js --assertion` generates the key and sends a
PKCS #10 request; `xacml_pep_credential.ts` checks the entry and hands the
request to `person_assertions.certifyRequest()`, the one CSR door for a
person's RFC 7523 key (`common/CLAUDE.md` 3ab).

* **WHO.** `name` (or `pep`) is a USERNAME under this realm's `ou=users`, not
  an `ou=peps` row — a PEP is provisioned before it ever registers. Refused:
  no such entry (`STS-XACML-0298`), not a service account (`0299`), not
  holding REMOTE_PEPS (`0301`), asked of `roles.rolesOf()` by DN as
  `pepAccess()` asks. A key for an entry every PEP door refuses would read as
  a broken PEP rather than a missing membership.
* **WHAT.** The leaf names the entry (`urn:sts:sa:<name>`, CN the username);
  the request's subject and SANs are read for nothing. EC P-256 or RSA ≥ 2048
  (`STS-PKI-0281`); a request that does not prove possession is the
  enrollment reader's `STS-ENROLL-0033`.
* **ROTATION ADDS** (#1290's rule for a person's keys): the old key keeps
  working until the PEP is moved; `revokePrevious: true` revokes the entry's
  other valid RFC 7523 keys after the new one is written, or before it when
  the entry is at `pki.personSigningKeyMax`. A failed revocation is `0302`
  with the new key registered.
* **THE ANSWER** is public material and the environment (`PEP_NAME`,
  `PEP_CLIENT_ID`, `PEP_ASSERTION_KEY` as a reminder, not a path); audited as
  `xacml.pep.credential` without the certificate. On the console: a form on
  the PEP's Overview and one under the Remote PEPs table (with a name field),
  the answer drawn once by `WebAnswers.pepCredential()`.
* **THE STACKS** generate the key (`--assertion --csr-only`) and mount it
  as `PEP_ASSERTION_KEY`; `sts_xacml_remote_pep.js` sends the request once it
  has made the PEP's entry in its realm, and the PEP's token fetches succeed
  from then on (it retries every five seconds). Since phase 4 they mint no
  client certificate for the PEP at all, and nothing carries its calls until
  the key is registered.

`tests/pep_assertion_credential.js` holds it in process.

### The entry is a SERVICE ACCOUNT, owned by the realm's administrators (#1760)

rcbj: "The user that a remote PEP uses to map its client cert to and connect
to the STS needs to be flagged as a service account. The realm admin can be
listed as the owner." `common/service_accounts.ts`'s *A REMOTE PEP'S IDENTITY
IS A SERVICE ACCOUNT* is the design; `common/CLAUDE.md` 3cd has the rule. What
this family needs to know:

* **ONE CHOKEPOINT, THE MEMBERSHIP WRITE.** `ldap_server.js`'s
  `noteMembershipChange()` — which every write of a group's members tells —
  hands each PERSON who joins the group `roles.remotePepGroup` names to
  `designateRemotePep()`. Not the registration: an entry designated by being
  granted REMOTE_PEPS is one before any PEP knocks, and the gate stays a
  read. The seed and the entries that predate this are
  `designateRemotePeps()`, run at startup after each realm's bootstrap
  administrator (`server.js`, inside the bootstrap claim) and at a realm's
  create (`admin_actions.ts`). An application holding REMOTE_PEPS, and an
  entry already a service account, are left as they are.
* **THE OWNER** is the realm's Admin Write group, else its bootstrap
  administrator, in the same write as the flag, else a deferral
  (`STS-SVCACCT-0051`) — never an ownerless write, whatever `requireOwner`
  says.
* **NO DOOR IS ON THIS PATH, AND NONE WAS ADDED.** The four links above ask no
  password and start no session: `callerIdentity()` reads the handshake and
  names the entry, `pepAccess()` asks `roles.rolesOf()` and the access
  policy. `credentials.serviceAccountDoorRefusal()` and
  `secondFactorRefusal()` are asked inside `credentials.verifyPrepare()` /
  `verify()` (a password), and the browser door in `authn.startSession()`;
  none of `/xacml/pep/*`, `/xacml/pip`, the settings, the listener
  certificate or the proxy's validation and identity doors reaches either
  for the PEP's own entry — `basic()` verifies an END USER's password, and
  `identity()` issues about the end user. A browser sign-in as the PEP's
  entry is refused, which is wanted. `tests/xacml_pep_proxy.js` B0s/B1
  registers and pulls as one; `tests/remote_pep_service_accounts.js` holds
  the rest.
* **THE PAGE** draws it on the PEP's Overview (`pepServiceAccount()`), from
  `identityAccount` on each row of `pepsJson()`, read where it is
  (`service_accounts.identityOf()`), never stored on `ou=peps`.

### This service's own policies are never pushed

`GET /xacml/pep/policies` withholds the documents named by `xacml.accessPolicy`
and `xacml.issuancePolicy`, and names them in a `withheld` field rather than
dropping them silently.

**THE REASON IS NOT SECRECY, IT IS THAT THEY WOULD BREAK THE PEP THAT PULLED
THEM.** Those two decide THIS service's questions against attributes only this
process can supply — a required role off an application entry, a resource owner
off a portal session. Evaluated in a remote PEP against its own requests they
answer NotApplicable to everything, and a deny-biased PEP turns NotApplicable
into a refusal: shipping them would silently make every remote decision a Deny,
which is the exact shape of the defect `xacml-pep/CLAUDE.md` records having cost
a run already. They stay readable at `GET /xacml/policies`, where a PERSON reads
the repository.

Filtered BY NAME and not by a flag on the entry, because those two names are
settings: an operator who points `xacml.accessPolicy` at a document of their own
has made THAT one internal, and a stored flag would still be on the old one.

**Every policy an application owns is withheld too (#564), and BY ITS FLAG**
(`xacmlApplication`) — the opposite choice, for the opposite reason:
ownership is not a setting that can be pointed elsewhere but a fact written
with the policy. It is named in `withheld` like the two above. The filter is
`XacmlSurface.pepPull()`, the route's body as a method so a test can hold it
without the mutual-TLS gate. See *Application-scoped fine-grained
authorization* below. What the container is sent instead is the list of
applications that enforce, on the AuthZEN catalogue pull, so its edge PDP
forwards their evaluations here (P7, *`GET /xacml/pep/authzen-catalogue`*).

## ALFA

The third rendering of the model, and the one worth reading — forty lines of
XML are eight of ALFA:

```
policy staffAccess {
    apply denyUnlessPermit
    rule allowStaff {
        permit
        target clause employeeType == "staff" and actionId == "GET"
    }
}
```

**It is an OASIS Committee Specification Draft, not a ratified standard.** No
conformance suite, no schema, no second implementation to disagree with — a
completely different footing from the engine. So the contract stated and
asserted is the one that can actually be kept:

> **Anything the emitter writes, the parser reads, and the policy decides
> identically either way.**

`tests/xacml_alfa.js` checks all three halves of that over every policy the
templates build and the seeded one — stable bytes, still type-checks, **and
the same decisions on seven probes**. The third is the one a round-trip test
usually omits, and the only one that would catch a swapped comparison: `age >
18` becoming `18 > age` round-trips perfectly and decides the opposite. That is
what `mirrorOperator()` is for.

**ALFA is a VIEW, never a second stored copy.** An imported policy is parsed,
converted and stored as XACML XML; the editor renders the ALFA back from the
model. A stored ALFA text beside a stored XML one would be two documents that
could disagree.

Three places the dialect is explicit where ALFA is vague, all argued in the
file's header: **typed literals** (`date("2026-01-01")`, because ALFA has
native syntax for four datatypes and nothing agreed for the other thirteen),
**the three target levels** mapping onto `clause` / `or` / `and`, and
**attributes declared before use** — which is ALFA's own rule and the most
useful refusal in the parser, because a typo in an attribute name is otherwise
a policy that quietly matches nothing and looks exactly like one that is
working and denying you.

A designator's **MustBePresent and Issuer** are not a dialect choice: ALFA
writes them after the short name where the attribute is used, as Axiomatics'
reference spells them — `role[mustbepresent]`, `role[issuer="..."]`,
`role[mustbepresent issuer="..."]`. Until 2026-11-13 the emitter dropped both
and the parser built every designator optional with no issuer, so a round
trip turned a missing attribute's Indeterminate into NotApplicable and let an
attribute from any issuer match; and `operatorFor()` took the first matching
suffix, so `-greater-than-or-equal` and `-less-than-or-equal` were written as
`==`. Through ALFA and back, 59 of the 447 OASIS mandatory policies that load
decided differently; none do now. `tests/xacml_alfa.js`
`checkOperatorsAndQualifiers()` holds both.

## The console

```
/admin/xacml            one Protocols destination, with six tabs:
  Metadata              this realm's XACML endpoints
  Settings              whether the PDP is on, its PEP bias and settings
  Policies              the repository; enable, disable, root, delete,
                        import ALFA, create from a template — and this is the
                        ONLY tab that creates a policy: the editor edits one
                        that exists
  Policy editor         the guided editor
  Remote PEPs           the remote enforcement points, and whether they are
                        deciding with the same policy this service holds
  Try a decision        ask the PDP and see what the PEP would do
```

The former policies, editor, PEPs and decision destinations are tabs, not
sidebar leaves; their distinct management API operations still supply them.
The decision counters remain `/admin/xacml/monitor` under Monitoring.

**The editor had no JavaScript, and that was argued rather than assumed.**
This console was `script-src 'none'` and `admin-ui/CLAUDE.md` refused a script
nine times over under a rule that the argument must be *made* each time — the
test being whether the page CANNOT work without one. An editor can. So every
"pick the next valid element" dropdown is a `<select>` whose options were
computed on the server by `xacml_editor.ts`, and choosing one was a form POST.

**Every page of this console but one was `script-src 'none'`** (the exception
was `/admin/api-explorer`, which arrived on 2026-09-09 and argued itself) —
**until #446 (2026-10-05)**, when the whole console became a static
application under `script-src 'self'`, drawn by `/admin/console.js` from
`/admin-api`. The editor's design survived it: its options are still computed
on the server (`GET /admin-api/xacml/editor`) and choosing one is still a
round trip, now an `/admin-api` call rather than a form POST; the editor has
no script of its own.

*What it costs*: a round trip per element — a five-rule policy built by hand is
perhaps forty POSTs. The page says so; the templates are the answer.

**THE EDITOR CREATES NOTHING, AND SINCE 2026-09-06 IT SAYS SO ON BOTH OF ITS
BRANCHES.** Every control on that page posts a policy NAME and a PATH into a
stored document, so there is nowhere for a policy that has not been written yet
to live and there is no New button. That was defensible and it was invisible: a
reader who opened the editor to write a policy found a chooser of other
people's policies and no door. There are now two notes rather than one, because
the two readers are different people — the empty-repository branch is somebody
with nothing at all, and the note beside the chooser is somebody who has a
policy open and is looking for the button that makes another. Both send them to
`/admin/xacml/policies` and both name the three doors there.

**The third door is the `blank` template**, added the same day and the reason
the second note could be written at all: before it, "create a policy and come
back" meant starting from somebody else's RBAC document or learning ALFA first.
It builds an empty `Policy` or an empty `PolicySet` — no rules, no children, no
Target — and **an empty deny-unless-permit document DENIES**, which the page
says on the template, on the created policy's own description and in the
editor's note, because the one thing that must not happen is somebody making a
blank policy the root and reading its silence as inert. That is the same choice
`xacml_editor.ts` makes for a child policy added in the editor, and it is the
direction a half-built policy should fail in.

*What it buys*: the menu is computed by the same process that will validate the
policy, against the real function library, so **the editor cannot offer
something the validator will then refuse**. A browser-side editor would have
needed a second copy of the grammar shipped to the page, and a second copy of a
grammar is what this whole directory is arranged to avoid.

**The editor holds no session state.** The draft IS the stored policy: every
edit loads the document, applies one change, serializes and writes back. There
is nothing to lose when a browser closes and no second copy that could disagree
with the stored one. The cost is that editing is LIVE, so the page says so and
puts the disable control one click away — and since 2026-11-15 (rcbj) says
first, above the chooser, that there is no overall Save: each Update writes
its own row at once, the PDP decides with it from the next request and the
remote PEPs are nudged (`editor.noSave`). **A route's generated policy
(`xacmlPepRoute`) carries a warning** (`editor.generatedRoute`, from the
answer's `policy.pepRoute`): `PepRoutePolicies.write()` writes it again
whenever the text it would generate differs — at Generate the policy again
and at EVERY save of that PEP's routes, since `proxyAction()` writes every
simple or public route's policy, so a Save on any route tab (not only
Authorization), another route's save or a manifest save replaces a hand
edit, and re-enables it. A hand-written policy belongs to the route's
existing-policy choice.

**An expression edit names an expression.** The six `set-expression-*` actions
replace the node at the path. A path that resolves to a Match, a rule, a
target, an AnyOf or an AllOf is refused (`STS-XACML-0035`) rather than
written: `writeTarget()` would then call `writeExpression()` on the Match's
missing `value` and throw reading `.kind`, which the fault boundary answers
as HTTP 500 (`STS-API-0140`, #1419). The document root was already that
refusal (#1356). A Match is edited by `edit-match`.

**An `edit-match` names a Match.** The action reads the Match's value.
A path `kindAt()` calls `allOf` (the fuzzer sent
`.rules.0.target.anyOf.0.allOf.0` and omitted `value`) has no `value`,
so the read throws (`STS-API-0140`, #1428). The edit is refused
(`STS-XACML-0035`) before anything is written. A function with no first
argument, and a Match that has no value when the body supplies none,
are the same refusal: both are the next read that would throw.

## What the editor can build, and the three things it cannot

**Since 2026-09-05 the guided editor reaches the whole of the XACML 3.0 policy
syntax this engine models.** Before that it built a `Policy` — rules, targets,
matches, conditions, obligations, advice — and nothing else, while
`xacml_xml.js` read and wrote considerably more. That gap was not a missing
feature so much as **four defects, because the editor SERIALIZES THE WHOLE
DOCUMENT ON EVERY EDIT**: a part of the syntax the reader skipped was not
merely unread, it was deleted by the next rename.

| Was | Is |
|---|---|
| A `PolicySet` drew as a policy with no rules, offered `add-rule`, accepted it, said "Rule added." and wrote a document without it — the writer serializes `children` and never looks at `rules` | `policySet` is a kind of its own with its own menu: an inline `Policy`, a nested set, a `PolicyIdReference` or a `PolicySetIdReference`, and the POLICY-combining algorithm list, which is a different set of URIs from the rule-combining one it is almost spelt the same as |
| `set-expression-variable` was in the menu and there was no way to DEFINE a variable, so choosing it built `$v1`, the validator refused the document and the store declined the write | `VariableDefinition` is addable, renamable (**every reference is rewritten with it**) and removable, and the reference option is WITHDRAWN where the enclosing policy defines none |
| Choosing `any-of`, `all-of`, `map` or the other four higher-order functions built an `<AttributeValue>` where a `<Function>` belongs — an expression the validator refuses, offered by the editor's own menu | a function-parameter argument arrives as a `<Function>` reference, and `map` gets a one-argument default because its function takes one value where the other six take a predicate of two |
| An `AttributeSelector` could not be built, and a policy that HELD one lost its namespace bindings on the first edit — an unresolvable prefix is an empty bag, which is NotApplicable, which looks exactly like a policy that decided you may not | selectors are addable and editable (path, category, `ContextSelectorId`, `MustBePresent`, one namespace binding at a time), a `Match` may test one instead of a designator, and **the bindings are written back onto the element** |
| `add-assignment` had been in the menu since the editor shipped and an assignment could not be SEEN, so the only way to correct a mistyped one was to delete the whole obligation | assignments are drawn, editable (`AttributeId`, `Category`, `Issuer`) and removable, and their value is an expression node of its own |
| `Version`, `Issuer`, `ContextSelectorId`, `XPathCategory` and `MaxDelegationDepth` had no control anywhere; `MaxDelegationDepth` was read and never written | all of them are settable, and a `Version` that is not dot-separated numbers is refused HERE, because nothing else in this service would refuse it and somebody else's schema validator will |

**`MustBePresent` is a `<select>` and not a checkbox, and that is the one piece
of markup here worth arguing about.** An unchecked checkbox sends nothing, so
the handler cannot tell "unchecked" from "this form does not edit that field" —
and it has to keep the value for the second case, or the form that edits a
Match's function would clear `MustBePresent` on every save. That is the
difference between an absent attribute being an empty bag and being
Indeterminate: between a policy that quietly does not apply and one that fails
closed.

**`XPathVersion` is REPORTED and never enforced.** Section 5.14 says the
element MUST be present when a policy holds an `AttributeSelector` or an
`xpathExpression`, and `xacml_validate.js` says nothing about it and never
will — that file refuses what is CERTAINLY WRONG for every request, and this
changes no decision this PDP makes, because this engine evaluates no XPath at
all (see *What is not here yet*), so nothing here chooses a dialect by URI. So
the editor page names the policies that need one, beside the field that sets it.
Refusing the write would be the editor inventing a rule the evaluator has not
got; saying nothing would let somebody build a document here that this service
is happy with and a schema validator elsewhere rejects.

**THE THREE THINGS IT DOES NOT DO, and each is a decision rather than a gap:**

* **The four combiner-parameter elements are carried, drawn and removable —
  and no menu offers to add one.** Section C of the specification says none of
  the twelve standard combining algorithms takes a parameter, so an Add button
  would be the first control on this console that provably changes no decision.
  Drawing them is a different question and comes out the other way: a document
  may arrive carrying them through ALFA, an import or an `ldapmodify` straight
  into `ou=policies`, and an element the editor did not draw would be one the
  person could neither see nor delete while the writer faithfully kept it.
* **`<PolicyIssuer>` is not implemented at all**, so a document carrying one
  loses it here. It belongs to the administrative delegation profile, which
  this PDP does not implement — and `MaxDelegationDepth` beside it is carried
  and read by nothing, which the console says out loud rather than letting the
  attribute imply otherwise.
* **A variable may not be named with a dot in it.** XACML allows one; this
  editor addresses a node by a dotted path, so `a.b` would produce a row that
  cannot be edited or removed while the document itself stayed valid. Refused
  at the point of naming, where it can still be explained.

`tests/xacml_pap.js` carries all of it — 62 assertions added with the change,
including the one that would have caught the policy-set defect: three children
added, serialized, read back, and counted.

**Every element arrives complete and valid** — a new rule has a Target and an
Effect, a new Match has a function, a value and an attribute — because an
editor that produced half-built elements would hold a document that cannot be
saved, and a document that cannot be saved cannot be evaluated, which is when
you most want to look at it.

## The surface

```
GET  /xacml                 what this is; ?format=json for the same as data
POST /xacml/pdp             a decision. JSON Profile in, JSON Profile out
GET  /xacml/policies        the repository as the PDP sees it, documents included
POST /xacml/pep/register    a REMOTE PEP registers, over mutual TLS
GET  /xacml/pep/policies    the enabled policies, for a remote PEP to LOAD
GET  /xacml/pep/authzen-catalogue
                            the AuthZEN catalogue, for its edge PDP (#1179)
GET  /xacml/pep/authzen-callers
                            who that edge PDP admits, and as whom (#1189)
POST /xacml/pep/heartbeat   what a remote PEP has enforced
POST /xacml/pip             the PIP over HTTP — XACML XML in, XACML XML out
```

**ALL NINE REQUIRE A CLIENT CERTIFICATE NOW, AND THIS SECTION SAID THE
OPPOSITE.** What stood here was an argument for `POST /xacml/pdp`
authenticating nobody, and half of it is still true and still load-bearing: **a
PDP is not an authorization boundary.** It answers a question about somebody
ELSE'S, the identity that matters is IN the request, and nothing the connection
carries reaches `decide()` — a PDP that decided about whoever holds the client
certificate would be a different and much worse component.

**What changed is that "not a boundary" was being read as "not worth
guarding".** Those are different sentences, and the endpoints proper do
something an anonymous caller should not get for free: `GET /xacml/policies`
publishes the documents this service now decides its own admissions with
(`GET /xacml/protected`, until #596, named its own subject from a query
parameter and was otherwise an oracle anybody could drive to map the policy
one subject at a time), and `POST /xacml/pdp` evaluates an arbitrary document on
this service's thread. `GET /xacml` is guarded because it describes the other
three, and its refusal names the group and the setting so that the page's job
survives being refused.

### Two roles, two groups, and they must not become one

| Endpoints | Role | Group |
|---|---|---|
| `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` | `XACML_USER` | `roles.xacmlUserGroup` (default `xacml-users`) |
| `POST /xacml/pep/register`, `GET /xacml/pep/policies`, `GET /xacml/pep/authzen-catalogue`, `GET /xacml/pep/authzen-callers`, `POST /xacml/pep/heartbeat`, **`POST /xacml/pip`** | `REMOTE_PEPS` | `roles.remotePepGroup` (default `remote-peps`) |

**ONE GROUP GRANTING BOTH WOULD BE THE MISTAKE.** The `/xacml/pep/*` endpoints
hand out the documents this service enforces its own access with, and
`/xacml/pip` hands out a named person's directory attributes; the three above
them answer questions put to the repository's root policy. Admitting a caller to the second set must
not silently admit it to the first, which is why there are two built-in roles
and two settings rather than one of each. `common/roles.js` argues it at the
role and `common/access_gate.ts` at the resource — `xacml-api` and
`xacml-pep-api` are two ids precisely so an operator narrowing one surface and
not the other has two names to target.

**`POST /xacml/pip` IS THE ONE ENDPOINT WHOSE ROLE DOES NOT FOLLOW ITS PATH**,
and that is deliberate rather than an oversight: what comes back is somebody's
personal data rather than a rule anybody may check, so it takes the narrower
role even though it sits outside `/xacml/pep/`. The `Requires` column on `GET
/xacml` exists so that a role never has to be inferred from a path.

**THE MECHANISM IS ONE CHAIN, DESCRIBED ONCE**, in *Four links* above: a
verified certificate, a DN resolved to an entry, the roles that entry holds,
and a policy decision. `xacmlAccess()` and `pepAccess()` in `xacml/xacml.ts`
are the two call sites and differ only in the role and the resource they name.

## Where a policy lives

`ou=policies` in the embedded directory **is** the repository, the way
`ou=federations` is the federation register. That buys three things and none of
them is tidiness: persistence in all three modes with no driver change,
per-realm isolation for free, and `ldapsearch` and `/admin/ldap/directory` as
inspection tools that already exist.

The entry holds the **document as authored** and everything else on it is
derived at write time — so where the two disagree, the document wins. A write
goes through static validation, so a policy that does not typecheck is refused
while somebody is still looking at it rather than going Indeterminate on every
request for ever.

**One policy is seeded**, role-based, and the seeded directory was given
`employeeType` to match it — alice and bob are staff, carol is admin. The two
seeds have to agree or neither demonstrates anything: a policy granting on an
attribute nobody has answers Deny for everybody, which looks exactly like a
broken PDP.

## The one rule this directory is built on

**One model; XML, JSON and ALFA are three renderings of it.**

`xacml_model.js` is what all three readers produce and what `xacml_pdp.js`
evaluates. **If a function in `xacml_pdp.js` ever asks which syntax a policy
arrived in, this separation has failed** and the fix belongs in the model
rather than in the evaluator.

The argument is `common/crypto_impl/xmldsig.js`'s, one layer up: a grammar is a
READING, and three readings are three chances to disagree with the PDP at the
far end — which for authorization means a decision nobody can reproduce. It is
also what makes ALFA cheap when it lands: a parser and an emitter, not a second
policy system.

## A NAME A POLICY OR A CALLER CHOSE IS AN OWN MEMBER, OR IT IS ABSENT (2026-11-12)

Every table this directory looks a chosen name up in — the function library,
the combiners, the datatypes and their short names, the legacy datatype
aliases, a policy's variables, the repository a reference resolves through,
ALFA's categories, algorithms, function names and declared attributes, the
row grammar's categories and datatypes, GNAP's drop and interaction words —
is a plain object, and `table[name]` follows the prototype chain. So
`constructor`, `toString` or `__proto__` answered a function or
`Object.prototype` where an unknown name answers nothing: an FGA or AuthZEN
row accepted `category: "constructor"`, a JSON request's `DataType:
"toString"` escaped its refusal, a VariableId `toString` was "defined twice",
a reference to `constructor` was a cycle, a FunctionId `toString` "takes 0
arguments", an interaction word `constructor` stopped asking for the person.
**Every such read goes through `common/own_members.ts`** (`read()`, `has()`),
and every write into a map read that way through its `put()`, so a name
called `__proto__` is a member rather than the map's prototype (a
VariableId `__proto__` was refused before and is a variable now; a policy
id `__proto__` in `XacmlStore.repository()` resolves as it did).
`XacmlEditor.ownStep()` (#1664) is that file's `has()`. An own member
answers what it answered before. `tests/own_members.js`.

## Where it stands against the conformance suite

**454 of 455 mandatory cases**, with the one exception recorded in
`conformance/MANIFEST.js`'s `EXPECTED_FAILURES` and argued there. The
VENDORED OASIS conformance suite is **Apache-2.0 rather than this repository's
Business Source License** and says so in `conformance/LICENSE`.

```
IIA   attribute references     18 of 18
IIB   target matching          55 of 55
IIC   the function library    261 of 261
IID   combining algorithms     57 of 57
IIE   policy references         2 of 3    (IIE003 — see EXPECTED_FAILURES)
IIF   other mandatory           3 of 3
IIIA  obligations              58 of 58
```

**The first run scored 6 of 455 and the second 434**, and what the difference
between those two numbers records is worth more than the final one: every
defect below was found by the suite and none of them would have been found by a
test written here.

## Four more defects, from phase two, and all four were silent

The engine's seven are below; these are from wiring it up. Every one of them
left a service that started, answered every request, logged nothing unusual,
and decided incorrectly. `tests/xacml_service.js` asserts each.

1. **LDAP ATTRIBUTE NAMES COME BACK LOWER-CASED.** RFC 4512 makes them
   case-insensitive and this directory normalises them, so a store that asks
   for the `xacmlPolicyDocument` it wrote gets `undefined`. Every field of
   every policy read back empty, `root()` found nothing, and the PDP answered
   NotApplicable to everything with a policy plainly sitting in `ou=policies`.
   `federation.js` reads `stored.attributes.fedid` in lower case for exactly
   this reason.
2. **THE SAME BUG IN THE PIP IS QUIETER AND WORSE.** A missing attribute is a
   *legitimate* answer, so there was nothing to report: the PDP simply decided
   as though the person held no roles.
3. **THE SEED RAN BEFORE THE STORE HAD ITS DIRECTORY.** `ldap_server.js` seeds
   at require time and fills the store's slot further down the same file. It is
   seeded at the slot-fill site now, guarded on the repository being EMPTY
   rather than on the container being new — those are different facts once
   persistence is in play, and the second would re-seed a policy an operator
   deleted on purpose.
4. **JSON HAS ONE NUMBER TYPE.** `5` and `5.0` both parse to `5`, so the
   integer/double distinction survives only in the source text.
   `xacml_json.js` re-scans the raw body for it.

## The seven defects the conformance suite caught, because each will be made again

Each of these produced an engine that looked correct, ran without error, and
was wrong. They are written up beside the code that fixes them; this is the
index.

1. **`errorHandler` is not a deprecated option in @xmldom/xmldom 0.9, it
   THROWS.** Passing both spellings defensively made every parse fail before a
   document was read — 449 cases reporting "could not be loaded" and naming an
   option rather than a policy. `xacml_xml.js`, `parseDocument()`.

2. **A combining algorithm CONTROLS EVALUATION; it is not handed results.** The
   specification's pseudocode returns from inside the loop, so a
   `deny-overrides` set whose fourth policy denies never evaluates the fifth.
   Evaluate all five and combine afterwards and the DECISION is identical every
   time — but the fifth policy's OBLIGATION is now in the response. Eight IID
   cases. `xacml_pdp.js`, above `COMBINERS`.

3. **NaN equals NaN.** XML Schema defines xs:double equality over a value space
   holding exactly one NaN and XACML defers to it, so `double-equal(NaN, NaN)`
   is True — the opposite of IEEE 754 and of `a === b`. IIC350, IIC358.
   `xacml_datatypes.js`, the double row.

4. **Date arithmetic is on the LOCAL components; the timezone is a label.**
   Normalising to UTC, adding, and re-labelling with the original offset shifts
   twice and lands five hours out — while still producing a well-formed
   dateTime. IIC102, IIC104. `xacml_functions.js`, `addSeconds()`.

5. **`only-one-applicable` must go through the same obligation collection as
   every other algorithm.** Returning the selected policy's result directly
   dropped the POLICY SET's own obligations and kept the policy's, which is a
   response that is right about the decision and short by half on what the PEP
   must do. IIIA025, IIIA026. `xacml_pdp.js`, `evaluatePolicySet()`.

6. **XACML is statically typed and a policy that does not typecheck must be
   REFUSED at load.** Five cases exist for this and for nothing else — a
   designator passed where a primitive is required (the commonest mistake in
   hand-written XACML), a Condition returning an integer, a string literal in
   an integer argument, a literal substring index out of range. Without the
   check all five load happily and produce a decision. `xacml_validate.js`.

7. **A rule's obligations must be resolved AT the rule.** XACML 3.0 put
   obligations on rules as well as policies, and the rule is the only place its
   variables are still in scope. `xacml_pdp.js`, `firedRule()`.

## Three things about the specification that catch everybody once

**The version segment in a function URI is not predictable.** Most standard
functions are `1.0`; every function of the two DURATION types is `3.0`, because
those types moved namespaces; and the six higher-order functions split across
both — `any-of`, `all-of` and `any-of-any` are 3.0 while `all-of-all`,
`all-of-any` and `any-of-all` are 1.0. This is the specification's own
inconsistency. It is why `xacml_model.js` spells every identifier out instead
of building one by concatenation: a wrong URI matches nothing and fails as
`NotApplicable`, which is not an error anywhere.

**There are seven decisions, not four.** `Indeterminate{P}`, `{D}` and `{DP}`
exist for the combining algorithms and for nothing else, and collapsing them
makes `deny-overrides` return Permit where the specification says Deny — a
policy that permits because an attribute lookup failed. `externalDecision()`
folds them down ONCE, at the bottom of `evaluate()`; a second call site
anywhere is a bug.

**Every value is a bag.** An `AttributeDesignator` returns a bag even when it
finds one value, which is why `string-one-and-only` exists and why IIC003 is an
invalid policy. Nothing here ever holds a bare value, so there is no code path
where somebody has to remember to wrap one.

## What is not here yet

One gap in the engine, and it is the only one left.

* **`AttributeSelector` and the XPath functions.** A policy using one is
  Indeterminate rather than silently empty, which is the deliberate choice: an
  empty bag is a perfectly ordinary result a policy may be written to expect,
  so returning one would make an unimplemented feature look like a decision.

**Phase five was this list's other entry and it landed as described**, which is
worth recording because two of the three things this section predicted about it
turned out to be exactly right and one was left open: it IS `xacml-pep/`, its
own container; it DOES register over mutual TLS on the main port, which already
asks for a client certificate (`server.js`'s `requestCert: true`), so no new
listener was needed; and the certificate DOES map to a directory entry through
`ldap_server.js`'s `certificatePlan()` rather than a second mapping — though
only the NAMING is reused and no `ou=users` entry is created, because a PEP is
a component and that container counts people.

What this section did not settle was the DIRECTION, and it reads as though a
push were assumed ("policy push"). **It is a pull.** See below.

## What phase three actually cost outside this directory

For the next person adding a console surface, following the shape
`ssf/CLAUDE.md` records:

* `common/config.js` — the `xacml.pepBias` row (deleted by #596) needed
  **`enumValues`**, not `values`. The wrong key name is not a startup error: the setting loads, the
  service runs, and the settings form throws a 500 on the one page that draws
  it.
* `admin-ui/admin.ts` — the **tenth slot** `setXacmlPages()`, a `SETTING_HOMES`
  row (its absence is what the boot warning was about), an `XACML` group of
  four in `SECTIONS` with a `blurb` each, and three helpers exported that had
  been private: `configFormsFor`, `configSettingsJson` and `respondToAction`.
* `mgmt-api/admin_api.ts` — three GETs and a POST with ten documented actions
  (`import-alfa` arrived in phase four);
  `mgmt-api/admin_api_spec.ts` — `Xacml`, `XacmlPolicies` and `XacmlEditor`.
* `sts_metadata.ts` — **eight** `ENDPOINTS` rows, four of them console pages
  and four management API, which are again the ones a checklist forgets.

**The one thing that is not a file**: `protocolSettingsJsonFor()` is NOT the
JSON counterpart of `configFormsFor()`. It is keyed by admin.js's own
`PROTOCOL_SETTINGS_PAGES` table and **throws** for a path that table does not
carry — correct for the pages that file generates, and a 500 for one drawn
anywhere else. `configSettingsJson()` is the right function and is now
exported beside the renderer it belongs to.

## And what phase four cost, which was almost nothing outside this directory

ALFA is a SYNTAX, not a second policy system — the model, the validator and the
XML writer were already there — so it landed as one new module, one console
`<details>`, one `import-alfa` action and its `/admin-api` operation. No new
setting, no new route, no metadata row beyond the action's own.

**One defect, and it is the same one twice.** The emitter first wrote a policy's
`<Description>` as a `//` comment — and the tokenizer discards comments, so
every explanation survived being read by a person and was DELETED by the next
round trip. The XML reader had had exactly this defect a phase earlier. It is a
`description = "..."` property now, which reads back.

**The one thing a round trip through ALFA can still change**: a policy naming a
LEGACY 1.0 or 1.1 combining algorithm comes back naming the 3.0 one. They share
an ALFA name and they are genuinely different functions (see `xacml_pdp.js`), so
this is a normalisation rather than a no-op. It is called out where
`ALGORITHM_NAMES` is declared.

---

# Phase five: the remote PEP

**THE REMOTE PEP LANDED 2026-09-05 and its container is `xacml-pep/`.**

**THE PEP PULLS. THIS SERVICE DOES NOT PUSH.** Everything below follows from
that sentence, and this section's predecessor assumed the opposite — the *What
is not here yet* entry above said "policy push" and the direction was settled
the other way when the phase was built.

A remote PEP holds its own copy of the engine and evaluates locally, because a
PEP that asked this service per request would be `POST /xacml/pdp` with a
network hop in front of every access decision, and pushing *policies* to
something that could not evaluate them would make no sense at all — you would
push decisions. So something has to move policy from here to there, and it
could have gone either way. It goes by pull for three reasons:

1. **A push would be an outbound request CARRYING CONTENT.** Outbound requests
   are deliberately rare in this repository — `federation/federation_http.ts`
   and `ssf/ssf_http.ts` each argue their own — and a push would make policy
   DISTRIBUTION depend on this service being able to dial every PEP.
2. **A PEP knows when it is behind and this service does not.** Under push, a
   PEP that was down for a minute has a stale copy and no way to discover it;
   under pull, being current is checked on every poll. That inverts the
   failure: a partition leaves a pulling PEP KNOWINGLY stale rather than
   unknowingly wrong.
3. **It works where a PEP cannot be dialled** — behind NAT, in another cluster,
   on a laptop. A PDP that could only serve PEPs it could reach would be a PDP
   for one deployment topology.

## The nudge is the third outbound request here, and it is the weakest case

When the repository changes, this service POSTs a few bytes to each registered
PEP that gave a notify URL, saying only "something changed, pull now".

`xacml_pep_http.ts`'s header makes the argument from scratch, as
`ssf_http.ts`'s does rather than citing federation's — and it opens by saying
it can make NEITHER of the other two arguments. Federation's rule is *those
URLs are supplied by the caller, these by the administrator*, enforced by
refusing to take a URL at all; a notify URL is supplied by the PEP that
registers, which is a caller. SSF can say that RFC 8935 push IS the receiver
telling the transmitter where to post; there is no specification here at all,
because XACML 3.0 says nothing about how a policy reaches a PEP.

**What makes it affordable is the one thing the other two cannot say: the nudge
is never the mechanism.** It carries no policy, no decision, no event, no
credential and not even the new sync token. Every PEP converges without it. So:

* `xacml.pepNotify` can be turned off in a deployment with no egress and nothing
  breaks — not the feature, not a test, not a PEP;
* there is no retry and nothing to redeliver, because there is nothing to lose
  (where `ssf_http.ts` records a failed push on the stream and offers a
  redeliver, because a lost push IS a lost event);
* a refusal is worth RECORDING and never worth escalating.

**If a future change puts something in that body a PEP cannot get any other
way, the whole argument goes with it.** The body is three members, and a
fourth, `full`, on a Sync (2026-11-16): a flag asking the PEP to pull every
document whole, which carries no content. Keep it that way or move the
argument.

Its four bounds are `ssf.push*`'s four, deliberately — an off switch, a host
allowlist empty by default meaning any, https, and a timeout — because two
families making one outbound request each should be configured the same way
or the second is a surprise to anybody who read the first. The timeout is
SHORTER (2s against SSF's 10s) and that is the difference that follows from
the argument: a lost push is a lost event, so SSF waits; a lost nudge costs
one polling interval, so waiting is the expensive mistake.

**THE NUDGE IS HTTPS ONLY, AND ALWAYS VERIFIED, IN EVERY MODE (2026-11-14,
rcbj: "The listener for Remote PEP notify URLs should be HTTPS. Let's assume
always HTTPS").** Until then the https rule was `common/outbound_tls.ts`'s
(#171), with `xacml.pepNotifyAllowHttp` and
`xacml.pepNotifySkipTlsVerification` as the development-mode escapes, and an
https nudge verified against node's store and `xacml.pepNotifyCaFile` alone —
so the compose demonstration's nudge to the PEP's realm-issued listener was
refused "self-signed certificate in certificate chain" (`STS-XACML-0070`)
unless an operator copied the service Root into a CA file. Now:

* **No plain http.** `urlVerdict()` refuses an `http://` URL in both modes
  (`STS-XACML-0259`), with a sentence short enough for the console's reason;
  the PEP converges by polling, as one with no notify URL always has. The
  PEP's Settings tab refuses an `http://` `notifyUrl` (`STS-XACML-0239`), and
  the PEP refuses `POST /notify` over plain HTTP (`xacml-pep/CLAUDE.md`).
* **The trust needs no setting.** A PEP's HTTPS listener certificate is
  issued by the `pep-tls` Issuing CA of the realm it registered to
  (`xacml_pep_tls.ts`, the issue and the CSR paths), so `trust()` puts THAT
  CHAIN — the Issuing CA, the realm's Intermediate and the service Root,
  `pki.useCaseChainPems()` — beside node's store and the CA file, with the
  RFC 9525 host check against the notify URL's host and the path rules
  (`OutboundTls.verifiedOptions()`).
* **And the pin.** The Root vouches for every Issuing CA of every realm, so
  a chain that reaches this service's Root must have been issued, at the
  leaf, by THIS realm's `pep-tls` CA (`pinProblem()`, compared by SHA-256
  fingerprint because every realm's `pep-tls` CA has the same subject;
  `STS-XACML-0260`). A chain to the CA file or node's store is not this
  service's to judge further.
* **`xacml.pepNotifyCaFile` stays**, as an ADDITIONAL anchor for a PEP
  certified elsewhere; an unusable file still refuses (`STS-CORE-0104`).
* **The two escapes are RETIRED, NOT REMOVED** — backwards compatibility. The
  rows stay, so an appconfig file, the environment or a stored value naming
  either still loads, and the value is ignored; one that is on is logged once
  per process with `STS-XACML-0258` the first time a nudge would have read it.
  `REPLACED_SETTINGS`, which refuses to start, is the pre-1.0 pattern and the
  wrong one for a setting whose only effect was to weaken something.
  `notify.transport` keeps its four members: `allowHttp` and
  `skipTlsVerification` read `false`, `skipTlsVerificationSet` still says one
  is stored. `STS-XACML-0073` and `0074` are retired.
* **Paranoid PKI mode** holds the handshake through the door's
  `tls-server-outbound` purpose, which already named this nudge; the realm's
  chain is the dialer's own `ca`, so no new purpose row was owed.
* **`tests/outbound_tls.js` no longer lists XACML among its families**: what
  it asserts of a family — the escapes honoured in development — is what was
  removed. `tests/pep_listener_certificate.js` section F holds the trust:
  this realm's leaf with no CA file, a foreign CA refused and accepted by the
  file, another Issuing CA under the same Root and another realm's `pep-tls`
  leaf refused by the pin, plain http with the retired setting on.

**THE CONSOLE'S NOTIFY CELL IS SHORT (2026-11-14).** It drew the service's
whole sentence about an unusable URL, and the last nudge's, inline; it draws
*usable*, *unusable* with a one-line reason (read from the URL where it can
be, from the sentence for the allowlist, so the API grew no member), or
*none*, and two words for the last nudge, with the sentences in a
`<details>` — no script, `admin-ui/CLAUDE.md`'s rule. The PEP page's
Overview draws the same cell. `tests/xacml_pep_console.js`.

**On an active-active node the nudge waits for the COMMIT, and only there
(2026-09-15, #46).** It is fired from inside `xacml_store.write()`, and the PEP
answers 204 and pulls at once — through the load balancer, on whichever node
its connection lands. A node that is not the writer serves what has COMMITTED,
so it answered the old sync token with 304 and the PEP converged on its next
heartbeat: the suite's `cluster` mode measured 2018ms and 916ms against a
nudge worth tens of milliseconds (`sts_xacml_remote_pep` section 6). So
`afterCommit()` in `xacml.ts` dispatches it after `setImmediate` (the saving
request has usually answered, so its barrier's commit is the flush in flight)
and `persistence.commitThrough(writeGeneration())`. A failed commit still
nudges. One node, the cluster off and a dispatched pool dispatch at once as
before; this is not "waiting on somebody else's web server" — nothing awaits
the nudge, it only leaves later. `tests/cluster_observation_counters.js`
section 4.

## What is authenticated, and what deliberately is not

**EVERY ENDPOINT IN THIS FAMILY ASKS NOW.** This section said otherwise —
that `POST /xacml/pdp` and `GET /xacml/pep/policies` needed no credential — and
the second of those two sentences had already stopped being true when phase
five put `pepAccess()` in front of that endpoint. The full argument is under
*Two roles, two groups* above; what belongs here is the part that did NOT
change and is easy to lose:

* **A PDP is still not an authorization boundary.** The identity on the
  connection decides who may ASK; the identity the decision is ABOUT is in the
  request, and nothing `xacmlAccess()` learns reaches `decide()`.
* **A policy is still a rule, and a rule nobody can read is a rule nobody can
  check.** That argument did not stop being sound — it stopped being the whole
  question. Once the access and issuance PEPs were embedded, these documents
  became the ones this service decides its own admissions with, and *who may
  read it* is a different question from *is it redacted*. The documents are
  still shown in full to anybody the policy admits, which is the half of the
  old sentence worth keeping.
* **`/xacml/protected` had TWO gates about two different people** (until #596
  moved it to the remote PEP, which has no gate of its own): the
  caller needs `XACML_USER` to drive the embedded PEP at all, and the subject
  in `?subject=` is what it then enforces about. An admitted caller can still
  ask about somebody the policy refuses and watch it refuse — which is the
  whole demonstration, and it is why the two are not folded into one.

**REGISTERING ASKS A SECOND QUESTION ON TOP**, and it is a different one: not
who the decision is about but WHICH PEP THIS IS — because a registration writes
an entry, puts a row on the console, and supplies an address this service will
later dial. `xacml.pepRequireCertificate` is on by default.

It is a TURNSTILE like every other gate here: the certificate need not chain to
anything, on RFC 8705 section 3's argument that what is proved is that the same
key completed the handshake. And **a registration is not a permission** — an
unregistered PEP pulls and enforces exactly as well. `xacml_pep_registry.ts`
says so where the register is defined, because the shape looks like an
access-control list and is not one.

**The refusal distinguishes the two ways of arriving at it**, because they need
opposite fixes: a plain-HTTP listener cannot carry a certificate at all (turn on
`global.https`, or turn the requirement off), and an https one can (the client
sent none). A single sentence covering both would send half its readers the
wrong way.

## `POST /xacml/pip`: THE POLICY INFORMATION POINT, OVER HTTP

A remote PEP holds its own copy of the engine and evaluates locally — that is
the whole point of having one. What it does NOT hold is the PIP: **this
service's PIP *is* the embedded directory**, and a process in another container
has no access to it. So a policy with an attribute designator the request did
not carry resolves to an EMPTY BAG out there and to a real value in here, and
**the same policy decides two different ways in two enforcement points** —
which is the drift a shared repository exists to prevent, reappearing one layer
down.

The remote PEP could not have fixed this for itself. The attributes are on
directory entries this service owns, and handing a PEP an LDAP connection would
be a far larger grant than handing it an answer to one question.

### XACML defines no PIP protocol, so this invents as little as possible

The specification describes the PIP as an architectural component and says
nothing about how a PDP reaches one: no request document, no response document,
no binding. So the obvious move is to design an envelope of this service's own,
and **the first draft did exactly that — a JSON body with a `Designator` array
— and it was wrong.** The reason is worth keeping: an invented vocabulary means
the remote PEP has to TRANSLATE, and every translation is somewhere the two
engines can come to disagree about a datatype, a category, or what an absent
value means. That is the drift this endpoint exists to remove, moved into the
transport.

Both directions are **XACML's own XML**, and the envelope is two elements
thick:

```
REQUEST   <PIPRequest xmlns="urn:sts:xacml:pip:1.0">
            <Request …/>                  the request being decided — it names the subject
            <AttributeDesignator …/>      one per attribute wanted
          </PIPRequest>

RESPONSE  <PIPResponse xmlns="urn:sts:xacml:pip:1.0">
            <Attributes xmlns="…core:schema:wd-17" Category="…">   ← XACML's namespace
              <Attribute AttributeId="mail" IncludeInResult="false">
                <AttributeValue DataType="…#string">alice@…</AttributeValue>
            <Unresolved>                                          ← this service's own
              <Designator …><Reason>…</Reason></Designator>
```

Nothing in either direction is read or written by code invented for it. The
`<Request>` goes through `xacml_xml.js`'s `readRequest()` and each designator
through its `readExpression()` — **the same function that reads an
`<AttributeDesignator>` out of a POLICY**, so a designator means the same thing
on this wire as it does in the document the PEP is evaluating, including the
reading of `MustBePresent` where absent and false are recorded as different
things.

`readRequest()` is a SPLIT of `parseRequest()` and not a second reader: that
one takes a whole document, this takes the node, and the alternative was to
serialize the nested subtree back to a string — putting an XML serializer in
the path of every PIP query, which is exactly where namespace declarations
inherited from an ancestor go missing.

### The response shape is the whole design

A PIP's answer is a bag of attribute values for a designator, and the XACML XML
rendering of exactly that already exists: it is the `<Attributes>` /
`<Attribute>` / `<AttributeValue>` tree a `<Request>` is made of. **So what
comes back is a REQUEST FRAGMENT**, and a remote PEP has two ways to use it,
neither of which needs a translator:

* splice the `<Attributes>` into its own request and evaluate — after which its
  engine finds the values where a designator looks for them, which is precisely
  what happens in this process when the embedded PDP asks the embedded PIP; or
* read them with its own copy of `xacml_xml.js`'s request reader, which is the
  same code that read them out here.

**AN EMPTY BAG IS AN ABSENT `<Attribute>` AND NOT AN EMPTY ONE.** Two reasons
pointing the same way. The schema requires at least one `<AttributeValue>`
inside an `<Attribute>`, so an empty one is not a legal request fragment and a
PEP splicing it would build a request its own parser refuses. And *the request
did not carry it* is what an unresolved designator ALREADY looks like to every
engine — so a PEP that receives nothing behaves exactly as the embedded PDP
behaves when the PIP answers nothing, **with no branch of its own**. That is
the sentence the whole endpoint is arranged around.

**`MustBePresent` IS READ AND DELIBERATELY NOT APPLIED.** Whether an empty bag
ends a decision is settled by the designator and by the function the bag is
handed to, and both of those are in the CALLER's engine. Applying it here would
move a decision across a network boundary and answer a question nobody asked —
and it would make an absent attribute an ERROR on the wire, which is the
classic PIP defect in its most damaging form: `xacml_pip.ts`'s header opens
with why an absence must never become a presence or a failure.

### `<Unresolved>` is the one invented thing, and it is out of the way

A bag can be empty for five reasons that need five different fixes — a
designator in the wrong category, an AttributeId that is not a directory name,
a request naming no subject, a subject that resolves to no entry, and an entry
whose values will not parse at the declared datatype. **To a PDP they are one
empty bag and must be**; `xacml_pip.ts` logs the difference at debug level, in
a log that is in another container as far as the caller is concerned.

So the reasons come back in `<Unresolved>`, in **this service's own
namespace**, a sibling of the `<Attributes>` rather than inside them. A PEP
reading only the XACML core namespace — which is every PEP — never sees it, so
the payload stays a clean request fragment; a person or a PEP that wants to
know why finds it named. Putting a diagnostic INSIDE the core namespace would
have been the mistake: an element the OASIS schema does not define, in a
document a caller is invited to splice.

### What guards it, which is a shorter list than it looks

Every mechanism this service puts on an endpoint that takes a body from a
stranger, and the one that had to be given its own number.

| | |
|---|---|
| **Authentication** | a client certificate this service VERIFIED, whose subject DN resolves to a directory entry holding `REMOTE_PEPS`. Four links, none permissive — see *The three `/xacml/pep` endpoints are GATED* above |
| **Authorization** | `accessGate.check()` on resource **`xacml-pep-api`** and NOT `xacml-api`, which is the role not following the path said at the resource as well |
| **Rate limiting** | `websecurity.attemptShared('xacml-pip', …)`, **BEFORE the access check** |
| **Body ceiling** | `validation.parseXml()` at `CAP.LARGE` — a megabyte, where `app.js`'s parser stops at five |
| **Scalar bounds** | AttributeId, Category and DataType at `CAP.IDENTIFIER`; the subject at `CAP.NAME`; C0 refused in all four |
| **Designator cap** | fifty per query |
| **Cache-Control** | `no-store`, like every other answer here |
| **Audit** | `xacml.pip.query`, one row per call, naming the PEP and the subject |

**THE RATE LIMIT IS BEFORE THE ACCESS CHECK AND THAT IS THE ONE ORDERING
DECISION.** Put after it, an unadmitted caller could ask this service to build
a certificate chain, resolve a DN and evaluate an access policy as fast as it
could send — refused every time and never counted. Put where it is, the ADDRESS
bucket bounds that and the IDENTITY bucket bounds the case that actually costs
something: a caller this service ADMITTED reading directory attributes in a
loop.

**AND IT NAMES ITS OWN CEILING**, `xacml.pipMaxPerWindow`, default 600 over
`security.rateLimitWindowS`. `security.rateLimitPerIdentity` is FIVE because it
guards a SIGN-IN, where a sixth attempt a minute is somebody guessing; a PIP
query is one per access decision, so a busy enforcement point makes several a
second and every one is legitimate. **Sharing the sign-in number would have
switched this endpoint off for its only caller, and it would have done it
SILENTLY** — `xacml-pep/pip.js` treats a refused query as an empty bag and goes
on deciding on less information. `websecurity.js` argues the optional fourth
argument that carries it and `tests/portal_access.js` asserts it in process,
where the bucket can be cleared afterwards; the buckets are per PROCESS, so a
job that drove one over HTTP would leave the next job in the run meeting 429s
that were nothing to do with it.

**ENTITY EXPANSION IS NOT A HAZARD AND THAT IS MEASURED RATHER THAN ASSUMED.**
`@xmldom/xmldom` resolves no entity declared in a DTD, internal or external: a
billion-laughs document and an `<!ENTITY xxe SYSTEM "file:///etc/passwd">` both
come back as *entity not found* and are refused as not well-formed. So there is
no expansion limit to set and no external resolver to disable — and
`sts_xacml_endpoints.js` asserts it anyway, which is what stops it becoming an
assumption the day the parser is swapped.

**THE XML READERS ARE NOT RE-CHECKED AND MUST NOT BE.** What a `<Request>` and
an `<AttributeDesignator>` ARE is settled by `xacml_xml.js`, held to 454 of 455
OASIS conformance cases; a schema over either would be a second, worse reading
of a specification this directory implements. What those readers have no
opinion about is the LENGTH of a string, and three of the scalars come back out
again — echoed into `<Unresolved>`, named in the audit row, handed to
`locateEntry()`. That is the whole of what is added, and the line is worth
keeping: bound what a caller chooses the size of, and re-read nothing the
conformance suite already covers.

### Three smaller decisions

* **The entry is resolved ONCE per call**, for `resolverFor()`'s own reason: a
  caller asking about six attributes of one person must not be able to see six
  different people because somebody wrote to the directory in between. The
  lookup exists a second time only so `<Unresolved>` can say which reason
  applied, and it goes through the PIP's own `locateSubject()` rather than a
  new one, so "resolves" means one thing.
* **`IncludeInResult="false"` is written explicitly** rather than left to the
  default. A PEP that splices this into a request it then echoes must not start
  reporting this service's directory contents back to its own callers.
* **A malformed query is a 400 and never an empty answer.** This is
  `/xacml/pdp`'s 400-not-Indeterminate rule and it matters more here: an
  unresolved designator is a legitimate ANSWER, so a reader that answered one
  for a typo would be indistinguishable from the attribute being absent, and
  the caller's PDP would go on to decide on it.
* **`xacml.remotePeps` turns it off, not `xacml.enabled` alone**, and the first
  draft had that the other way. The endpoint is NAMED for the component it is,
  so putting it behind the registration feature's switch looks inconsistent —
  but **the switch follows the CALLER rather than the name**. An operator who
  turns remote enforcement points off has said they want none outside this
  process, and leaving an endpoint that hands a named person's directory
  attributes to anything holding `REMOTE_PEPS` still answering would be that
  switch not doing what its own description says. The role does not follow the
  path here and neither does the switch, and both point the same way — which
  makes it one decision rather than two exceptions.

### The remote PEP uses it, and the shape of how is the interesting part

**`xacml-pep/pip.js` is the client** and `xacml-pep/CLAUDE.md` argues it. The
one thing worth knowing from this side is why the endpoint is BATCHED: the
engine's resolver is synchronous — it is handed a designator and must return an
array — so the remote PEP cannot make an HTTP request from inside evaluation.
It walks the policy for every access-subject designator first, asks for all of
them in ONE query, and evaluates with a resolver over what came back.

**So the list is not an optimisation.** A one-designator-per-call endpoint
would have been unusable by the only caller it was built for, and that is the
constraint that decided the request shape rather than anything about
efficiency.

`tests/protocol/sts_xacml_remote_pep.js` section 3 drives the whole path: a
policy over `employeeType`, a container asked about `carol` with the request
asserting NOTHING, and a Permit that can only have come from her entry under
`ou=users` in this service's embedded directory — beside a name the directory
has never heard of, refused at both ends. **That section used to assert the
opposite**, in both directions, and the inversion is recorded where it happens.

### It answers ROLES as well as directory attributes (#303, 2026-09-27) — rule 3bq

A designator for `urn:sts:xacml:role` — the issuance PEP's own attribute —
is answered with the subject's CONFIGURED roles in the realm, through
`common/role_permissions.ts`'s `configuredRolesOf()`: held directly, through a
group or as an application, and ADMIN_READ / ADMIN_WRITE for a person from the
console roster. **The same answer token issuance gets**, which is the point:
a subject that arrived with no scopes — a person named in a SAML assertion, a
Kerberos principal, a `client_id` — is decided on the roles this service
would issue for, and the remote PEP (which asks `POST /xacml/pip`) decides on
the same roles as the embedded one. rcbj asked for it on #303: "a SAML
assertion won't have scopes".

* **A role is not a directory attribute**, so it is a designator of its own
  rather than an `urn:sts:xacml:attribute:` name: membership lives on the
  role entry, and group-held and console roles are resolved at decision time.
* **`urn:sts:xacml:subject-kind` says person or application** (`user`, the
  default, or `application`): a name alone cannot, and the two hold roles
  through different relations. The issuance PEP sends it; the remote PEP
  asserts it from `subjectKind` and `pip.js` forwards it in the query.
* **The built-in roles are not answered.** They describe the REQUEST — who
  authenticated, over what — which a PIP naming a subject cannot know; the PEP
  asserts them where it can. The subject is taken as authenticated: a PEP
  asking about a named subject is deciding for somebody it already accepted.
* An empty answer's `<Unresolved>` reason says the subject holds no configured
  role, as a person or an application.

### What it does not do yet

**Nothing caches.** A PIP query is made per decision, so a busy PEP asks the
same question about the same person repeatedly. That is correct and slow, and
correct is the right half to have first: a cache needs an invalidation story,
and the honest one here is that a directory entry can change at any moment with
nothing to tell a PEP about it. The nudge is the obvious mechanism and it
currently carries nothing by design.

## `ou=peps` is the register, and one certificate is one entry

The same arrangement `ou=policies` has, for the same three reasons — persistence
in all three modes, per-realm isolation, and `ldapsearch` for free.

The entry is NAMED from the client certificate through `certificatePlan()`'s
naming rule, which arrives across the slot rather than being reimplemented, so a
PEP is filed under exactly the name this service gives any certificate-borne
identity. A PEP that restarts UPDATES its row. Two instances sharing a
certificate collapse into one row, which is correct: the question the register
answers is *which PEPs am I distributing policy to, and are they current*, and a
nudge to either instance is a nudge to that deployment.

**No `ou=users` entry is created.** The NAMING is reused, the entry creation is
not — a PEP is a component and that container counts people, which is exactly
the distinction `spiffe_registry.js` had to draw between an ISSUANCE and an
AUTHENTICATION.

Three decisions on the row that each prevent a specific wrong reading:

* **A re-registration keeps the counters, the date and the DISABLED flag.** The
  last is the one that would have been a security-shaped mistake the other way
  round: a PEP an administrator stopped nudging must not re-enable itself by
  reconnecting.
* **A heartbeat SETS the counters rather than adding to them**, because a PEP
  reports its own cumulative totals — adding would count every decision once
  per heartbeat and produce a number that only goes up, looks plausible, and is
  wrong by a factor of the heartbeat interval. A PEP that restarts therefore
  makes the row go DOWN, which is honest.
* **A failed nudge does not move `lastSeen`.** A nudge that failed is evidence
  the PEP is NOT reachable, and letting it stamp liveness would make an
  unreachable PEP look freshly seen.
* **The reverse proxy's signal-stream health is a SNAPSHOT, held to counts and
  ages (#1760).** A PEP whose proxy built CAEP/RISC receivers sends `GET /`'s
  `proxy.signals` on each heartbeat as `signals`; the row keeps it in
  `xacmlPepSignals` (OID 753, a JSON document; the concept's `signals`).
  `PepRegistry.signalsOf()` keeps ONLY the twelve members and the library
  stores' five, each a non-negative integer or 0, and stamps `at` with when
  it arrived, whatever the PEP said: the PEP promises no client id, URL or
  error text, and this is the end that makes a `REMOTE_PEPS` holder unable
  to put text on an administrator's page. The same function reads the stored
  value, so an `ldapmodify` cannot get round it. **An absent member keeps the
  snapshot** (an older PEP, and the pull's own `heartbeat(name, {})`), `null`
  clears it, and a registration drops it, because a registration is a new
  process whose receivers the old numbers do not describe. A row with none
  answers `signals: null` and the console draws "not reported", which is a
  different fact from a proxy with no streams. Backwards compatibility both
  ways: an older PEP sends no member, and an older service's heartbeat reads
  the members it names and ignores this one.
* **A heartbeat value the service cannot hold (fuzz run #595).** The fuzz
  gate's pep-control-plane profile sent a stream `lastSuccessAgeMs` of
  2^53 - 1, a safe integer and no safe AGE: its instant fell before the
  earliest a Date holds, `signalsOf()`'s `toISOString()` threw a RangeError,
  and the answer was express's HTML 500 in all three fuzz realms. **Within
  `signals` and `listeners` a value is still held to its member**, the rule
  above: `timeOf()` answers null (no time) for an age older than the epoch,
  as for a negative one, so neither a report nor a stored value can throw.
  **The members the ENTRY stores are refused instead**, because beside the
  throw a `refused` of -5e22 had been stored as -5 (`parseInt()` of the
  exponent form) and `version` went into its attribute with a control
  character: `PepRegistry.reportProblem()` holds the counters
  (`policyCount`, `decisions`, `allowed`, `refused`, `undischargeable`) to
  non-negative safe integers, the text members (`syncToken`, `bias`,
  `resource`, `version`, `notifyUrl`) to strings with no C0, DEL or C1
  control character (or null), and `signals`, `settings` and `listeners` to
  an object or null, before `heartbeat()` reads or writes anything, and
  refuses with 400 `STS-XACML-0331` naming the member — `hostname`'s rule.
  `HeartbeatRequest` in `models/pep/pep_control_plane.tsp` says the same
  (`minimum`/`maximum`/`pattern`). The Rust PEP sends u64 counters and
  Strings and never meets the refusal. `tests/xacml_pep_heartbeat_values.js`
  holds both halves.

## A heartbeat writes the entry only when something durable changed (#1882)

**rcbj: "not every PEP heartbeat needs a directory write".** Until
2026-11-17 every heartbeat, and every pull naming a registered PEP (which
calls `heartbeat(name, {})`), REPLACED the whole entry: at the PEP's defaults
(a pull every 15 s, a heartbeat every 60 s) five rewrites a minute per PEP,
each a directory write, a persistence flush, a change-log row every node
applies and an audit `entry.update` row — about 1,900 of them on 8081, nearly
all changing nothing but `lastSeen` and the counters. And the write made a
pull, a GET, a request the cluster barrier holds.

* **DURABLE, in the entry, written when one changes**: identity, certificate
  subject, thumbprint, authenticated, notify URL, bias, resource, version,
  hostname, enabled, registration date, description, the administrator's
  proxy, settings and listener definitions, the sync token and policy count
  the PEP holds (being current is a fact an operator acts on, and it moves
  only when the repository does), the settings in force without their
  arrival stamp, and each listener's state, reason, address, port, renewal,
  certificate and POOL BOUNDS (`stats.pool.min` and `max`: the
  `threadPoolMin` and `threadPoolMax` in force, which move only when a
  tuning is applied). `PepRegistry.durableOf()` is the comparison; it is made
  against the ENTRY as stored, never the joined row.
* **The pool bounds were volatile until run #500 (2026-11-18)**, with the
  rest of the pool. A PEP reports a pulled settings token on a heartbeat
  that can come before its listeners are re-tuned; that heartbeat wrote the
  entry with the old pool and the next carried the new bounds as volatile,
  held in the receiving process for up to a journal interval. In a cluster
  the other node drew the old bounds for a minute, and
  `sts_xacml_pep_proxy_cluster` gave up on `api-http.threadPoolMax` after
  60 s, about a second before the record was due.
* **VOLATILE, in the minted store `xacml_pep_registry.liveness`**
  (`VOLATILE_ATTRIBUTES`): `lastSeen`, the four counters, the signal-stream
  health (counts and ages), the in-use reports' stamps, per-listener pool
  figures but its bounds and the connection figures, memory and path
  counts, and the last nudge's outcome — `recordNotify()` writes the store,
  never the entry, since a nudge
  goes to every PEP on every policy change. These move on every heartbeat
  of a PEP serving traffic, and none of them is a change to what the PEP is.
* **EVERY READER IS UNCHANGED**: `all()` and `read()` join the entry with
  the newest record of the SAME registration (`registeredAt`) seen LATER
  than the entry was written (`withLiveness()`); a tie is the entry's, so a
  registration in the same millisecond still drops what a new process has
  not reported, and a heartbeat in the same millisecond as the last is
  stamped a millisecond on. The console's PEP pages, `/admin-api/xacml/peps`,
  the clusters, the monitor, `notifiable()` and `stale` all read the join.
  The LDAP browser's `/admin/ldap/peps` puts the joined values over the
  entry's (`ldap_server.js`'s `withPepLiveness()`); `ldapsearch` on 389
  reads the entry as stored, as of its last durable write.
* **THE STORE IS AN OBSERVATION, MERGED BY RECORD, AND GLOBAL-TIER.**
  `observation: true`, so a heartbeat no longer makes a pull a writing
  request (`cluster/CLAUDE.md`, *A decision counted is not a write
  either*); `mergeRow` (`mergeLiveness()`) keeps the later registration's
  record whole, else the later-seen half and the later nudge, and
  `mergeOnApply` keeps an older arrival from going over a newer record held
  here. Global in `persistence/tiers.js`, because the entry is and every
  cell's console saw every heartbeat until then; a row is a component's
  times and counts.
* **JOURNALLED AT ONCE WHEN THE COUNTERS OR THE SIGNAL HEALTH'S EVENTS
  MOVED, OTHERWISE ONCE AN INTERVAL.** The events are every count and flag
  of the snapshot without its `at`, `oldestSuccessAgeMs` and each stream's
  times and poll count (`signalEvents()`). Counting the four counters alone
  held a set accepted in the receiving process for up to a minute, so in a
  dispatched service the worker answering `/admin-api/xacml/peps` drew the
  older snapshot and `sts_xacml_remote_pep` gave up after 40 s (run #478,
  single-node, mariadb and cluster). The interval is `journalIntervalMs()`,
  a fifth of `xacml.pepStaleAfterS` between 1 s and 60 s, measured from the newer of the entry's and the
  journalled record's `lastSeen`, which every process reads, so a node's
  workers and a cluster's nodes share one interval. The receiving process
  holds its newest record in `latest` (per process, per realm, a row per
  PEP) and reads it exactly; any other reads a `lastSeen` at most one
  interval old, a fifth of the stale threshold, which is why **the stale
  determination does not move** — it is still `(now - lastSeen) >
  xacml.pepStaleAfterS`, over the newest record. Derived rather than a
  setting, so the two cannot be set against each other. No timer flushes
  `latest`: the next heartbeat or pull journals it once due, and a process
  that stops takes at most the last interval's `lastSeen` with it.
* **Measured** (`tests/xacml_pep_heartbeat_writes.js`): 25 heartbeats and 5
  pulls that change nothing durable are 0 entry writes and 0 journalled rows
  (were 30 entry writes and 30 audit rows); a counter change is 1 minted
  row; a version, listener-state or sync-token change is exactly 1 entry
  write.
* **Backwards compatible**: an entry written before is read as it was until
  its PEP's next heartbeat, an older PEP's heartbeat is unchanged on the
  wire, a durable write still carries the newest volatile values into the
  entry, and no setting was added or renamed. A refused write is still 507,
  now only for a heartbeat that changed something durable.

## The sync token is a digest of what would be SENT

`syncToken()` hashes the documents of every ENABLED policy plus which one is the
root — exactly the bytes `GET /xacml/pep/policies` answers with. Three
consequences, and the third is why it is not a modification stamp:

* a policy edited and edited BACK does not invalidate anybody's copy, because
  the repository genuinely did not change;
* DISABLING a policy moves it, because a disabled policy is not sent;
* a change through ANY door moves it — console, `/admin-api`, `ldapmodify`,
  LDIF restore — because it is computed from the store on the ask. A counter
  incremented by the write path would have been correct for the two doors that
  remembered to increment it.

**A policy an application owns is not in it (#564)**, because it is never
sent: were it counted, every client created in a realm would make every
remote PEP re-pull bytes that had not changed. (The two service policies the
pull withholds BY NAME are still in the digest, as they were before #564: a
token that moves when nothing sent moved costs a re-pull and no more.)

`current` is therefore a COMPARISON this service performs rather than a claim
the PEP makes about itself.

## What modelling the control plane corrected (#1830, 2026-11-16)

`models/pep/pep_control_plane.tsp` describes every `/xacml/pep/*` answer and
`POST /xacml/pip` (`xacml-pep/CLAUDE.md`, *THE MODEL OF EVERY ENDPOINT*), and
writing it found seven places where the service was irregular; an eighth
came from the PEP's side. Each is fixed, and each keeps what a deployed PEP
relies on — it treats any answer but 200, 201 and 304 as a failure and reads
only the members the model names:

* **A pull touches the CERTIFICATE's row.** `GET /xacml/pep/policies?pep=`
  moved that row's `lastSeen` whatever the certificate said, so any
  `REMOTE_PEPS` holder could keep another PEP looking alive after it had
  gone. The name is `pepNameOf()`'s now, as on every other door: `?pep=` is
  read only with no certificate. A PEP sends its own name, which is its
  certificate's. (`authzen_evaluation.js` X11.)
* **`If-None-Match` is read on all five pulls** (`unchanged()`): RFC 9110
  section 13.1.2, `*` or a list, weak comparison. Only `?since=` answered
  304 before, so the header the PEP sends on the settings and proxy pulls
  was answered 200 with the whole body every time. `?since=` stays. (X12.)
* **Register and heartbeat answer the registry's status**, carried on every
  refusal and argued at `PepResult` in `xacml_pep_registry.ts`: 400 a bad
  name or hostname, 404 a heartbeat from no row, **503** no directory
  (`STS-XACML-0026`), **507** the directory refused the write — which
  `writePep()` does only at `xacml.maxPeps` or the entry cap (`0027`).
  Register answered every refusal 400 and the heartbeat every one 404, so a
  fault of this service's read as the PEP's. (`xacml_pep.js` 4, X13.)
* **`POST /xacml/pip` answers EVERY refusal as a `<PIPError>`** — the gate's
  403 (`error="access_denied"`) and the off switches' 501
  (`not_implemented`) as well as its own 400 and 429 — through an `xml` flag
  on `offCheck()`, `remotePepOffCheck()` and `pepAccess()` that only the PIP
  passes. The codes recorded are unchanged; every other door stays JSON.
  (X14; `sts_xacml_endpoints.js` reads the two members out of the XML.)
* **The listener certificate's 200 carries no `ok`**, which was
  `issueForListener()`'s own flag sent whole. (`xacml_pep_proxy.js` L9b.)
* **The nudge's `pdp` names the realm's PDP**: every caller passed `''`, so
  it was always empty. An empty issuer asks `PepNotifier`'s `pdpIdentity()`
  — the base `/xacml/pep/*` is served under, pinned where a listener or
  `global.publicBaseUrl` pins it, else that of the request that made the
  change (`helpers.urlOf()`), realm prefix included; `''` only with neither,
  the rule every request-less URL here follows. KEPT rather than removed,
  because the model and the PEP's generated type require it; the PEP reads
  nothing in the body but `full`. (`pep_listener_certificate.js` F1d.)
* **A route may not be `/.iya-pep` or under `/.iya-pep/`** (`STS-XACML-0300`,
  `PepProxy.reservedPath()`): the proxy keeps that prefix for its callback
  and sign-out and answers 404 (`STS-XPEP-0134`) to the rest, and an updated
  PEP refuses the whole configuration holding such a route and keeps its
  last good one. A document stored before this fails the pull's validation
  like any stored document the grammar refuses — logged `STS-XACML-0200`,
  pulled as `configured: false`, so the proxy answers 404 until an
  administrator saves it again. (`xacml_pep_proxy.js` A3, A6, C9b.)
* **Every validation door answers ONE 429 shape**: `{ error:
  "too_many_requests", error_description, retryAfterS }`, with `Retry-After`.
  `basic`'s own lockout (`STS-XACML-0205`) answered `{ valid: false,
  retryAfterS }` and the doors' shared limiter (`0215`) an `Error` with no
  wait in the body, so one status had two bodies. The PEP reads
  `retryAfterS`, else the header, from any 429, so a deployed one reads the
  new body as it read the old. (`xacml_pep_proxy.js` G3.)

## `GET /xacml/pep/authzen-catalogue` — the pull's other half (#1179)

**The container answers AuthZEN as an edge PDP** (`xacml-pep/CLAUDE.md`), and
an AuthZEN request means nothing until the realm's attribute catalogue says
what each property is. So the catalogue travels with the policies: this
endpoint answers the rows `authzen/authzen.ts` maps a request with — read
through the same `authzen_catalogue.ts` `rowsOf()` off the same
`sts-authzen-api` object, written back through `valueOf()` — and the AuthZEN
settings that change the mapping or the answer, behind `pepAccess()` and
`REMOTE_PEPS` like the policy pull (rcbj's decision on #1179).

* **ITS OWN SYNC TOKEN**, a digest of exactly the body it sends (the realm,
  whether the object exists, the rows, the settings), with the same ETag and
  `?since=` 304. **Not folded into `syncToken()`**: that token is what a
  heartbeat compares, and `/xacml/pep/policies` stays as it is.
* **A VALUE THAT IS NOT A ROW IS LEFT OUT AND COUNTED** (`leftOut`,
  `STS-AUTHZEN-0060` in the log), never sent — the evaluation leaves it out
  too, so the edge maps that property as undeclared exactly as this service
  does. The container re-reads every row it is sent through its own port of
  the grammar anyway.
* **NO NUDGE.** The registry's change observer is about the policy
  repository; a catalogue change reaches the container on its poll. Nudging on
  it would be a change to the nudge, which this ticket does not make.
* **`GET /xacml`'s endpoint list does not name it**, because that document is
  one of the existing endpoints rcbj said stay unchanged; `/admin/sts-metadata`
  and `/admin/xacml`'s protocol-endpoint table do.
* **`fgaApplications`: THE APPLICATIONS THAT ENFORCE FINE-GRAINED
  AUTHORIZATION (#564, P7).** The edge FORWARDS an evaluation about one of
  them to this realm's `/access/v1/evaluation` (rcbj's decision of
  2026-10-30; `authzen/CLAUDE.md`), so it has to know which. The list is
  `applications.applicationsEnforcingFga()`, sorted, an ADDITIVE member —
  identifiers only, never a policy, so `/xacml/pep/policies`' withholding is
  untouched — and **inside the catalogue's digest**, so switching
  `appFgaEnforced` moves the token and the edge pulls again on its poll.
  Here rather than on the policy pull because it changes what the AuthZEN
  answer IS, which is this pull's subject, and because the policies' token
  is what heartbeats compare. **A registry that cannot be read refuses the
  whole catalogue** (500, `STS-FGA-0108`) rather than sending an empty
  list: an empty list would have the edge decide every enforcing
  application from the root, and a refusal keeps it on the list it holds.

`tests/authzen_evaluation.js` K holds it in process: the gate (no certificate,
and an AUTHZEN_PEPS caller that is not a remote PEP, both 403), the rows and
settings, the ETag and 304, a token that moves with a row and a setting, and
`/xacml/pep/policies`' token that does not; and (K10–K12) `fgaApplications`
through a switch flip, which moves this token and not the policies'.

## `GET /xacml/pep/authzen-callers` — who the edge PDP admits (#1189)

**rcbj's decision on #1189: the edge PDP admits callers by PULLING the
service's answer**, not by the list its operator configures, **and the cost
is accepted: anybody holding `REMOTE_PEPS` can read who may ask the PDP.** So
this endpoint answers, behind `pepAccess()` like the other two pulls,
`authzen/authzen_caller.ts`'s `edgeCallers()`: for every caller the
access-control policy admits to `/access/v1/*` now, its name, the SHA-256 of
each certificate that names it, its application scope and the endpoints it is
admitted to. `authzen/CLAUDE.md` argues what is a candidate and what is left
out; what belongs here is the door.

* **THE NAME AND THE DIGEST ARE THE DOOR'S, NOT A SECOND READING OF IT.**
  `certificateCaller(der)` is `callerIdentity()` for a certificate in hand:
  the naming is one private `namedBy()` both call — `certificatePlan()`
  across the register's slot, the stored-certificate lookup for an outside
  authority — over `X509Certificate.toLegacyObject()`, the object
  `getPeerCertificate()` hands a handshake, so the DN cannot be spelt twice.
  What a handshake's `mtls.peerVerified()` adds is applied to the DER the
  same way: `tls_client_certificates.js`'s `checkCertificate()` (the half of
  `checkSocket()` that needs no socket) and `revocation_status.js`'s
  register-only `localVerdictFor()`. Whether the CHAIN verifies is the one
  thing not asked: that is each door's own, against its own trust anchors.
  `tests/authzen_evaluation.js` P holds the name to the actor of a real
  handshake's audit row, for a stored outside certificate and for one the
  realm issued.
* **ITS OWN SYNC TOKEN**, a digest of exactly the body it sends, with the
  same ETag and `?since=` 304 and `no-store`; neither the policies' token nor
  the catalogue's moves with it. It moves with a membership, a certificate
  (stored, issued, expired, revoked in the register), a scope, the realm's
  `authzen.callerAuthentication` and the policy's answer. **NO NUDGE**, for
  the catalogue's reason: the edge converges on its poll.
* **NOTHING BUT NAMES, DIGESTS AND SCOPES** is sent — no certificate, no
  attribute, no group membership — and the counts of what was left out.
* **`GET /xacml`'s endpoint list does not name it**, for the catalogue's
  reason; `/admin/sts-metadata` and `/admin/xacml`'s protocol-endpoint table
  do.

## The remote PEP as a reverse proxy (#1760, phase 1)

A registered PEP may stand in front of an application. Its configuration is
ONE attribute on its own `ou=peps` entry, `xacmlPepProxy` (OID 752, a JSON
document; the concept's `proxy`), so a registration and a heartbeat carry it
(`register()` keeps the existing value, `attributesOf()` writes it when set)
and Forget removes it with the row. `xacml_pep_proxy.ts` is everything the
service decides about it; `xacml.ts` answers the doors and `xacml_admin.ts`
the two actions.

* **ONE GRAMMAR, ASKED TWICE.** `validate()` is the issue's D2, closed (a
  member it does not name is refused by name), each refusal its own code
  (`STS-XACML-0184`–`0199`). `set-pep-proxy` stores what it normalised; the
  pull validates the stored text again, so a value an `ldapmodify` wrote that
  does not validate is pulled as `configured: false` and logged
  (`STS-XACML-0200`). In product `publicBaseUrl` must be https
  (`mode.servesProxyBrowsersInTheClear()`).
* **HOW THE IDENTITY REACHES THE APPLICATION IS A ROUTE'S `identity` (D11)**,
  `{ mode, headers: [{ name, claim }], separator }`, default mode `headers`
  with no header (`subjectHeader` and `mechanismHeader` are gone, refused as
  members the grammar does not name). At most 16 headers; a name is an RFC
  9110 token, unique without case, and not a hop-by-hop or framing header,
  `Authorization`, `Cookie`, `Set-Cookie`, `Host`, `Forwarded` or
  `X-Forwarded-*`; a claim is one of `sub`, `username`, `email`, `name`,
  `given_name`, `family_name`, `groups`, `mechanism`, `acr`, `amr`; the
  separator one printable ASCII character that is not a letter or a
  number (`STS-XACML-0224`-`0227`). Mode `saml` names no header and needs
  the application's `samlEntityId` and a registered
  `samlAssertionConsumerService` (`0228`), mode `jwt` an audience (`0218`).
  The normalised form keeps an empty `headers` in every mode, so a saved
  document validates again; a public route accepts only that default.
* **`GET /xacml/pep/proxy`** is the AuthZEN pulls' shape: `pepAccess()` READ,
  its own sync token over exactly the body (ETag, `?since=` 304), `no-store`,
  no nudge. The PEP is named by its certificate, the registration's rule.
  A policy write does not move the token.
* **THE FOUR DOORS** (`introspect`, `basic`, `saml`, `session`, all POST) go
  through `validationDoor()`: the PIP's rate limit and ceiling
  (`xacml.pipMaxPerWindow`, before the gate), `pepAccess()` READ, one audit
  row `xacml.pep.validate` naming the PEP, the mechanism and the outcome and
  never the credential, `no-store`, and a closed answer. Basic is
  `credentials.verifyAsync()` behind door limits `xacml-pep-basic` (they
  count only where passwords are verified, product) and the password door
  `xacml-pep`, the sixth app-password door: in product a person who holds or
  owes a second factor (everybody, by default) presents an app password
  scoped to `xacml-pep`, never their own password. Introspection is
  `oauth2.introspectionFor()` (`introspectionOf()`, no client
  authentication and no section 5 narrowing — the PEP checks `aud`). SAML
  requires the signature at the ROOT assertion with its reference naming the
  root's ID, so a signed assertion nested in an unsigned one is refused.
* **A ROUTE NAMES AN APPLICATION (D10)** by its identifier in the realm's
  registry (`application`, required on a non-public route, refused on a
  public one) and the configuration copies nothing from it: `resolveRoute()`
  reads, at the save and again at every pull, the audiences an access token
  for it carries (`oauthAudience` and `oauthPermissionBaseUri`; there is no
  `audience` member), its `samlEntityId`, and for a session route its
  confidential OIDC client (`client_secret_basic` or `client_secret_post`,
  the code grant, `<publicBaseUrl>/.iya-pep/callback` registered, an
  unexpired secret; `STS-XACML-0217`–`0223`). The pull carries each route's
  `resolved` and `realm.clients[clientId] = { clientSecret,
  tokenEndpointAuthMethod, redirectUri, scopes }` with the secret OPENED, and
  `realm.tlsCaChain` (`tls_server.listenerChainPem()`, the bundle
  `GET /tls/server-certificate` answers). The token is a digest of that
  body, so a rotated secret or an edited application reaches the PEP on its
  poll; an application deleted or no longer qualifying leaves its route
  `usable: false`. The secret is on no console page and in no `/admin-api`
  answer: a PEP's row carries `proxyRoutes` (`route`, `application`,
  `usable`, `why`), and the application's page (`pepRoutes`) the routes
  that front it. Nothing is created for a PEP; a session route needs an
  https `publicBaseUrl`, and `signals` (default true) says whether its
  sign-out reaches the proxy by CAEP/RISC or by `POST /xacml/pep/session`.
* **THE BASIC TICKET AND `POST /xacml/pep/identity` (D11).** A valid Basic
  answers `ticket` as well: 256 random bits, kept under its SHA-256 in
  `xacml.pepTickets` (a `realms.map`, persisted and cell-tier, its expiry on
  the row, 10000 per realm with the oldest dropped, on `/admin/caches` as
  `xacml.pep-tickets`), bound to the PEP and the subject, 120 s, not
  single-use. The fifth door, through `validationDoor()`, takes `{ route,
  evidence: { kind, value }, claims? }`: the route must be a non-public route
  of THIS PEP's stored configuration (`0230`), and the evidence is validated
  again: an access token active in this realm and issued to or for the
  route's application, a SAML assertion through `saml()` with the
  application's entity ID as the audience, or a ticket handed to this PEP and
  unexpired (`0231`, `0232`). Mode headers answers `{ claims }` off the
  directory entry (`saml/person_attributes.ts`, `groupsOfUser()` as a
  list), narrowed by `claims` to the route's own (`0229` otherwise); mode jwt
  `{ accessToken, tokenType: "Bearer", expiresIn }` through
  `oauth2.accessTokenAsync()` after `gate.check()` at `issue-access-token`
  (so it is in the token register); mode saml `{ samlResponse, acsUrl,
  notOnOrAfter }` from `saml2_sso.pepProxyResponse()`, the unsolicited
  Response's builder, policy and encryption rules with no InResponseTo. A
  policy refusal is 403 (`0234`), anything that cannot be issued 422
  (`0233`, `0235`); every answer is audited as `xacml.pep.validate`.
* **THE CONSOLE EDITS THE DOCUMENT WHOLE**: the Remote PEPs tab draws each
  PEP's routes as a table and the document in a textarea; a route is added,
  removed or moved by editing the list. **A route's identity is edited on
  the route's own page** (since 2026-11-14, rcbj: the per-route sections
  under the tab's table moved to the route drill-down), in the identity part
  of its `set-pep-route` form: a mode choice, a header/claim table (the
  route's rows and two empty ones) and the separator, read by
  `identityFromForm()`. `set-pep-route-identity` still replaces one route's
  `identity` alone for `/admin-api`, saved through `set-pep-proxy`'s checks;
  no console form posts it now, and the tab draws no identity form.

`tests/xacml_pep_proxy.js` holds all of it in a child process.

## A remote PEP's decision records (#1827, 2026-11-16)

**A remote PEP decides in its own process, so until #1827 the only record of
what it decided was a line on its own standard output**: the heartbeat
carried the counts and nothing else, and a removed container took its
decisions with it. Now the PEP queues a record per decision it MADE — a
`/protected` enforcement, an AuthZEN evaluation decided at the edge (never
one it forwarded: the service decided that one and wrote its own
`authzen.decision` row), and a reverse-proxy request to a route — and pushes
them in order, at least once, to `POST /admin-api/pep-audit`
(`mgmt-api/CLAUDE.md` argues the door, the scope, the role and the token).
`xacml/pep_audit.ts` turns each into one audit row:
`xacml.remote.enforcement`, `authzen.remote.decision` or
`xacml.remote.proxy`.

* **ONLY A PEP REGISTERED IN THIS REALM'S `ou=peps`**, under the name its
  token's subject carries (`STS-XACML-0287`, 404) — the heartbeat's rule. A
  cluster member is registered as itself, so its rows name the member.
* **TWO TIMES.** A row's `at` is when the service received it, because the
  audit chain is the order this process wrote rows in; `decidedAt` in the
  detail is the PEP's. Neither is rewritten into the other.
* **A REPEAT IS RECOGNISABLE, NOT SUPPRESSED.** The PEP removes a record only
  once `acknowledged` (the highest `seq` of the batch) covers it, so an
  answer lost on the way back sends it again; every row names the PEP, its
  process `instance` and the record's `seq`. Suppressing repeats across the
  nodes of a cluster would need a mark on the `ou=peps` entry — a new
  attribute, its OID and a catalog in every language — and was left out on that cost.
* **WHAT A ROW CARRIES** is what the PEP's log line carries: never a property
  value or an id an AuthZEN caller sent (decision 9 on #563), never a query
  string, cookie or token from a proxied request. The PEP's error code goes
  on the row where the table knows it, and the rows are `summarised`: the
  PEP logged each already.
* **A RECORD THE SERVICE CANNOT READ** (no positive integer `seq`, a kind it
  does not know) is counted `ignored` and logged once a push
  (`STS-XACML-0288`); a body that is no push is 400 (`STS-XACML-0286`) and
  the PEP drops that batch rather than send it forever.
* **NOTHING CHANGES ON THE ROW OR THE MONITOR**: the heartbeat's counters
  are still the source of the counts on `/admin/xacml/peps` and
  `/admin/xacml/monitor`.

## A remote PEP's own page, and the settings it manages (#1760)

**Each row of the Remote PEPs tab opens the PEP's own page**,
`/admin/xacml/pep?pep=<name>` (`admin-ui/web_pages.ts`' row, drawn by
`web_xacml.ts`'s `pepDetail()`), the application page's arrangement: the same
operation, `GET /admin-api/xacml/peps`, asked with `pep`, answers that row
alone and `found`. Its trail leads back to `/admin/xacml#xacml-tab-peps` (the
row's `upTo`, which the runtime reads so a drill-down whose list is another
page's tab has that page's crumb and nav). Six tabs: Overview (identity,
registration, version, state, notify URL, the two row actions), Decisions,
Settings, Listener (every listener, below; it was Listener certificate, with
the issue control that left the table, which it still carries), Reverse proxy
(the whole section that was on the tab, moved, with the route forms below)
and Signal streams (a table, one row per stream, below). The table keeps a Reverse proxy column: the route count, off,
or an unusable route.

**THE SETTINGS** (`xacml_pep_settings.ts`): every setting the container read
only from its environment, except the minimum to connect the first time, may
be set there. One attribute, `xacmlPepSettings` (OID 754, the concept's
`settings`), holds ONLY what is set; `set-pep-settings` REPLACES it from
`settings` (an object, a member it does not name refused by name) or from
the members on the body (the console's form, an empty box "not set"),
validated whole: `STS-XACML-0236` (not an object, an unknown member), `0237`
(type, closed set), `0238` (bounds), `0239` (text, URL, origin), `0240`
(product refuses `proxyUpstreamInsecure` and `proxyRpAllowInsecure` true —
`mode.skipsOutboundTlsVerification()` and `dialsPlainHttpOutbound()`), `0241`
(the directory refused). `clear-pep-settings` removes it. A registration and
a heartbeat keep it, as they keep the proxy.

* **`GET /xacml/pep/settings`** is the proxy pull's shape: `pepAccess()`
  READ, its own token over the body (ETag, `?since=` 304), `no-store`, no
  nudge, the PEP named by its certificate. A stored value that no longer
  validates is pulled as `configured: false` (`STS-XACML-0242`).
* **THE PRECEDENCE IS THE SERVICE'S VALUE, THEN THE ENVIRONMENT'S, THEN THE
  DEFAULT**, applied at the PEP (`xacml-pep/CLAUDE.md`, *Configuration*).
  Backwards compatible both ways: an older PEP never asks; a newer PEP's 404
  from an older service is its environment.
* **WHAT THE PEP HAS IN FORCE** arrives on its heartbeat as `settings` and is
  kept in `xacmlPepSettingsInUse` (OID 755) by `PepSettings.inUseOf()`, the
  signal health's rule: only the table's settings, each value of its type,
  each source one of `service`, `environment`, `default`, stamped on
  arrival; absent keeps, `null` clears, a registration drops. The row's
  `settingsCurrent` compares its token with what would be pulled now.
* **THE NOTIFY URL SET HERE IS THE ONE THE NUDGE DIALS**: `notifiable()`
  answers each row with `notifyUrlOf()`, so `xacml_pep_http.ts` is unchanged;
  the registered URL stays on the row as the PEP reported it.
* **NO PROSE IN THE CATALOGUE**: `settingsCatalogue` on the answer is keys,
  variables, types, bounds, defaults, when a change applies and whether the
  mode refuses `true`; the console's catalog says what each means.

`tests/xacml_pep_proxy.js` S holds all of it; `cargo test -p xacml-pep` the
PEP's half.

## A remote PEP's listeners (#1760)

rcbj (2026-11-14): the Listener tab "modelled after Server configuration →
Listeners", the HTTPS listener that exists as the default, and "an arbitrary
# of listeners (HTTP, HTTPS)". `xacml_pep_listeners.ts`.

* **THE ENVIRONMENT'S FOUR ARE THE BUILT-IN ROWS** (`BOOTSTRAP`: `api-http`,
  `api-https`, `proxy-http`, `proxy-https`, with the variables that bind
  them): what lets the PEP connect first, so read-only, and their ids are
  reserved. Their HTTPS pair is still `issue-pep-certificate`'s.
  **The two plain-HTTP ones are off by default** (rcbj 2026-11-14,
  `xacml-pep/CLAUDE.md` has the PEP's switch and precedence): each row
  carries `enable`, the variable that binds it (`PEP_HTTP`,
  `PEP_PROXY_HTTP`; `''` for the HTTPS two), a PEP reports one nobody turned
  on as `off` with the reason `http-off`, and the tab draws it without the
  alert, naming the switch. **A row reported `off` holds no port**
  (`environmentOf()`), so a listener defined here may take 9090 — the
  managed way to serve plain HTTP; one not reported holds its default.
* **THE DEFINED ONES ARE ONE ATTRIBUTE**, `xacmlPepListeners` (OID 756), a
  JSON array validated WHOLE on every write: `STS-XACML-0243` (shape, a
  stray member, more than 32), `0244` (id, reserved, twice), `0245`
  (protocol, purpose), `0246` (address, port), `0247` (an address and port
  another holds — a wildcard overlaps every address — including the
  environment's as the PEP last REPORTED them, or the container's defaults
  where it reported none), `0248` (certificate names on plain HTTP, more
  than 16, a name a certificate cannot carry, a key outside `ec-p256`,
  `ec-p384`, `rsa-2048`, `rsa-3072`), `0249` (product), `0250` (an unknown
  or environment id; renewing plain HTTP), `0251` (the directory refused).
  `set-pep-listener` adds or replaces by id (an edit keeps `renew`),
  `remove-pep-listener` removes, `renew-pep-listener-certificate` moves
  `renew`. A registration and a heartbeat keep the attribute.
* **THE PULL CARRIES THEM** as `listeners` on `GET /xacml/pep/settings`,
  under the settings' token, only when there are some (so a PEP with none
  pulls the body it always did). A stored list is read again WITHOUT the
  environment clash — the report can move after the write, and the PEP
  refuses a clash by failing to bind — and one that does not validate sends
  none (`STS-XACML-0252`).
* **THE KEY NEVER COMES HERE.** `POST /xacml/pep/listener-certificate`
  (`pepAccess()` WRITE, the heartbeat's gate) takes `{ listener, csr }`;
  `xacml_pep_tls.ts`'s `issueForListener()` reads the request through
  `cert_enrollment.ts`'s `parseCsr()` (the proof of possession verified),
  and issues from `pep-tls` through `pki.issueTlsServerKeyPair()`, which
  since #1760 takes a `publicKeyPem` and then generates and returns no key.
  The names are the PEP's derived ones and the definition's, never the
  request's; the slot is `<pep>/<id>`. The same key asked again, with the
  same names and a third of its life left, is answered the certificate held
  (`issued: false`); otherwise a new one supersedes it. `STS-XACML-0253`
  (no such HTTPS listener of this PEP), `0254` (the request), `0255` (the
  issue). The answer is `no-store` and audited as
  `xacml.pep.listener.certificate`.
* **WHAT THE PEP REPORTS** arrives on the heartbeat as `listeners` and is
  kept in `xacmlPepListenersInUse` (OID 757) by `inUseOf()`, the signal
  health's rule: the closed sets (`source`, `protocol`, `purpose`, `state`
  listening/waiting/failed/off, `reason` from ten), a reason that is not one
  read as `other`, the certificate's seven members as text without a control
  character, stamped on arrival; absent keeps, `null` clears, a registration
  drops. **No operating-system sentence is kept**: a `REMOTE_PEPS` holder
  writes it and an administrator reads it. **A reported `purpose` may be
  `crl`** as well as the two a definition may name (`REPORTED_PURPOSES`,
  2026-11-15): the PEP's CRL-only plain listener on `PEP_PORT`, which the
  console drew as the decision API. Every drawing asks
  `PepPicture.purposeOf()` — the Configured Listeners table, the listener's
  page and the picture — which reads an older PEP's `api` with the reason
  `crl-only` the same way; `tests/xacml_pep_console.js` LP.
* **THE PAGE** answers `listeners` (the definitions as the pull reads them),
  `listenersProblem`, `listenersInUse` and `listenerRows` — every listener,
  the environment's first, joined to its report and, for a defined HTTPS
  one, the certificate the realm issued it — and `listenersCatalogue`.
* **`requireClientCertificate` NEEDS A TRUST SOURCE** (2026-11-16,
  `xacml_pep_listener_tuning.ts`'s `parse()`, `STS-XACML-0281`, on
  `set-pep-listener` and `set-pep-environment-tuning` alike): a
  `trustAnchorsFile`, or — on an API listener — `trustIssuedClientCertificates`.
  The PEP's API listener had asked nobody and admitted everybody while it
  reported the requirement, and its proxy listener had asked everybody and
  admitted nobody; the cluster job's listener table found the first. What
  this service cannot see — `trustIssuedClientCertificates` with no
  `PEP_AUTHZEN_CLIENT_CA` in the PEP's environment, or an anchors file the
  PEP cannot read — the PEP refuses itself, fail-closed (`STS-XPEP-0137`,
  `xacml-pep/CLAUDE.md`). A stored tuning saved before this is not
  re-validated; the PEP holds it to the same rule.
* **PRODUCT MODE REFUSES A PLAIN-HTTP PROXY LISTENER** unless
  `xacml.pepPlainHttpProxyListeners` is on (`STS-XACML-0249`): the question
  is `mode.servesProxyBrowsersInTheClear()`, the proxy's public base URL's,
  and the setting is the administrator saying TLS ends in front of it.
  `xacml-pep/CLAUDE.md` argues why the environment's `PEP_PROXY_PORT` is
  not held to it.

### The routes one at a time, and the streams one per row

* **`set-pep-route`, `remove-pep-route`, `set-pep-route-application`**
  (`xacml_admin.ts`'s `withRoute()`) build the whole document from the
  stored one and hand it to the same `validate()` and `resolutionProblem()`
  as `set-pep-proxy` — one validator. `set-pep-route` takes `route` (an
  object) or the form's members (the authorization's are `authz*`, below),
  replaces a route of the same id where it stands keeping its `identity`
  and its `authorization` where the form says nothing of them, and inserts
  at `position`. A missing route
  object, a missing application or a position outside the list is
  `STS-XACML-0256`. The page carries `applicationChoices`, which names the
  chosen application and `routeDetailOf()` resolves against.
* **THE APPLICATION FIELD IS A SEARCH** (rcbj 2026-11-15: "an application
  name search field, results field, and the ability to choose a search
  result"), on Create a New Route and the route's page alike
  (`XacmlPage.applicationChooser()`), where it was a text box over a
  `<datalist>` of every application. It is the field search (#459) in a
  plain form, the person page's push destination's arrangement (#602,
  `admin-ui/CLAUDE.md`): a hidden `application` shown as a link, Clear, a
  box and Find asking `GET /admin-api/applications` five to a page (rule 7:
  no new operation), each result a Use. The presses (`fgsearch`, `fgadd`
  on `/admin/xacml/peps`, `WebAnswers.isFieldSearch()`) are answered in the
  browser by `ConsoleRuntime.pepRouteSearch()` and never sent; the form is
  drawn again from its draft in `state.pepRoute`
  (`WebAnswers.pepRouteState()`, `XacmlPage.routeOfDraft()`), keyed by the
  form (`new`, `page-<from>`), so nothing typed is lost. Each form's first
  button is a hidden default save, so Enter in a box saves and Enter in the
  search box is a Find. `tests/xacml_pep_console.js` A1–A8.
* **THE MANIFEST'S FOUR BUTTONS ARE ONE ROW** (rcbj 2026-11-15: "add a
  download button ... easy to save and transfer between remote PEPs. Put
  all of the buttons on the same row"), `XacmlPage.manifestButtons()`:
  Save (the editor form's, by `form=`), Remove (its own form, behind the
  route page's required checkbox), Download and Load from file. Download
  is a `data:` link with `download="<pep>-proxy.json"` (the certificate
  downloads' arrangement, `kit.base64Utf8()`) of the stored document from
  the answer the page holds, pretty-printed: no operation, and no secret,
  because the document's members are closed, its URLs carry no userinfo
  and a session route's client secret is read off the application at the
  pull. Load from file is `ConsoleRuntime.wireFileLoads()` (a
  `button[data-load-file]` opening a hidden file input whose
  `data-load-into` names the box): the file's text goes into the editor
  and nothing is sent until Save, whose `set-pep-proxy` takes another
  PEP's file only where every route's application resolves in this realm
  (`STS-XACML-0217` otherwise). `tests/xacml_pep_console.js` M1–M4,
  `tests/xacml_pep_proxy.js` M1–M3.
* **METHODS HAS A NONE AND AN ALL BOX on both route forms** (rcbj
  2026-11-15: "Clicking None deselects everything else. Clicking All
  deselects None and selects all other options"), drawn by
  `routeFields()` ahead of the seven methods, ticked to match the route.
  They carry NO NAME, so they are never posted and the route's `methods`
  is the list of real methods ticked. `ConsoleRuntime.wireCheckAll()`
  does the ticking (`data-check-none` beside the Policies checklists'
  `data-check-all`): both switches of a form and name share one refresh,
  so each shows the state — None when no method is ticked, All when
  every one is — and unticking None with nothing ticked leaves it ticked.
  **NONE IS DENY-ALL (rcbj 2026-11-15: "None should mean no methods
  allowed, essentially deny all")**: the empty list is stored, the route
  still matches its path, and the PEP refuses every request on it with 403
  AFTER asking the route's policy (`STS-XPEP-0116` where it permitted,
  `0086` where it denied) — so the decision is
  still made in XACML and counted, and a hand-written policy that permits
  too much cannot open a route that states no method; a simple or public
  route's generated policy is then the deny rule alone. **Any method is
  stated**: All stores the seven. A route with no `methods` member is
  refused (`STS-XACML-0262`), so the form posts `methodsGiven`, which makes
  no box ticked the empty list. The routes table draws *none (deny all)*.
  `tests/xacml_pep_console.js` B1–B8, `tests/xacml_pep_route_policies.js`
  1, 2.6–2.7, 4.4.
* **A ROUTE'S AUTHORIZATION (#1760, rcbj 2026-11-15)**: "the authorization
  section to have two approaches to the XACML policy: 1) select an existing
  XACML policy ... 2) provide the parameters for a very simple (and common
  policy)", and then "force them to pick one of these two policies or
  Public. But, that still results in a generated XACML policy representing
  the public access for this path. All authorization decisions are made in
  XACML." So `authorization` is a REQUIRED route member, `{ kind, policy,
  resource, actionModel, roles }` (`STS-XACML-0263` for none or a kind
  outside `policy | simple | public`, `0264` for a member of the wrong
  shape), and it REPLACED `public`, `resource` and `action`, with no
  backwards compatibility: the proxy is unreleased, and the validator
  refuses the old members as members it does not name. `kind: public` is
  what `public: true` was (no mechanism, no application, no identity).
  * **EVERY ROUTE NAMES ONE POLICY, AND THE PEP DECIDES IT WITH THAT POLICY
    ALONE**, never the realm's root: `policy` is a policy ENTRY'S NAME, the
    `name` of a row of `GET /xacml/pep/policies`, because a route is
    configured by name and a PolicyId is the document's. For `simple` and
    `public` it is always `pep-<pep>-<route>` (`PepProxy.
    generatedPolicyName()`; `validate(doc, pep)` writes it, so a document
    loaded from another PEP's file names THIS PEP's policy once saved). A
    policy the PEP does not hold refuses every request on the route
    (`STS-XPEP-0117`, whatever the bias). `xacml-pep/CLAUDE.md` has the
    PEP's half.
  * **THE SAVE ASKS MORE THAN THE GRAMMAR** (`xacml_pep_route_policies.ts`'s
    `problem()`, after `resolutionProblem()`): an existing policy held,
    enabled and SENT to a PEP — `pepPull()` withholds `access-control`,
    `role-issuance` and every application's policy (`0265`); a simple
    route's roles CONFIGURED roles of the realm, because the PIP answers
    `urn:sts:xacml:role` with configured roles only (rule 3bq, `0266`); a
    generated name not held by a policy without this route's mark
    (`0267`). The pull asks none of it again: a role deleted since must
    not take the whole route table down; the generated policy says what it
    said, and the route page reports a policy missing, disabled or
    withheld (`routeDetail.authorization.policy.problem`, and each row of
    `proxyRoutes`).
  * **THE GENERATED POLICY** is ALFA (`alfaFor()`) read by `xacml_alfa.ts`,
    written by `xacml_xml.ts` and stored by `XacmlStore.write()` — the
    editor's and `import-alfa`'s door, so it is statically validated like
    every other. First-applicable: one Permit per action with the route's
    roles (any of them), the resource-id `anyURI-equal` and the action-id;
    a public route's one Permit names the methods and no subject; and a
    LAST UNTARGETED DENY, because a route's policy is the route's whole
    decision and a permit-biased PEP would admit a NotApplicable. Its
    entry carries `xacmlPepRoute` = `<pep>/<route>` (OID 759, the
    concept's `pepRoute`), kept by every rewrite as `xacmlApplication` is,
    so `root()` never takes it (the "only enabled policy" fallback would
    otherwise make a realm's one route the root) and `write()` refuses it
    as the root (`STS-XACML-0267`). Every save of a simple or public route
    writes it again (unchanged text is not rewritten); before the document,
    so a PEP pulling the new table finds its policies.
  * **THE LIFECYCLE** (`XacmlAdmin.afterRouteSave()`): a rename removes the
    old route's generated policy (the new one was just written); a remove
    needs `removePolicy: true` when there is one (`0268`, rcbj: "ask for
    confirmation on remove") and takes it; a switch to an existing policy,
    and a route a whole-document save dropped, LEAVE it, unreferenced, and
    the answer's `policies.unreferenced` names it — an edit that did not
    ask never deletes a policy. `clear-pep-proxy` leaves them too.
    `generate-pep-route-policy` writes one again from the route as saved.
  * **THE RESOURCE.** A simple or public route's `resource` must be an
    absolute http(s) URL; empty, the save fills `defaultResource()`: the
    proxy's `publicBaseUrl` and the path, else the PEP's environment HTTPS
    proxy listener, `https://<the hostname it reports, else its name>:<the
    port it reported for proxy-https, else 9543>` — the address the
    configuration states first, then the one the PEP itself serves. An
    existing-policy route's empty resource is the request's normalised
    path, so a hand-written policy can still decide by path (the 8081
    demo's `pep-demo-routes` does). **The application's URL is
    `appHomePageUrl`**, its declared home page — where a person reaches it,
    so where the proxy stands — whose origin and the route's path is
    offered beside the default (`applicationUrl()`, a Use on the form) with
    a different origin flagged; redirect URIs are callbacks, not front
    doors, as the attribute's own row argues.
  * **THE ACTION** is `actionModel`: `method` (the HTTP method; an existing
    policy's default), `crud` (GET/HEAD/OPTIONS read, POST create,
    PUT/PATCH update, DELETE delete) or `read-write` (read, and write for
    the rest). A simple route is `crud` or `read-write`, a public route
    `method`. `PepProxy.METHOD_ACTIONS` is the table; the PEP's
    `ActionModel::action_for()` is its copy, both held by tests.
  * **THE CONSOLE** (`XacmlPage.authorizationFields()`): one selector,
    `authzKind`, with an empty first option on a new route, and each
    choice's fields a panel the runtime shows for the value
    (`ConsoleRuntime.wireChoicePanels()`, `select[data-panels]`); the
    shared Resource box with the default as its placeholder and where it
    comes from; the existing-policy chooser (`authzPolicy`, asking
    `GET /admin-api/xacml/policies?routable=true`, which gained `q`, `per`,
    `page` and `routable`, unchanged without them) and the action sent;
    the simple panel's model select (its own panels show that model's
    actions) and a box and a role chooser per action (`authzRole.<action>`,
    several roles, each with a Remove, asking `GET /admin-api/roles`); the
    route page's policy state and **Generate the policy again**. The
    choosers are the application chooser's presses on more attributes
    (`WebAnswers.pepRouteState()`, `pepRouteKindOf()`), answered in the
    browser and never sent; `find.attribute` keeps each chooser's results
    to itself. `set-pep-route-authorization` sets the choice alone for
    `/admin-api`.
  * **AN OLDER PEP AND A NEWER ONE DO NOT MIX**, deliberately: a PEP older
    than this reads no `authorization` and defaults `public` to false, so a
    table holding a public route is refused whole there (it keeps what it
    held); one holding none is accepted and decided by the root by path and
    method, with an empty `methods` read as any. Upgrade the PEP with the
    service. A newer PEP refuses an older service's document whole.
  `tests/xacml_pep_route_policies.js` holds it all through the real engine;
  `tests/xacml_pep_proxy.js` reads its older fixtures into this shape
  (`shaped()`).
* **A ROUTE'S OWN PAGE** (rcbj 2026-11-14: "click on a route name and go to
  another page and be able to update all the configuration values"),
  `/admin/xacml/pep/route?pep=&route=`: `getXacmlPeps` with `route` adds
  `routeDetail` (`routeDetailOf()`: the normalised route, its position and
  the count, usable and why from the resolution, the application as a
  reference and whether the chooser knows it, and every proxy listener with
  what the PEP reported — a route table is the proxy's, so every proxy
  listener serves every route). Its one form is `set-pep-route` with
  **`from`**, the route's current id: `withRoute()` takes only `from` out, so
  a rename to an id another route holds is the validator's own
  `STS-XACML-0192` and an unknown `from` is `0230`; and with **`mode`** the
  form's identity members become the route's identity
  (`identityFromForm()`, the one reading `set-pep-route-identity` shares).
  No per-route upstream exists in the model; the page says so. A PEP still
  holding the old document asks `/xacml/pep/identity` for the old id until
  its next poll, which is the rename's one cost. **Its sections are a fourth
  row of tabs** (rcbj 2026-11-15), `kit.subTabbedPanels()` inside the
  Configured Routes panel: Metadata (Effective state and Listeners that
  serve it), Settings (id, Matching's path and match, the application,
  Order), Authentication (mechanisms, signals, multiple accounts),
  Authorization (Methods with None/All, the choice and its fields,
  Generate the policy again), Identity sent to backend (credential
  forwarding and the identity), Remove the route (`XacmlPage.ROUTE_*_TAB`,
  rcbj: "Split the 'Edit the route' into a Settings tab ..."). They are
  fragments of the route's page, so the runtime's tab tree ends the trail
  at the open one and `markOpenTabs()` marks it while the rows above keep
  theirs (`tests/xacml_pep_console.js` RT). The old `#xacml-route-tab-edit`
  is an empty anchor at the top of Settings, so an old link opens Settings
  by the runtime's anchor-inside-a-tab rule, with no alias table.
  **EACH EDITING TAB IS ITS OWN FORM, AND SENDS `part`** (`settings`,
  `authentication`, `authorization`, `identity`): `withRoute()` reads only
  that part's members off the form (`XacmlAdmin.ROUTE_PARTS`) and keeps
  every other member of the stored route, so a Save on one tab cannot
  change or lose another's. Without `part` the members are the whole
  route, as before (backwards compatible); `part` on a route that does not
  exist is `0230`, an unknown one `0256`. The tabs other than Settings
  post the id unchanged, so a rename is Settings' alone and the landing
  reads `id`. A save lands on `#xacml-route-tab-<part>`
  (`WebAnswers.landing()`; no part, Settings). A chooser press keeps a
  draft PER TAB (`state.pepRoute.drafts`, `WebAnswers.pepRouteState()`,
  laid over the route by `XacmlPage.routeOfDraft()` for that tab's
  members), so a Find on one tab keeps what was typed on another.
* **THE VISUAL SUB-TAB** (rcbj 2026-11-15: "a new tab labeled Visual ...
  the remote PEP and a hierarchy of every configured path, its
  corresponding application object, and which role is allowed to access
  it. Show the configured listeners as well"), the Reverse proxy tab's
  fourth and last (`XacmlPage.PROXY_VISUAL_TAB`,
  `#xacml-pep-proxy-visual`), drawn by `web_pep_picture.ts` from the row
  the PEP page already holds — `name`, `hostname`, `listenerRows`, `proxy`
  and `proxyRoutes` — so the answer grew no member and no operation was
  added (rule 7). It is the console's pictures' arrangement
  (`admin-ui/CLAUDE.md`, *THE PICTURES ARE LAID OUT IN THE BROWSER*): inline
  SVG from the bundle, the delegation picture's palette, hexagon and text
  metric, `role="img"` with a title and a desc, a key, and the same tree as
  nested lists for a text alternative. The layout is by hand, no dagre: the
  PEP, its listeners (a green line from every proxy listener to the proxy,
  since every proxy listener serves every route), and the routes as a path
  trie (`PepPicture.tree()`, a segment no route stops at a chip, a run of
  them merged) whose rows own both coordinates, so it grows down with the
  routes. Below the console's 56rem breakpoint a stacked drawing is shown
  instead (`.pep-picture-stacked`), **laid out 240 wide whatever the tree**
  (2026-11-15: at 390px its boxes ran past the card): every box ends at one
  right edge, the step in shrinks for a deep tree so the deepest route keeps
  140, and its text wraps inside its box (a path breaking before a `/`)
  rather than being cut; the box's padding is thinner there and, only
  narrower than a phone, the SVG is scaled to it. `tests/xacml_pep_picture.js`
  W bounds every box and line. **What each kind draws**: a simple
  route every action of its model with its roles (each a link to
  `/admin/roles?q=`; none is *nobody*); a public route *Public*; an
  existing policy its NAME, linked to the editor, and no roles — reading
  them would mean interpreting arbitrary XACML in the browser, and a guess
  drawn as a fact is worse than the link; no methods *deny all* and
  *nobody*, whatever the kind. Each box links to its page (a route's, a
  listener's); the console runtime follows an SVG `<a>` (whose `tagName` is
  `a`) as it does an HTML one since this change, which the delegation and
  federation pictures' boxes gain too. `tests/xacml_pep_picture.js`.
* **AN XACML TAB IS NEVER A PAGE** (rcbj 2026-11-15: the Deciding policy
  link answered "/admin/xacml/editor is not a page of this console").
  `/admin/xacml/{policies,editor,peps,decide,authzen}` are written as paths
  by the renderers and moved onto `/admin/xacml?…#xacml-tab-…` by
  `WebPages.xacmlTabLinks()`, the one mapping, which `WebPages.render()`
  runs on every page's links and GET forms; a POST form keeps its action,
  which `WebForms.resolve()` and `WebAnswers.PEP_ROUTES_PAGE` read
  (`tests/xacml_pep_console.js` XL, `tests/console_web_bundle.js` F0x).
* **`multipleAccounts`** (#1760, rcbj: "support multiple authenticated
  users within a tab"), a route member, false by default and normalised
  onto every route; true needs the `session` mechanism (`STS-XACML-0257`).
  The PEP's half, its pages and its bound (`proxyMaxAccounts`, a managed
  setting) are `xacml-pep/CLAUDE.md`'s. An older PEP ignores the member.
* **A PEP REPORTS ONE ROW PER STREAM** inside `signals` as `streams` on its
  heartbeat (never on its `GET /`, which answers anybody): the client id,
  the transmitter's stream id, running, healthy, the AGES of its start,
  last poll and last success, and its counters. `signalsOf()` keeps them,
  the two ids held to a charset, and turns the ages into times by the
  arrival, ignoring any time the PEP sends. `pepsJson()` joins each to the
  routes and applications whose resolved client it is, and answers a client
  this PEP's routes do not name as empty rather than echoing it.

`tests/xacml_pep_proxy.js` L, R and T hold it.

## Sync, and the Clustered column (rcbj, 2026-11-16)

**THE TABLE'S CLUSTERED COLUMN** reads `cluster` off each row, which
`XacmlPepClusters.effectiveRow()` sets on a member only. It needs no new member,
so `GET /admin-api/xacml/peps` already answered it.

**SYNC IS A NUDGE TO ONE PEP, AWAITED.** rcbj asked for a button that "pushes"
the policies, the instance's configuration and the cluster's. This service
pushes nothing, so `sync-pep` (`XacmlAdmin.syncPep()`) is one nudge to that PEP
alone, at the URL `notifiable()` would dial. A member's pulls are its cluster's
documents. **The nudge carries `full: true`** (rcbj, 2026-11-16), and the PEP
then asks for every document without its token, so each is sent whole and loaded
again. The PEP honours that at most once a poll interval (`STS-XPEP-0120`
otherwise), because `/notify` is not authenticated; `xacml-pep/CLAUDE.md` has
its half. **It dials a PEP whose change nudges are stopped**: Stop nudging is
about the change nudge, and Sync is a person asking for this one. Unlike the
change nudge it waits for the answer, because a person pressed a button. It
writes nothing, so there is no commit to wait for. It refuses before dialling
with `STS-XACML-0282` (remote PEPs or nudging off) or `0284` (no usable notify
URL); `0283`, the stopped-nudging refusal, is retired. An undelivered nudge is
`0285`, recorded on the row like every nudge. It is a PROMISE, like
`issue-pep-certificate`. It is not a `MEMBER_REFUSED` action.

## What the console page is NOT

`/admin/xacml/peps` reaches into no other process. "Stop nudging" stops this
service dialling a PEP; it does not stop it enforcing, because it already holds
the engine and the policy. "Forget" removes a row. **A control labelled
"disable" that leaves the thing running is the single most misleading thing a
console can do**, so every disabled row says so.

## The remote PEP's HTTPS listener (2026-09-13)

The fourth control on `/admin/xacml/peps`, and the only one that does something
FOR the other process rather than about it: **Issue certificate** mints the key
pair a PEP serves its own clients over HTTPS with. `xacml_pep_tls.ts` is the
module; `common/pki.js`'s `issueTlsServerKeyPair()` does the issuing, from the
realm's `pep-tls` Issuing CA.

* **THE REALM IS THE REGISTRATION'S.** The row is looked up in the ambient
  realm's `ou=peps` and a PEP not registered there is refused
  (`STS-XACML-0071`). That is not a permission on the PEP — registering is
  still not what lets it pull — it is the only record that says which realm
  this PEP belongs to, and it carries the notify URL the default name comes
  from.
* **THE NAMES** are the PEP's registered name (where it is a DNS name), the
  hostname it reports, the host of its notify URL (an IP host becomes an IP
  subjectAltName), and what the caller adds, each once. Added, never
  replacing: the notify host is where this service would dial the PEP.
* **THE HOSTNAME (#1760)** is what the PEP's notify-URL derivation looks for
  in the certificate, and a PEP that derives its URL registers with none
  until it holds one — so without it a fresh install's first certificate
  named the registered name alone and the derivation picked that, which
  nothing resolves. The PEP sends `hostname` (`HOSTNAME`, the kernel's,
  `/etc/hostname`, and only a DNS name) on its registration and heartbeat;
  `PepRegistry.hostnameOf()` holds it to a DNS name of at most 253
  characters that is not an IP literal, lower-cased, and refuses anything
  else with 400 `STS-XACML-0261`. It is `xacmlPepHostname` (OID 758, the
  concept's `hostname`): a registration without it drops it, a heartbeat
  without it keeps it. `derivedNames()` adds it, so the environment pair
  (`issue()`) and a defined listener's CSR (`issueForListener()`) both name
  it. Backwards compatible both ways: an older PEP sends none and the
  defaults are as before; an older service ignores the member. The PEP
  page's Overview draws it. `tests/pep_listener_certificate.js` E2 and
  `tests/xacml_pep.js` hold it.
* **THE KEY IS IN ONE REPLY.** Nothing writes it onto the PEP's entry — this
  service is never party to a handshake between the PEP and its clients, so a
  copy would be a server key held by something with no use for it. The console
  answers the POST as a `no-store` PAGE rather than a 303, for
  `/admin/pki/person`'s reason: a private key on a query string is a private
  key in the history, the log and the next `Referer`. JSON in, JSON out.
* **THE ROW SHOWS WHAT WAS ISSUED, FROM THE CERTIFICATE REGISTER** (`pki.js`'s
  slot for the PEP's name), not a copy on `ou=peps` that would go stale at the
  first reissue. Whether the PEP is SERVING it is the PEP's own `GET /`.
* **IT IS THE ONE ASYNCHRONOUS XACML ACTION.** `pepAction()` answers a PROMISE
  for it and a plain result for the other three, and both callers
  (`admin-core/admin_actions.ts`'s `xacmlAction()` and the console handler)
  settle it with `Promise.resolve()`. The other actions stay synchronous
  because `tests/xacml_pap.js` and `tests/xacml_alfa.js` call
  `combinedAction()` without awaiting.

`xacml-pep/CLAUDE.md` argues the container's half — why the pair is re-read
from disk rather than read once — and `tests/pep_listener_certificate.js` (the
issuing half), `rust/bins/xacml-pep/src/listener.rs`'s test (the reload) and
section 1b of `tests/protocol/sts_xacml_remote_pep.js` pin both.

## What phase five cost outside this directory

* `common/config.js` — **eight** rows and the regenerated `env/defaults.js`.
* `ldap/ldap_server.js` — `ou=peps`, its three store functions, and a slot
  carrying FOUR things: the three plus `certificateIdentity`, which is the whole
  reason the register does not invent a naming rule of its own.
* `admin-ui/admin.ts` — the tenth slot grew from four views to SIX, a
  `SECTIONS` row, and `xacmlPepsView` / `xacmlDecideView`.
* `mgmt-api/` — two GETs, three actions and two schemas for phase five itself,
  plus the nineteen undocumented editor actions and thirty-two request bodies
  that defect 5 below turned out to owe.
* `sts_metadata.ts` — **six** `ENDPOINTS` rows.
* `admin-ui/crypto_metadata.ts` — the XACML row's missing halves (see below).
* `docker-compose.yml` — a `xacml-pep` service under `profiles: [xacml]`.
* And the container itself, `xacml-pep/`, which has its own `CLAUDE.md`.

## SIX DEFECTS PHASE FIVE FOUND THAT WERE NOT PHASE FIVE'S

All six predated it, all six were in the PDP-side work of phases one to three,
and **every one of them was found by running three jobs this branch had never
run** — `sts_metadata.js`, `admin_api.js` and `sts_admin_api_operations.js`,
all three of which are THIS REPOSITORY'S OWN (`local: true` in the vendored
manifest) and all three of which would have failed the day the defect was made.

1. **`/admin-api/crypto` answered 500.** The XACML row added to
   `crypto_metadata.js`'s `FAMILIES` in phase one carried no `envelopes` and no
   `algorithms()`, and `cryptoJson()` calls both on every row without checking —
   deliberately, because a row is the whole shape or it is not a row. Three rows
   of that table say "nothing" and this one must still carry the fields.
2. **`/admin/xacml/decide` had no `/admin-api` operation**, which rule 7 requires
   in the same commit as the page. It shipped in phase three without one.
3. **`tests/protocol/sts_metadata.js`'s protocol list did not name XACML**, so
   the card added in phase one was never checked against the page.
4. **The action endpoint answered `{ ok, why }` where every other action
   resource on `/admin-api` answers `{ ok, errors: [...] }`.** That is not a
   cosmetic difference: `sts_admin_api_operations.js` reads that array on every
   resource to check that the refusal SENTENCE names the actions, and
   `admin_api.js`'s parity check reads that same sentence to find out what a
   resource can do. A resource answering `why` is invisible to both. The
   conversion is in `xacmlAction()` (in `admin-core/admin_actions.ts`; it was
   `admin.js`'s until 2026-09-12), which is the one function the management
   API calls and the console does not.
5. **NINETEEN of the editor's twenty-three actions were undocumented, and not
   one of the thirty-two carried a request-body example.** Both halves matter
   and they fail differently: an undocumented action is a console control that
   could lose its operation with nothing failing, and an operation with no
   example is one `sts_admin_api_operations.js`'s ledger drives with nothing —
   its walk is driven off the document, so an operation arriving with no
   example and no section of its own is covered by nothing and reported by
   nothing. All thirty-two carry a documented body and an example now, and the
   ledger replays every one of them against the running service.
6. **`sts_admin_console.js` read only the FIRST console control an operation
   said it mirrored.** `/admin-api/xacml/{action}` mirrors three, so
   `/admin/xacml/editor`'s forms were never checked against the route list at
   all — and when phase five's sentence grew a comma, the greedy `\S*` swallowed
   it and even the first path stopped matching. `consolePostPathsIn()` is the
   one reader of that prose field now, it finds all of them, and it strips
   trailing punctuation. **Phase five did not cause that defect; it made the
   pre-existing one visible**, which is the ordinary way a silent guard is
   found.

## AND TWO THAT WERE

1. **`certificatePlan()` takes DN fields as STRINGS and node hands back
   OBJECTS.** `getPeerCertificate()` returns `subject` and `issuer` as
   null-prototype objects of RDN types, so `String()` on one throws `Cannot
   convert object to primitive value` rather than producing a DN. Every existing
   caller had always put both through `helpers.dnRfc4514()` first, so the
   precondition was real and written down nowhere — it is written at the
   function now. It was met TWICE, once per field: fixing the subject alone just
   moved the throw eighty lines down.
2. **The remote PEP asserted attributes under only ONE spelling.** The mock's
   PIP answers both `employeeType` and
   `urn:sts:xacml:attribute:employeeType` from one directory attribute, so
   a policy author may legitimately write either; the container asserted only the
   prefixed form and the seeded RBAC policy names it bare. **Every request was
   denied by a policy that was working perfectly**, which is the worst shape an
   authorization bug can take. It asserts both now.

Neither would have been found by anything but running the container against the
service.

## THE MOST VALUABLE THING IN PHASE FIVE IS NOT THE FEATURE

`xacml-pep/common/helpers.js` is thirty lines exporting `log` and `xmlEscape`,
and it is what `../common/helpers` resolves to inside that container. Every
engine module here claims **no I/O, no DOM, no store** in its header — and every
one of them requires `../common/helpers`, which in this service pulls in the
config table, the crypto module, the realm registry, node-forge and
jsonwebtoken. The claim had a loophole wide enough to drive anything through.

An engine module that grows a dependency on this service does not degrade in
that container — **it throws at load**, and `tests/xacml_pep.js` fails naming
it. That test also asserts that not one of this service's modules is in the
child's `require.cache` once the engine has loaded, and that the engine reaches
the same decision there as here on the same policy.

So "the engine is a library with no I/O" stopped being a comment at the top of
seven files and became something that is checked. That is worth more than the
remote PEP it arrived with.

## THE THIRTEENTH DEFECT, AND THE ONLY DOOR THAT COULD HAVE SHOWN IT

`tests/protocol/sts_xacml_editor.js` found it on its first run, and it had been
there since phase three: **every refusal on the three `/admin/xacml` pages
redirected back to the page with `error=` and nothing in it.**

The three action functions here — `policyAction()`, `editorAction()` and
`pepAction()` — refuse with a single `why`, which is the shape `xacml_store.ts`
and `xacml_editor.ts` hand up to them. `admin.respondToAction()` built the
browser's message out of `errors`, which none of them sets. So the person got
the page they had just posted from, unchanged, with no explanation — which reads
exactly like a control that does nothing.

**It was invisible from both of the places that look.** `/admin-api` had already
been given the translation (`admin_actions.js`'s `xacmlAction()` puts `why`
into `errors`), so
every refusal was fully explained there and
`tests/protocol/sts_admin_api_operations.js` was right to be satisfied. And
`tests/xacml_pap.js` asserts the refusal the FUNCTION returns, which was correct
the whole time. The defect lived in the two lines between them, and the only way
to see it was to press a button in a browser and read the page that came back.

It matters most exactly where this console leans on it hardest: the editor is
LIVE, and the thing that makes that tolerable is that an edit which would leave
a policy invalid is refused and the stored document is untouched. The sentence
saying so — which names the type error the author has to fix — was the part
being dropped.

Fixed in `admin-ui/admin.ts` rather than in the three handlers, so that a fourth
handler written in that shape cannot reintroduce it and so that the console and
`/admin-api` cannot disagree about what a refusal said.

## AND SINCE 2026-09-05 IT DECIDES THIS SERVICE'S OWN ISSUANCE

`xacml_role_pep.ts` is the exception to the sentence at the top of this file.
Everything else here answers a question about SOMEBODY ELSE'S boundary — that is
what a PDP is. This one turns THIS service's issuances into XACML requests and
refuses the ones the PDP will not permit.

It fills `common/issuance_gate.js`'s decider at require time, which is what arms
every issuance site in the service: the ten kinds of issuance in
`issuance_gate.js`'s `ISSUANCE`, and every `gate.check()` call in the modules
that issue them. The decider is read at CALL time, so a module required after
23c (GNAP, at 23d) is armed exactly as one required before it. So
`xacml/xacml.ts`
requiring this module is the line that turns a service which answers "allowed"
to everything into one that asks a policy.

**There is no second implementation of the rule.** No `if (roles.includes(...))`
in `oauth2.js`, no membership test in the SAML builder. The reason somebody was
refused is a document an administrator can read, edit, test on
`/admin/xacml/decide` and see in the audit log — which is the whole point of
routing an internal decision through a policy engine that is already here.

### 3br. The request it builds is the contract

| Category | Attribute | What it is |
|---|---|---|
| access-subject | `subject-id` | who is being authenticated |
| | `urn:sts:xacml:role` | the roles they hold |
| | `urn:sts:xacml:role-from-token` | roles read out of a token they PRESENTED |
| resource | `resource-id` | the application |
| | `urn:sts:xacml:required-role` | what it demands |
| action | `action-id` | `issue-access-token`, `start-session`, and the rest of `issuance_gate`'s `ISSUANCE` |
| | `urn:sts:xacml:requested-scope` | the scope values asked for (#304) |
| access-subject | `urn:sts:xacml:client-id` | the client the request came through (#304) |
| environment | `urn:sts:xacml:grant-type`, `urn:sts:xacml:protocol` | the OAuth grant and the protocol family (#304; the protocol filled from the kind where the caller names none) |
| access-subject | `urn:sts:xacml:home-jurisdiction` | the jurisdiction the subject is homed in — a transfer question only (#98) |
| environment | `urn:sts:xacml:serving-jurisdiction`, `urn:sts:xacml:client-country`, `urn:sts:xacml:transfer-listed`, `urn:sts:xacml:realm`, `urn:sts:xacml:purpose`, `urn:sts:xacml:setting:cells.hardGeofence` | the serving cell's jurisdiction, the client's country when known, whether the realm lists the transfer, the realm, a release's purpose, the hard geofence — a transfer question only (#98) |
| resource | `urn:sts:xacml:data-category` | `session`, `request` or `attributes` — a transfer question only (#98) |
| resource, action, environment | `urn:sts:xacml:fga:*` | an RFC 9396 detail asked of its owning application's policy — a fine-grained authorization question only (#564, rule 3cy) |

#### 3bs. One question per requested scope (#304, part C of #88)

**AND ONE QUESTION PER REQUESTED SCOPE (#304, part C of #88).** Which scopes
are issued is the policy's decision too, not code's: `issuance_gate`'s
`checkScopes()` asks, action-id `issue-scope` with the scope as the
resource-id, `urn:sts:xacml:scope-gated` (does its resource gate it by role,
#303) and `urn:sts:xacml:authorizing-role` (which roles' `rolePermission`
names it) on the resource, and the subject's ROLE bag. The answer carries
`urn:sts:xacml:obligation:scope` — `keep`, `drop` or `refuse`, and a code —
on a Permit as well as a Deny. The built-in `role-issuance` has two rules for
it (`scope-not-authorized`, `scope-kept`, parameter `decideScopes`), and an
operator's rule may drop any scope with its own code. **No verdict is not a
verdict (rcbj's decision on #304)**: `xacml.enabled` off, no loadable policy,
or an override built without the scope rules — the PEP asks the BUILT-IN
policy instead, so role gating never switches off; a process with no XACML
family drops a gated scope (`STS-XACML-0079`). The code that gathers the
facts is `common/role_permissions.ts`; nothing in it decides.

#### 3bt. The other scope rules (#305, part D of #88)

**AND SINCE #305 (part D) THE OTHER SCOPE RULES ARE HERE TOO.** The #110 scope
rules (`scope_policy.ts`), delegated permissions (`permissionRefusal()`),
consent (`consent.outstanding()`, verdict `consent`) and the two RFC 9396 type
questions (action-id `issue-authorization-detail`, the type as the
resource-id) ask the same question, each with only ITS facts — a rule tests
its facts with `boolean-is-in`, false over an empty bag, so one subsystem's
question never trips another's rule. The environment carries the realm's
MODE, the settings a rule reads (`urn:sts:xacml:setting:<key>`) and the STAGE
(`request` refuses, `mint` narrows, `consent`), by rcbj's decision that the
mode and the settings are facts and the policy decides what differs. **With no
decider the gate evaluates the built-in policy itself** (rcbj's decision on
#305): `xacml_scope_verdicts.js` is a library — engine, builder and templates,
no route and no slot — which the issuance PEP and `issuance_gate.js` both ask
through, so the rules hold in every process.

#### Each GNAP access right (#432 phases 3 and 4) — rule 3bz

**AND SINCE #432 (phase 3) EACH GNAP ACCESS RIGHT.** `gnap/gnap_rights.ts`
asks one question per right, action-id `issue-gnap-right`, the right's type
(or reference string) as the resource-id, with the facts `xacml_request.js`'s
`gnapRight()` spells (`urn:sts:xacml:gnap:*`: the right's five fields, what
the access-type catalogue declares for its type, the token, the client, the
approver and how it approved, the session, risk and device), through
`issuance_gate.checkGnapRights()`, `decideGnapRights()` here and
`xacml_gnap_right_verdicts.ts` — the scope question's arrangement, a realm's
policy first and the built-in one where it says nothing. Two things differ
from the scope question, and each is there for a reason:

* **`narrow` and a lifetime.** A right has dimensions, so the obligation
  `urn:sts:xacml:obligation:gnap-right` may carry DROP values per dimension
  and a maximum lifetime beside keep / narrow / refuse. Several Permit rules
  may each carry it — the built-in `gnap-type-lifetime` and an operator's
  narrowing rule — so the reader MERGES every obligation (refuse over narrow
  over keep, drops unioned, the shortest lifetime). That is why the built-in
  lifetime rule is a separate Permit and not a member of `gnap-right-kept`.
* **The risk, device and session facts have names of their own**
  (`urn:sts:xacml:gnap:risk-level` and the rest), because the document's risk
  and device rules are untargeted: given their attributes, every per-right
  question would trip them and answer with an obligation the right reader
  does not know. A realm rule may still read the GNAP names.

The built-in rules (`decideGnapRights`, default yes) are the code
`gnap_grants.ts` used to run, in its order — bearer, protected scope,
gnapAllowedAccess, unknown reference — then the catalogue's: uncatalogued in
product (`inProduct`, the mode as a fact), a type's `bearer: false`, its
`maxLifetimeS` — and, since phase 5, the resource OWNER's two: a right
naming an identifier somebody else owns (`gnap-owner-mismatch`,
`STS-GNAP-0861`, read off `owner-known` and `owner-matches`, the latter sent
only once a person is known) and one whose owner lookup could not be
answered (`gnap-owner-unresolved`, `0863`). The right's limits ride with the
question too (`urn:sts:xacml:gnap:limits` and each member decomposed —
`limit-amount` a double, `limit-count` an integer), for a realm that wants a
rule on them; no built-in rule reads them, because a limit is stated and
counted, not granted or refused (`gnap/CLAUDE.md`, *Ownership and limits*).
A verdict this reader does not know refuses
(`STS-GNAP-0815`); no verdict at all is a defect and refuses
(`STS-XACML-0168`, `STS-GNAP-0816`) — a right is never issued because the
engine broke. `tests/gnap_catalogue.js` holds each rule through the policy
and a realm's narrowing override.

#### Who must be asked, and how strongly (#432 phase 6)

**WHO MUST BE ASKED, AND HOW STRONGLY (#432 phase 6).** Two more members of
the same obligation, `urn:sts:xacml:gnap-right-interaction` (none, skippable,
always) and `urn:sts:xacml:gnap-right-acr`, carried by four more built-in
Permits — `gnap-type-interaction-never`, `-always`, `gnap-type-consent-action`
(a right naming a listed consent action, or naming no actions, which is
every action) and `gnap-type-acr`. They are Permits that keep the right and
STATE A REQUIREMENT, merged like the lifetime: the most demanding
interaction, every acr. So a realm tightens by adding a Permit with the
obligation, and an interaction word the reader does not know reads as
`always`. The grant engine does what they say (`gnap/CLAUDE.md`, *Phase 6*);
the approval fact gained the value `owner`, the resource owner approving on
their portal.

#### Fine-grained authorization's request (#564) — rule 3cy

**AN RFC 9396 DETAIL, ASKED OF THE POLICY OF THE APPLICATION THAT OWNS ITS
TYPE** (rcbj's decision 1 on #564). This is phase P2: the mapping and the
request, pure (`fga_map.ts`). Where the policy lives and its lifecycle are
P1's, where the question is asked and what a refusal does are P3's, and
AuthZEN deciding against the application's policy is P4's.

| Detail | Category | Attribute |
|---|---|---|
| `type` | resource | `urn:sts:xacml:fga:detail-type`, and `resource-id` at an issuance stage |
| `actions`, `privileges` | action | `urn:sts:xacml:fga:detail:action`, `…:detail:privilege` (string bags) |
| `locations`, `datatypes` | resource | `urn:sts:xacml:fga:detail:location`, `…:detail:datatype` (string bags) |
| `identifier` | resource | `urn:sts:xacml:fga:detail:identifier` |
| any other member | the type's `xacml` row's | the row's, and nothing else |
| a `notForPolicy` member | — | nothing, and not in `supplied` either |
| *(trusted)* | access-subject | `subject-id`, `urn:sts:xacml:subject-kind`, `urn:sts:xacml:client-id` |
| *(trusted)* | resource | `urn:sts:xacml:fga:application`, `urn:sts:xacml:fga:definition-digest` |
| *(trusted)* | action | `action-id` = `grant-authorization-detail` at every issuance stage (`authorize`, `token`, `refresh`, `exchange`, `par`); the caller's action at `access` |
| *(trusted)* | environment | `urn:sts:xacml:protocol` (`oauth2`), `urn:sts:xacml:realm`, `urn:sts:xacml:fga:stage`, `urn:sts:xacml:grant-type`, `urn:sts:xacml:fga:supplied` |

**The common data fields are BUILT-IN rows**, applied when present: they mean
the same in every type (and in a GNAP right), so a policy reads them with no
declaration, and an absent field is an absent attribute. A type's row may not
name `type` or a common field, and `notForPolicy` may not list one — each is
mapped once, under one identifier. Strings, not `anyURI`, for `locations`, as
GNAP's `right-location` is, so one `string-is-in` reads both protocols.

**The facts are written by `xacml_request.js`'s `fga()` (rule 3br), and the
action-id is FORCED at an issuance stage** whatever the caller passes, so an
issuance question can never be asked as anything else. Every identifier is in
`VOCABULARY` (`FGA_*`), spelt the same in the Rust builder
(`tests/xacml_request.js` E2, F), with `FGA_STAGES`,
`FGA_ISSUANCE_STAGES` and `FGA_GRANT_ACTION` exported beside it — engine
data, so an embedded FGA PDP in the remote PEP (future work, decision 4)
finds them named.

**THE ROWS AND THE VALUE RULES ARE AUTHZEN'S, SHARED THROUGH
`xacml_attribute_rows.ts`, NOT COPIED.** A row is AuthZEN's catalogue row with
`path` for `property` and no `object`; its category defaults to resource. The
reserved identifiers — all of `urn:sts:xacml:` by prefix, subject-id,
resource-id, action-id, the current-time attributes, a bare LDAP-shaped name
in a subject category — are refused when the DEFINITION is written
(`applications.js`'s `authorizationDetailsTypeOf()`, `STS-REG-0112`, which
requires `fga_map.ts` lazily and only for a definition carrying one of the two
members). Two rows for one member, one inside another's member, two members
onto one attribute, and a member both mapped and not for policy are refused
too: each would make what a policy reads ambiguous. The value rules are the
walk AuthZEN's request goes through, so a detail can never forge a trusted
attribute and a member no row names is refused rather than guessed at
(`STS-FGA-0103`).

**COVERAGE IS A QUESTION ABOUT THE TYPE, `uncovered()`**, which P1/P3 ask
before FGA may be enforced: the member paths the type's JSON Schema permits
that are neither a common field, mapped, nor `notForPolicy` — and `*` (or
`<path>.*`) where the schema permits members it does not name. **An open
schema makes the type uncoverable**: no schema, or a level without
`additionalProperties: false`. `unevaluatedProperties: false` closes a level
only where it has no applicator (`allOf`, `anyOf`, `oneOf`, `$ref`,
`$dynamicRef`, `if`/`then`/`else`, `dependentSchemas`) that could evaluate
members this module cannot enumerate; `patternProperties` leaves it open.
Conservative on purpose: an administrator closes a schema with one keyword,
and closing it also makes RFC 9396 section 5 refuse the stranger before any
policy is asked. A nested object is walked only where a row or a
`notForPolicy` entry reaches into it; otherwise the member is mapped whole, or
uncovered.

**THE DIGEST** is a SHA-256, lowercase hex, of the definition's canonical JSON
(members sorted; a bare name is `{"type":…}`), so a policy may be pinned to the
definition it was written against; `authorizationDetailsTypeOf()` keeps the
object as `source` and `declaredTypes()` carries it with `xacml` and
`notForPolicy`, so P3 hands `fga_map.request()` a `declaredTypes()` entry as
it stands.

**`STS-FGA-0100`–`0107` are all DEFENSIVE**: details reach `request()` after
RFC 9396 validation, so a definition that is not usable (0100), a detail not
of its type (0101), missing trusted facts (0102), an uncovered member (0103)
and the value rules' four kinds (0104 null, 0105 type, 0106 array, 0107
object or depth) are refusals no well-formed path produces — never an
attribute. They start at 0100 so P1's lifecycle codes keep the low numbers.
`tests/fga_map.js` holds the contract, through the real engine at the end.

#### Where a person's data may go (#98, D4 and D11) — rule 3bu

**AND SINCE #98 (D4, D11) WHERE A PERSON'S DATA MAY GO.** When the service is
deployed as cells, three questions go to the same policy from
`common/cell_transfer.ts` through `issuance_gate.checkTransfer()`:
`hold-session` (may a traveller's session be HELD by the serving cell),
`serve-request` (may a request about them be served there at all, even by
relaying) and `release-attributes` (may a cell's residents be released to a
reader at another — or, purpose `scim-provision` since #553, may one person
be pushed by their home cell to an outbound SCIM client's service provider,
the client's declared jurisdiction as the serving side; the same six rules
decide it, and a realm's own policy may write one against the purpose). The
facts are the attributes above; the answer carries
`urn:sts:xacml:obligation:transfer` with `urn:sts:xacml:transfer-verdict` —
`hold`/`relay`, `serve`/`refuse`, `release`/`withhold` — on a Permit as well
as a Deny. The built-in `role-issuance` has six rules for them, targeted at
the three action-ids (parameter `decideTransfers`): relay and withhold unless
the jurisdictions are the same or the realm lists the transfer, refuse to
serve only under `cells.hardGeofence` for an unlisted one, and keep
everything else. Every untargeted rule of the document reads a fact a
transfer question never carries, so none fires on one. **The scope
question's arrangement exactly**: `xacml_transfer_verdicts.js` is the one
library both the PEP and the gate ask through; a realm's own policy decides
where it carries the obligation (an operator's rule "`us` subjects may hold
sessions in `eu`" is one targeted Permit), and where it does not — an
override built without the rules, `xacml.enabled` off, no decider — the
built-in document decides, so the strict default never switches off. A
verdict that is not one of the two for its question reads as the strict one.
The three are not members of `ISSUANCE` (`common/CLAUDE.md`, 3bu).

#### Which passkeys may be registered and sign somebody in (#536)

**AND SINCE #536 WHICH PASSKEYS MAY BE REGISTERED AND SIGN SOMEBODY IN.** The
passkey policy (#527-#535, Directory → Policies) CONFIGURES. Two questions go
to this policy from `common/passkey_policy.ts` through
`issuance_gate.checkPasskey()`: `register-passkey` (from
`credentials.addKey()`) and `use-passkey` (at a session's start, and at the
two assertion doors for the attestation rules).
* **The facts are the `urn:sts:xacml:passkey:*` attributes** of
  `xacml_request.js`'s `passkey()`: BE, the reported minimum PIN length, the
  device serial and whether the person holds it, the recorded attestation,
  and what the FIDO Metadata Service says now (listed, compromised, a
  certification RANK, FIPS, or `metadata-unchecked`).
* **The selected profile's rows are `urn:sts:xacml:passkey-policy:<row>`**,
  and the `webauthn.attestation*` settings are setting facts.
* **The answer carries `urn:sts:xacml:obligation:passkey`**: verdict
  `allow`/`refuse`, a code and a reason.
* **The built-in `role-issuance` has fifteen refusing rules** (parameter
  `decidePasskeys`), in the order the code asked. Each fires only on a
  question that names its fact group in `urn:sts:xacml:passkey:facts`, so the
  sign-in line's question never trips an attestation rule, nor the reverse.
* **The codes are the ones the code recorded**: 0312-0317, 0320, 0321, and
  0322 for a realm's refusal with no code of its own.
* **#718 ADDED THE POST-QUANTUM RULE, ONE PER ACTION, LAST AT EACH**, so a
  key refused today for its BE flag or its PIN is refused for that still.
  The fact group is `algorithm`: `urn:sts:xacml:passkey:algorithm` (the
  JOSE name), `urn:sts:xacml:passkey:post-quantum` (a boolean) and
  `urn:sts:xacml:passkey:lane`. The rule reads `post-quantum` and the row
  `urn:sts:xacml:passkey-policy:postQuantumRequired` — `sign-in` and
  `registration-and-sign-in` at `use-passkey` (0356), the second alone at
  `register-passkey` (0355) — and NEVER the lane: with #643's switch off an
  ML-DSA key is made in the one lane and its row records none, so a rule on
  the lane would refuse a post-quantum key. `post-quantum` is computed once,
  in `passkey_policy.ts`'s `question()`, and always sent with its group, so
  an absent fact is never read as "classical"; the lane is there for a
  realm's own rules. The remote PEP (`xacml-pep/`, `rust/`) carries no
  passkey vocabulary, so it did not change. **A realm's own issuance
  document built from the template between #536 and #718 does not carry
  the rule**: it answers `use-passkey` with its `passkey-use-allowed`
  Permit, which carries the obligation, so it DECIDES and the built-in rule
  is not asked — the realm's document is the realm's, by design. Such a
  realm rebuilds its document from the template to be held to the row; a
  document built before #536 answers no passkey verdict and falls to the
  built-in rules as it always did.
* **#941 ADDED THE ATTESTATION-ALGORITHM RULE, ONE PER ACTION, AFTER THE
  POST-QUANTUM ONE.** The fact group is `attestation-algorithm`:
  `urn:sts:xacml:passkey:attestation-statement-algorithm`, a bag
  `...:attestation-certificate-algorithm` (leaf to anchor),
  `...:attestation-post-quantum`, and the verdict
  `...:attestation-algorithm-allowed` that `question()` computed; the
  attestation group's `verified`/`trusted` facts are sent with it where
  that group is not. The rule reads ALLOWED and the row
  `urn:sts:xacml:passkey-policy:attestationAlgorithms` (a bag, empty for
  none) — at `register-passkey` whenever it is set (0411), at
  `use-passkey` only with `enforceAttestationAtSignIn` (0412) — and
  `passkey_rules.js` mirrors it. A document built before #941 carries no
  such rule, as above.
* **#946 ADDED ONE POLICY FACT AND NO RULE**:
  `urn:sts:xacml:passkey-policy:postQuantumAllowCredentials`, `narrow` or
  `list-and-refuse`, resolved from the realm's setting where the profile's
  row is `realm`. A classical key refused under `list-and-refuse` is
  refused by the `post-quantum` rule above, as under `narrow`; the fact is
  there for a realm's own rule to tell a key picked from a full list from
  one never offered.
* **Arranged as the transfer questions are**: `xacml_passkey_verdicts.js`
  serves both the PEP and the gate. A realm's own document decides where it
  carries the obligation; otherwise the built-in document decides. Where
  neither answers, `common/passkey_rules.js` reads the same rules from the
  facts.
* **Not members of `ISSUANCE`.**
* **A THIRD QUESTION, `recover-account` (#724; `common/CLAUDE.md` 3cq).**
  Whether a way back into an account that asks for no passkey may restore
  access, and whether a session after one may reach an application. Fact
  group `recovery`: the door, where it is asked (`door` or `session`), the
  credential that answered, and whether the door is self-service, whether
  the person holds a passkey (`covered`) and whether a recovery is pending.
  Two Deny rules after the `use-passkey` Permit: `recovery-self-service`
  (`STS-AUTHN-0380`, under `recoveryAssurance: operator-only`) and
  `recovery-enrol-first` (`STS-AUTHN-0381`, under `not-weaker` or
  `operator-only`, at a session a passkey did not answer). Then a Permit.
  `common/passkey_rules.js` reads both, and `tests/recovery_assurance.js`
  holds the two to one truth table.

#### The subject, and the application

**The subject is the party being authenticated and not always a person.** In a
browser flow it is whoever signed in; in a `client_credentials` grant there is
nobody there and it is the CLIENT. That is the case `common/roles.js` exists to
be able to answer, and it is why an application is a first-class member of a
role.

**The application is the resource and also, often, the subject's employer.** A
client asking for a token for itself appears in both categories, which is not a
confusion: as a resource it is the thing being reached, as a subject it is the
party whose roles are read. A policy may name either.

### The policy is BUILT IN, called rather than seeded

The `role-issuance` template answers by being CALLED. It is not written into
`ou=policies` at startup, and that is a correction rather than a preference:
`ou=policies` is per realm, so a seed written once in the default realm left
every later realm unable to use roles at all. A repository entry named by
`xacml.issuancePolicy` overrides it, so an administrator who wants to see and
edit the document still can.

**ONE COPY EVERYWHERE, OVERRIDDEN PER REALM — rcbj's decision (2026-09-19).**
Asked whether the two service policies (`role-issuance`, and `access-control`
over the console, `/admin-api` and the portal) should instead be SEEDED as a
stored copy into every realm's `ou=policies`, the answer was no: one built-in
document, identical in every realm, and a realm that wants something else
writes an override into its OWN `ou=policies`, which reaches that realm and no
other. `tests/xacml_service_own.js` section 5 holds both directions — a
realm's override does not reach the default realm, the default realm's does
not reach the realm, and deleting either brings the same built-in back.

### The two ways it can fail get OPPOSITE answers

This is the part to read before changing anything in that file.

**A missing or broken issuance policy fails OPEN for an application that
requires only `EVERYBODY`, and CLOSED for one that requires anything else.**

An application that names no required role is the default state of every
application here. It requires `EVERYBODY`, everybody holds `EVERYBODY`, and the
only answer the policy could give is Permit — so a missing policy costs it
nothing, and refusing it would mean a service whose issuance policy was deleted
stops issuing ANYTHING to ANYBODY, including the session an administrator needs
to put the policy back. That is not a security posture, it is a locked room with
the key inside.

An application whose entry names `staff` is a different sentence entirely:
somebody deliberately asked for a restriction, and answering Permit because the
document implementing it is missing would be the one failure this feature must
not have — a configured refusal silently not happening. So that one is refused,
and the refusal NAMES the policy and the template that rebuilds it.

**An error is not a decision.** A throw out of the engine is a defect, and in
DEVELOPMENT `issuance_gate.js` answers a throw (or no answer) by allowing, for
the locked-room reason. **In product it refuses (#1494, ASVS 5.0.0 16.5.3,
`STS-XACML-0183`), as the access gate does (#1450)**: `noDecision()` asks
`mode.failsOpenOnPolicyFault()`, and an application register that cannot be
read to judge a sign-in yields the mechanism `unreadable`, which nothing holds.
The recovery from a policy that denies its own repair is `roles.enforceIssuance`
off, which `/admin/mode` reports while it is. An EMPTY decider (the XACML family
not loaded in this process) still allows in both modes — that is rule 3v. A
Deny, a NotApplicable and an Indeterminate are not throws — they are answers,
and every one of them refuses here, because the policy is `deny-unless-permit`
and an issuance decision must not rest on a PEP's bias. **`xacml.pepBias` was
deliberately never read here**: that setting belonged to the demo PEP at
`/xacml/protected` (both the remote PEP's since #596, as `PEP_BIAS` and
`GET /protected`), which existed to SHOW what bias does, and this one is
enforcing.

### It fills `admin.js`'s `setRolePreviewer()` slot

`setRolePreviewer()`, carrying TWO functions — the preview, and the thing that
says WHICH POLICY answered. Validated together for `setLogoutReader()`'s reason:
a preview installed without the explanation would be a page able to ask a
question and unable to explain the answer.

Rule 3e's test answers yes both ways round. A require from `admin.js` (18) to
this module would load the engine there and — much worse — fill the issuance
decider FROM THE CONSOLE, so a process that loaded the console and not
`xacml/xacml.ts` would gate every issuance in the service with half this family
present. A require the other way closes a cycle, because `xacml_admin.ts`
requires `admin.js` for the page shell.

### Who may act for whom, and as what: three questions the policy ANSWERS (#186, 2026-10-03)

Until #186 this was a deny-only question, action-id `delegate`, asked after
`../common/delegation_policy.ts` had decided from the attributes in code.
rcbj's decision on #186 put the decision itself here. Every delegating act —
an RFC 8693 token exchange, a WS-Trust `OnBehalfOf` / `ActAs`, and (phase 3)
a Kerberos S4U request — asks the issuance policy two questions through
`xacml_exchange_verdicts.js`, with the facts `delegation_policy.ts` gathers
and `xacml_request.js`'s `exchange()` spells (the subject in access-subject,
the actor in XACML 3.0's `intermediary-subject`, S and R in the resource, the
requested and chosen semantics in the action, may_act and the protected groups
in the environment, `urn:sts:xacml:exchange:*`):

1. **`choose-exchange-semantics`** — four mutually exclusive Permit rules,
   the precedence in order: the request, the actor's default, the subject's,
   `delegation.defaultSemantics`. The obligation
   `urn:sts:xacml:obligation:exchange-semantics` carries the choice.
2. **`exchange-token`** — ordered Deny rules, each carrying the obligation
   `urn:sts:xacml:obligation:exchange` with the verdict `refuse`, the REFUSAL
   KIND and `enforced` (an Apply of `string-is-in('product', mode)`, except
   may_act's, which is `true`): `may-act`, `targets`, `unregistered-target`,
   `no-target`, `subject` (protected), `intermediary` (unknown, or a person
   without `delegation.actorRole`), `semantics`, `subject` (the actor's
   subject groups, unless may_act names it), `authority`, then `target` for
   the delegation relationship and for the impersonation reach. Then three
   mutually exclusive Permit rules carrying the verdict `allow`, the ISSUED
   semantics (`self`, `delegation`, `impersonation`) and the audience (R, or
   S for a self exchange that named none).

3. **`assign-may-act`** — what RFC 8693 section 4.4's `may_act` on a token
   about a subject names. The fact is the party the subject chose
   (`urn:sts:xacml:exchange:subject-delegate`, from `stsMayAct` or
   `appMayAct`); the built-in rule `may-act-subject-choice` assigns it
   through the obligation `urn:sts:xacml:obligation:may-act`. A realm's
   policy may assign another party, or none by answering with that
   obligation and no party — a BARE Deny says nothing, so a risk or device
   rule written for every action never drops a restriction the subject
   chose. Where neither policy answers, the subject's own choice stands
   (`STS-XACML-0087`): `may_act` restricts, so dropping it would widen.

**THE FACTS OF A QUESTION ASKED ACROSS A KERBEROS TRUST (#430 Phase 1,
2026-10-19)** are defined in `xacml_request.js`. `exchange:subject-realm`,
`exchange:actor-realm` and `exchange:target-realm` (the Kerberos realm of each
party, in its category), and in the environment `exchange:trust-partner`,
`trust-type` (`external`, `trust-realm`), `trust-direction` (`inbound`,
`outbound`, `bidirectional`), `trust-attribute` (each of [MS-ADTS]
6.1.6.7.9's bits by name, as `kerberos/krb5_trusts.ts` records them),
`trust-path` (the realms crossed, the client's first) and `trust-hops` (an
integer). **Each is sent only when the question names it**, so every question
asked before #430 is the request it was, attribute for attribute; an absent
realm is never an empty value a rule could compare.

**THE CROSS-REALM RULES THAT READ THEM (#430 Phase 3, 2026-10-19)** are five
Deny rules of the built-in `role-issuance` document, placed just after
`protected-subject` and refusing as `trust-disabled`, `trust-direction`,
`self-realm`, `classic-across-realms` and `tgt-delegation` — the KDC asks and
records (`STS-KRB-0230`–`0233`), and decides none of it with an `if` of its
own. Phase 3 added four more facts: `exchange:trust-enabled`,
`exchange:local-realm`, `exchange:mechanism` (now also `forwarded`, a TGT
delegated across a trust), the actor's `exchange:actor-self-realm` (its
`krb5S4uSelfRealm` values) and the target's
`exchange:target-foreign-tgt-delegation` (`inherit` | `deny`, which only
narrows), plus the setting `krb5.crossRealmClassicDelegation`, sent only when
the realm has it. A foreign subject or actor named `SPN@REALM` is exempt from
the rules that ask this realm's registers about it (unregistered target,
unknown actor, user-actor role, subject group) only across a trust, and the
delegation and impersonation rules accept RBCD naming the foreign actor and a
classic list vouched by the front end's realm. **No rule grants a foreign
subject a role**: what it holds arrives resolved, and since 2026-10-19 that
is only what was granted to its name or its filtered SIDs — never EVERYBODY
or ALL_AUTHENTICATED_USERS (`kerberos/CLAUDE.md`). `classic-across-realms`
is asked in whichever realm is deciding, so each realm refuses on its own
setting. `tests/tools/exchange_oracle.js`
states every one of them independently, and both `exchange_policy` files run
the across-a-trust product against it. `kerberos/CLAUDE.md` (*Delegation
across a trust, built*) carries the reasoning.

AND ONE PER-SCOPE RULE: **`exchange-widens-scope`**, at stage `exchange` of the
per-scope question, refuses in product a scope the verified subject token
does not carry (`STS-OAUTH-0621`), from two facts the token endpoint sends —
whether the subject token has a `scope` claim, and whether it carries this
one. An ID Token or a WS-Trust JWT has no grant to compare, and is not
refused.

**AND A DELEGATED PERMISSION IS DECIDED BY DELEGATION, NOT BY THE SUBJECT
TOKEN (#549, 2026-10-10).** rcbj: a token exchange may put a delegated
permission in the issued token that the subject_token did not carry, when
the CALLER holds it, and the decision is policy. So the token endpoint adds
two facts for a scope that names a delegated permission —
`urn:sts:xacml:scope-delegated` and `urn:sts:xacml:scope-granted` (does the
calling client hold it, `oauthDelegatedPermission`) — and the policy has
three rules about it: `exchange-widens-scope` leaves a delegated permission
alone; **`exchange-permission-not-delegated` DROPS one the caller does not
hold, in every mode** (`STS-OAUTH-0954`, logged; the rest of the request is
issued, RFC 6749 section 3.3); and the request-stage
`permission-not-granted` no longer refuses a TOKEN EXCHANGE's permission
(it tests the environment's grant type), because the exchange stage decides
it. A question with no `scope-delegated` fact is judged as before.
`tests/scope_rules_policy.js` section G holds the truth table, and
`tests/protocol/sts_token_exchange_chain_delegation.js` the chain: esb1
holds read and write on sp1 and sp2 and not admin, asks for all three, and
admin must never be issued.

**AN APPLICATION'S PERMISSION IS A ROLE'S (#551, 2026-10-10).** A delegated
grant needs a person: `permission-not-granted` also skips `client_credentials`
(the environment's grant type), and on that grant `role_permissions.ts` sends
every application permission with `urn:sts:xacml:scope-application-permission`
beside its `authorizing-role` values; **`application-permission-not-authorized`
drops one no role the subject holds authorizes, in every mode**
(`STS-OAUTH-0957`). It sits after `scope-not-authorized`, which still decides a
permission its resource gates. `tests/role_permissions.js` section H and
`tests/protocol/sts_delegated_permissions_example.js` (an app role over HTTP)
hold it.

**MUTATION-TESTED** (2026-10-03): each of the twenty exchange rules removed
in turn is told apart by the matrix, except the two that answer other
questions — `may-act-subject-choice` (held by `exchange_policy.js` section N)
and `exchange-widens-scope` (`token_exchange_product.js` 7o).

**THE ORDER IS THE ARGUMENT, AND THE COMBINING ALGORITHM KEEPS IT.** The
document is ordered-deny-overrides: the first Deny wins, so the refusal a door
speaks is the most fundamental one; on a Permit the obligations of every
applicable Permit rule are collected, which is why the allows are mutually
exclusive — two would send two audiences. `decideExchanges` (default yes) is
the template parameter that leaves the rules out.

**THE REALM'S OWN POLICY ASKS FIRST, THE BUILT-IN ONE ANSWERS WHERE IT DOES
NOT** — `xacml_transfer_verdicts.js`'s pattern: `xacml_role_pep.ts`'s
`decideExchange()` against the realm's issuance policy, falling back to the
built-in `role-issuance` document where the answer carries no exchange
obligation; `../common/issuance_gate.js`'s `checkExchange()`, in a process
with no XACML family, against the built-in one alone. **Where neither answers
— a defect — the act is REFUSED** (`STS-XACML-0085`): a broken engine must not
become permission to act for somebody. A realm policy that Denies with the
exchange obligation and the refusal `policy` is how an operator writes
something stricter (`tests/delegation_policy.js` section I).

**HELD TO AN ORACLE.** `../tests/exchange_policy.js` is a truth table and
20,976 combinations against `../tests/tools/exchange_oracle.js`;
`../tests/exchange_policy_exhaustive.js` runs all 2,488,320 (about six
minutes). A rule changed here changes the oracle in the same commit, or both
files fail.

### The registered device, and two rules that settings switch (#164 phase 6, 2026-09-26)

rcbj's decision 3 is that enforcement is XACML. So the device register's
facts go into the issuance request, and the built-in `role-issuance` policy
decides on them. There is no `if` at an issuance site.

* **The facts** are the environment attributes in `xacml_templates.ts`'s
  `DEVICE_ATTRIBUTE`, built by `xacml_role_pep.ts`'s `deviceAttributes()`:
  * recognized (a boolean), id, via, owner-matches (a boolean), owner-kind,
    compliance, attestation, status and risk-level;
  * the REQUIREMENT bag, from the realm's settings
    (`issuance_gate.deviceRequirementOf()`).
  They are sent only when the gate asked the device question (the question
  carries a `deviceRequirement` array). A delegation question, a preview
  or a caller that went round the gate carries none, so every device rule
  is inapplicable to it.
* **Ownership is decided in the PEP** against the subject the gate names: a
  person's own device, or an application's own device for a
  `client_credentials` subject. The policy reads a boolean.
* **The two rules come FIRST in the document**, so that under
  ordered-deny-overrides their obligation is the one the PEP reads. A risk
  Deny may only ask for a step-up; a device refused after a step-up would
  be one refusal made in two steps.
  * `device-compromised`: applies while `not-compromised` is required,
    which `devices.refuseCompromised` puts there (ON by default).
  * `device-required`: applies while `compliant` is required
    (`devices.requireCompliantDevice`, OFF by default in both modes), and
    `attested` beside it.
  An application's device satisfies `device-required` for a person, and
  another person's device does not. `deviceExempt` (by default the console
  and the portal) is never refused by it: the console for #226's reason,
  and the portal because it is where a person registers a device.
* **Settings switch the rules, and the policy states them.** That is
  #62's arrangement: the risk rules are always in the document and apply
  only to the facts that make them applicable. So a realm switches a rule
  with a setting, never an edit to this document, and an operator's own
  document may still say anything else.
* **The device obligation** (`urn:sts:xacml:obligation:device`, with
  `device-refusal` naming the rule) is how the PEP tells a device Deny from
  the rest:
  * it is enforced in BOTH modes, since a compromise and a realm's explicit
    requirement are not things development should only observe;
  * it refuses even where the role question was waived;
  * the audit row carries STS-DEVICE-0037 or 0038;
  * the client is told only "Authentication failed." or "A compliant
    registered device is required."
* **The gate asks the policy past its two shortcuts only when a device rule
  could refuse**: the realm requires a compliant device, or the device in
  hand is compromised and the realm refuses one. Every other issuance is
  asked exactly as before.
* **`decideDevices: no`** builds a document with neither rule, as
  `decideRisk: no` builds one with no risk rules.

### The protocol an application is declared for (2026-10-01)

`protocol-not-declared`, a Deny right after the two device rules: **in product
mode**, an issuance whose protocol families share none with the application's
`appAllowedProtocol` is refused. Two bags carry it — the declaration on the
RESOURCE (`PROTOCOL_ATTRIBUTE.DECLARED`, a fact about the application) and the
families the issuance satisfies in the ENVIRONMENT (`FAMILY`), with the realm's
mode beside them — and the rule fires only when both hold something, so an
application declared for nothing and a session are never refused by it.

* **The gate supplies both** (`common/issuance_gate.js`'s `protocolFactsOf()`):
  the families from `FAMILIES_OF_KIND` or the caller's `protocolFamilies` (the
  SAML 2.0, SAML 1.1 and GNAP sites name theirs), the declaration off the entry
  (a Kerberos service by the entry `kerberosEntryOf()` resolves — the bare
  SPN's, then `SPN@REALM`, #747 — which the PEP's role reads use too). In
  product it makes the policy asked past the `roles.enforceIssuance`
  shortcut, as risk and the device do.
* **The PEP enforces the obligation** (`PROTOCOL_ATTRIBUTE.OBLIGATION`) before
  risk and where the role question was waived, as the device's: it is not about
  roles, and a step-up cannot answer it. `STS-XACML-0084` on the audit row; the
  client is told the application is not configured for the protocol.
* **`decideProtocols: no`** builds the policy without it; development is never
  refused because the rule reads the mode (`mode.issuesThroughUndeclaredProtocols()`
  is the gate's half of the same question).
* `tests/protocol_declaration.js` holds the rule, the request and the gate;
  no over-HTTP job asserts a refusal yet.

### The sign-in mechanisms an application allows (#457, 2026-10-06)

`authn-mechanism`, a Deny right after the protocol rule and before risk, **in
both modes**: a browser issuance to an application that lists the sign-in
mechanisms it allows (the first factors of the named authentication policy
it names, `appAuthnPolicy`, since #1148; its own `appAuthnMechanism` until
then) is denied when the person's authentication satisfies none of them. Two
ENVIRONMENT bags carry it — `AUTHN_ATTRIBUTE.ALLOWED_MECHANISM` (the
application's list) and `MECHANISM` (what the session satisfies, from
`common/authn_mechanisms.ts`) — and the rule fires only when the allowed bag
holds something.

* **The gate supplies both** (`issuance_gate.js`'s `mechanismFactsOf()`), on
  four BROWSER kinds only — a session started at a sign-in door (which names
  the event it is about to record, `authenticationEvent`), an authorization
  response, a SAML assertion and a WS-Federation token on a session — and
  never for a caller saying `browser: false` (SAML 2.0's attribute query).
  rcbj: browser authentication only. It makes the policy asked past both
  shortcuts.
* **The PEP reads the obligation** (`MECHANISM_OBLIGATION`) after the protocol
  Deny and before risk, enforced where the role question was waived, and
  answers `mechanism: { allowed, satisfied }` — which the doors read as a
  RE-PROMPT, never a refusal about roles (rcbj). `STS-XACML-0170` on the audit
  row.
* **A gated sign-in door is asked again at the session's start**, the role
  question waived, because the door asked before its second factor and could
  not ask about the whole authentication (`authn/CLAUDE.md`).
* **`decideAuthnMechanisms: no`** builds the policy without it.
* `tests/authn_mechanism_enforcement.js` holds the library, the rule, the
  routing, the door and the OAuth and WS-Federation re-prompts.

### The second factors an application allows (#475, 2026-10-07)

`mfa-mechanism`, a Deny right after `authn-mechanism` and for its reasons,
**in both modes**: a browser issuance to an application that lists the second
factors it allows (the second factors of the named authentication policy it
names, `appAuthnPolicy`, since #1148; its own `appMfaMechanism` until then) is
denied when the person's authentication GAVE a second factor and none of them is
listed. Two ENVIRONMENT bags: `AUTHN_ATTRIBUTE.ALLOWED_MFA_MECHANISM` and
`MFA_MECHANISM` (from `common/mfa_mechanisms.ts`), and the rule requires BOTH to
hold something — so a session on one factor is never denied by it (rcbj: the
list says which second factors, never whether one is needed), whatever built the
request.

* **The gate supplies both** (`mfaFactsOf()`) on #457's four browser kinds,
  and only when a second factor was given.
* **The PEP reads `MFA_MECHANISM_OBLIGATION`** just after the mechanism one,
  audits `STS-XACML-0171`, and answers `mechanism: { allowed, satisfied,
  secondFactor: true }`, so every door that re-prompts for #457 re-prompts
  for this, choosing its own code by `secondFactor`.
* **`decideMfaMechanisms: no`** builds the policy without it.
* `tests/mfa_mechanism_enforcement.js` holds the library, the rule, the
  proof-then-enrolment, the narrowed enrolment and the OAuth and
  WS-Federation re-prompts.

### A phishing-resistant authentication, as a fact and as a floor (#723, 2026-10-19)

**`AUTHN_ATTRIBUTE.PHISHING_RESISTANCE`** (`urn:sts:xacml:phishing-resistance`)
is an ENVIRONMENT bag. It holds OpenID Connect EAP ACR Values 1.0's `phr` and
`phrh` as the authentication earned them (`common/phishing_resistance.ts`,
`common/CLAUDE.md` 3cp), or **`none`**.

* **The gate supplies it** (`issuance_gate.js`'s `phishingFactsOf()`) on
  #457's four browser kinds, from the event a session is about to record or
  the session's latest. It rides along whenever the policy is asked and does
  not make it asked.
* **It is never empty when sent.** A rule that holds on `none` therefore never
  speaks to an issuance the gate did not describe: a token grant, WS-Trust,
  Kerberos, or a gated sign-in door's pre-check before its second factor.
* **The floor: two role-issuance options, empty by default**, so no existing
  document changes:
  * `requirePhishingResistant` adds `:rule:phishing-resistant`, a Deny for the
    listed application handles on `none`;
  * `requireHardwareProtected` adds `:rule:hardware-protected`, a Deny on a
    non-empty bag without `phrh`.
  
  Each carries the AUTHENTICATION obligation, which is `refuseEmailFactor`'s.
  The PEP therefore refuses where the role question was waived. The
  obligation's `AUTHN_ATTRIBUTE.REFUSAL` assignment
  (`phishing-resistant` / `hardware-protected`) makes the PEP's sentence
  name what the authentication lacked, not the roles the person holds.
* **A floor, not a step-up.** The rule refuses, and the client's
  `acr_values=phr` (or the application's `oauthDefaultAcrValues`) is what
  sends the person to the key first (`oauth-oidc/CLAUDE.md` 3cp). The option's
  help says to set both.
* `tests/eap_acr_values.js` D and E7 hold the rules through the PDP and over
  HTTP.

## THE FOURTEENTH DEFECT: TWO CONTAINERS CLAIMING A PAGE THAT WAS NEVER WRITTEN

`xacml_store.ts` and `xacml_pep_registry.ts` each carry a `SCHEMA` whose comment
says it is "Published on `/admin/ldap/*` the way every other container's is".
Neither was. The export was dead in the first since phase two and in the second
since phase five, and `common/roles.js` copied the same comment on 2026-09-05
and made three.

The pages exist now — `/admin/ldap/policies` and `/admin/ldap/peps`, drawn by
`ldap/ldap_server.js` beside the other six, because that module already requires
both of these to fill their `setDirectory()` slots and therefore already holds
both schemas. No new require, no cycle, no route moved.

**What writing them exposed is the reason a dead export is worth chasing.** The
store lower-cases every attribute name (`@ldapjs/attribute` does), and
`ldap_server.js` un-lower-cases it through `learnName()` from a table each
owning module contributes to — a merge `applications.js` has had for months and
neither of these had. So the first draft of the policies page showed every
policy's kind as `(unstated)` and, worse, **drew a DISABLED policy as enabled**,
because a missing `xacmlEnabled` is not the string `FALSE`. Both are fixed by
merging the schemas rather than by reading case-insensitively at each site: a
lookup that silently misses answers something plausible, and these three pages
are not the only readers of these entries.

The booleans are `TRUE` and `FALSE` — RFC 4517's Boolean syntax, which is upper
case, and what both of these modules write. A page comparing against `'false'`
is a page that overstates what is switched on.

## THE FIFTEENTH AND SIXTEENTH DEFECTS: THE TWO POLICIES THAT DECIDE HERE WERE INVISIBLE, AND ONE OF THEM COULD NOT BE OVERRIDDEN AT ALL (2026-09-06)

rcbj asked a question rather than reporting a bug: *are the XACML policies
created for the various resources this service advertises visible in the editor
page as existing policies?* The answer was **no**, and finding out why turned up
a second defect underneath the first.

### The fifteenth: the console described the repository and called it the policies

`/admin/xacml/editor`'s chooser is `editorJson()` → `store.all()` →
`directory.allPolicies()`, so it lists `ou=policies` and nothing else. On an
ordinary service that is exactly one row — `seeded-rbac`, drawn **(root)** — and
it is *the one document on that page that decides nothing this service
enforces*. The two that do are `role-issuance` (all nine issuance sites) and
`access-control` (the console, the management API, the User Portal, SCIM and the
SPIRE Server API), and both are BUILT IN: the template is called at decision
time rather than seeded, for the reason `xacml_role_pep.ts` argues at length —
`ou=policies` is per realm, so a policy seeded once into the default realm
leaves every realm created afterwards unable to decide anything, and falling
back to the default realm's copy would couple two realms.

**THE FIX IS TO SAY SO AND NOT TO SEED THEM**, because seeding is the thing that
argument rules out. `serviceOwnPolicies()` in `xacml_admin.ts` reports both:

* a section under the repository table on `/admin/xacml/policies` — under it
  because the order is the argument, a reader sees the stored policies and is
  then told which two are deciding and are not among them. Above it, it reads as
  a preamble to scroll past; folded, it is the fact that was already invisible,
  hidden once more;
* a line under the editor's chooser, and in the **empty-repository branch**
  especially — that branch used to say "there is nothing to edit" on a service
  whose issuance and access decisions were both being made every request;
* `serviceOwn` on `GET /admin-api/xacml/policies` and `/admin-api/xacml/editor`,
  so a caller is not left believing `policies` is the whole answer either;
* a **Create an override** button, prefilled with the name the setting already
  names — so what it makes is an entry the PEP will pick up rather than one
  named after the template and silently ignored. It posts `create-from-template`
  like the template forms below it: **moving a form is not moving an action**, so
  no second operation on `/admin-api`.

**THE STATE COMES FROM THE FUNCTIONS THE PEPs THEMSELVES CALL.**
`issuancePolicyState()` and `accessPolicyState()` are thin wrappers over
`issuancePolicy()` / `accessPolicy()`. A page that worked out for itself which
document was in force would be a second answer to that question, and it would be
the one that is wrong the moment somebody disables an override.

**`entry` AND `builtIn` ARE TWO FACTS AND MUST COME FROM TWO PLACES.** *Nobody
has written an override* and *somebody wrote one and disabled it* are opposite
situations that `builtIn` alone cannot tell apart. `entry`/`enabled` are facts
about the DIRECTORY and come from `store.read()`; `builtIn` is a fact about the
DECISION. The first draft of `accessPolicyState()` read the entry through
`store.repository()` — the resolver facade, which holds only ENABLED policies —
and so reported `entry: false` for a disabled override, which is the very
confusion the function was added to remove, restated one level down.

### The sixteenth: `xacml.accessPolicy` had never once been honoured

Found by the test written for the fifteenth. `accessPolicy()` read:

```js
const repository = store.repository();
const found = repository && typeof repository.get === 'function'
  ? repository.get(name) : null;
```

`store.repository()` returns a **plain object keyed by PolicyId**. It has no
`get` method, so `typeof repository.get === 'function'` was false on every call:
what looked like a defensive guard *was the whole condition*, `found` was always
null, and the built-in document always answered. **A documented setting, offered
on the console, that did nothing.** Two more mistakes were hiding under it and
would each have been enough on their own — the name is an ENTRY name and that
map is keyed by PolicyId, and a value in it is a parsed policy rather than a row
with an `enabled` flag.

It reads the entry the way `issuancePolicy()` does now, which is the function
this one's own header had always claimed to follow.

**AND THE DISABLED CASE CHANGED WITH IT, which is a change rather than a fix.**
It used to fall back to the built-in document — so the console's Disable button
meant *evaluate something else instead*, which is exactly what
`issuancePolicy()` refuses to do and calls a lie. The divergence was invisible
because the branch was unreachable. Disabling the access policy now means what
the button says: this layer stops deciding.

**WHAT STILL DIFFERS IS THE CONSEQUENCE, AND THAT IS DELIBERATE.** A disabled
issuance policy REFUSES a narrowed application; a disabled access policy ALLOWS
every gated surface, because `decide()` here allows when no policy is loaded —
refusing would close the console that is the only place to fix it. Two different
answers to *what does not deciding mean here*, from one answer to *is it
deciding*.

### What the lookup bug generalises to

**A GUARD THAT IS ALWAYS FALSE IS INDISTINGUISHABLE FROM A FEATURE THAT IS
SWITCHED OFF**, and neither shows up in a log. `typeof x.get === 'function'` on
a plain object reads as caution and behaves as `return null`. The thing that
found it was not a review: it was a test that created the override and asserted
the state FLIPPED — an assertion about a transition rather than about a value,
which is the only shape that catches a condition nothing ever satisfies.

`tests/xacml_service_own.js` pins all four states and was mutation-tested
against both spellings of the bug.

---

## `/admin/xacml/monitor`: THE ONLY PAGE HERE ABOUT TRAFFIC (2026-09-06)

Every other page in this directory is about CONFIGURATION — what policies
exist, what one of them says, what the PDP would decide about a subject you
type in. None of them answered the question somebody has when authorization is
misbehaving: *how many decisions are being made, by whom, and how many are
refusals*.

Two sections. **Global** — policies, enforcement points, decisions, allows,
declines. **Per enforcement point** — every PEP, embedded and remote, in one
table.

**IT IS FILED UNDER `Monitoring` IN THE CONSOLE AND NOT UNDER Protocols >
XACML, and that is the paragraph above read as a placement.** The five
configuration views this directory registers are tabs on the single
`/admin/xacml` Protocols page; this one answers *what has this service done*,
which is the Monitoring section's own heading, and it is labelled `XACML
decisions` there because `Monitor` alone would name the section rather than
the subject. **The PATH did not move**: it is `/admin/xacml/monitor` still,
drawn by `xacml_admin.ts` still, because a console page is a `path` and a `label` in
`admin-ui/admin.ts`'s `SECTIONS` whoever builds the body — the arrangement the
eight `/admin/ldap/*` pages have with the Directory section and
`/admin/sts-metadata` has had since 2026-08-24. Two consequences for this
route: its `active` is its own path, so the crumb's label comes from `NAV`; and
it passes NO `up`, because it is a page of a section rather than a drill-down
of `/admin/xacml`. **The rule to take from it is that where a page is FILED is
decided by the question it answers**, never by the module that draws it or the
path space it sits in.

`xacml_monitor.ts` is the counters and `xacml_admin.ts` draws them. Four things
about it are decisions rather than details, and the first two are the reason
the page is not one number.

### Nothing counts in `xacml_pdp.js`, and nothing ever may

That file is a DOM-free library with no I/O — the claim `xacml-pep/`'s
thirty-line `helpers.js` shim exists to CHECK — and a counter in the evaluator
would also count in the wrong process the moment the remote PEP loaded its
build-time copy of it. So the counting is at the PEPs, in each one's existing
`allowed()`/`refused()` funnel: two lines per module, and a return path added
later is counted BY CONSTRUCTION rather than by whoever adds it remembering.

`xacml_monitor.ts` is a LEAF (rule 3) and **may not require `admin.js`**, which
is the constraint that decides where the page lives. `xacml_access_pep.ts` fills
`common/access_gate.ts`'s decider and is reached from `common/`, far above
`admin-ui/admin.ts` at 18 — so a console require here would have dragged every
console route into the router at that position (rule 1). Since #50's R1 the
console registers nothing when required, but it still loads the JavaScript
`tls/tls_server` on the way (through `admin-core/admin_views.ts`), whose routes
WOULD move, and it would run the console's load-time code far too early. The
symptom would not be an error: it would be `/admin/sts-metadata` reporting a
different route order.

### A DECISION IS NOT AN ENFORCEMENT, and both are counted

XACML has four decisions and a PEP has two outcomes. What maps between them is
the PEP's BIAS — so a deny-biased PEP refuses a NotApplicable that a
permit-biased one allows, from one identical decision — and **an obligation the
PEP cannot discharge turns a Permit into a refusal** (section 7.2), which is the
one enforcement outcome that looks like a bug from the client side and is the
specification working.

So `allowed` is not `permit`, and a page showing either alone would be wrong for
whichever question the reader had. Both are drawn, with the four decisions
broken out on every row that has them.

### THE FOUR FIGURES HAVE TO RECONCILE, AND THE FIRST DRAFT DID NOT

`allowed + refused` is less than `decisions` on any service that has answered
`POST /xacml/pdp`: those decisions were enforced by somebody else's PEP in
somebody else's process, so counting them either way would report an
enforcement this service was not present for. On that row `allowed` and
`refused` are **null rather than 0** — a zero reads as "it refused nothing".

The gap was real and unexplained until the page was driven with traffic on it,
where it read as an arithmetic error. **A total that does not add up is what
makes somebody distrust every other number beside it**, so the gap is now
COUNTED, as `unenforced`, and drawn as its own column:
`allowed + refused + unenforced == decisions`, on every row.

**The error path then broke the same rule and a test caught it.** `record()`
incremented `decisions` and THEN read the outcome, so a caller whose object
threw on a property access — a getter, a Proxy, a half-built object — left the
row with a decision counted, no bucket and no enforcement, permanently one
short with nothing to say why. Everything is read before anything is written
now: a throw records NOTHING, because half a count is worse than none — it is
indistinguishable from a real decision.

### What is on the page is every PEP this service KNOWS ABOUT

Which is a smaller claim than every one that exists, and the page says so.

* **An embedded PEP is not "registered" and cannot be.** It is compiled into
  this process, so its existence is a fact about the build. There are exactly
  two — the issuance PEP and the access PEP — and they are the catalogue in
  `xacml_monitor.ts` (the demonstration PEP at `/xacml/protected` was a third
  until #596 moved it to the remote PEP, whose heartbeat reports it). A fourth
  asker
  added without a row there would be decisions nobody could see.
* **A remote PEP registers because it has no other way to be known about**, and
  even that is not a permission: an unregistered PEP pulls
  `/xacml/pep/policies` and enforces perfectly and appears here nowhere.
* **`POST /xacml/pdp` is on the table and is NOT a PEP.** It earns its place
  because a reader counting decisions has to see all of them; it is marked as an
  endpoint with an empty enforcement cell.

**ONE TABLE FOR BOTH KINDS rather than two.** Embedded and remote PEPs differ in
where they run and in how this service learns their figures; they do not differ
in what a reader wants from the row. Two tables would have been two renderers
that could drift, and a reader comparing one against the other would have had to
do it across a page break.

It keeps two things apart that a single number would lose: **a decision is not
an enforcement** (four decisions, two outcomes, and the PEP's bias in between),
and **what this service SAW is not what it was TOLD** (a remote PEP's counts are
reported by it and go down when it restarts).

### The two counting sites that were nearly wrong

**`enforce()` looks like the obvious funnel for the demonstration PEP and is
not.** `/admin/xacml/decide` calls it too, to show what the embedded PEP WOULD
do with a decision somebody just asked about — a what-if, not a request anybody
guarded. Counting there would put the console's own experiments into the figure
an operator reads to find out how much traffic authorization is seeing, and the
number would grow every time somebody looked at the page. The count was at
`/xacml/protected`, the one place a real request was enforced; since #596 that
is the remote PEP's `GET /protected`, counted in its process and reported on
its heartbeat.

**Drawing the monitor page itself DOES add one to the access PEP's count, and
that is right.** `/admin` is one of the five gated surfaces, so reading it is a
real request the access policy really decided; the number would be wrong if it
did not move. The two cases are worth telling apart and the page does it: one is
an access that happened, the other is a question somebody typed.

### A DRY RUN IS A QUESTION ABOUT A DECISION AND NOT ONE (2026-09-06)

`preview: true` on an issuance request means NOTHING IS BEING ISSUED — somebody
is looking at a page that says what would happen. `xacml_role_pep.ts` then
writes no `xacml.issuance.refused` audit row and moves no counter here. **The
decision itself is identical**: same policy, same PIP, same request, same
answer, which is what keeps a preview worth having at all.

Two callers set it. `/admin/roles`'s "would alice be issued a token" button,
which had been writing those rows and moving these counters since it was
written — **so this is a fix rather than a new feature**, and the shape of the
old defect is the shape this page exists to prevent: a number an operator reads
to find out how much traffic authorization is seeing, growing every time
somebody looks at a console page. It is the same argument `enforce()` makes two
sections up, arriving from the other direction.

The second is the User Portal's `/portal/applications`, which asks this
question once per application every time somebody opens it: a person with two
permitted applications out of forty would have written thirty-eight refusal
rows into a 5,000-event ring per page load.

The flag is held in a module variable rather than threaded through the eleven
return sites, and it is SAVED AND RESTORED rather than merely set. `decide()`
is synchronous end to end — `issuance_gate.js`'s header says why it must stay
so — and the save/restore makes that a property of this code rather than of an
assumption about its callers. `issuance_gate.js` needed no change: it passes
the request through untouched.

### There is no reset, and its absence is a decision

A console that could zero its own monitoring would make every number on the page
a number somebody might have zeroed — and the durable record of a refusal is the
AUDIT LOG, which cannot be reset either. The counters are in memory, per trust
realm (like `ou=policies` itself), and start with the process; the page prints
the timestamp, because a count with no epoch is a count somebody will misread.

### Several processes or nodes: every decision is journalled (2026-09-15, #46)

Where minted state is persisted, `counters` is a `merge: 'own'` store — each
process writes its own row and `merge()` adds the other processes' rows in. **It
was journalled only when a process's row was CREATED**: `record()` changed the
object `rowFor()` handed back, in place, and a `realms.map()` hears only
`set()` and `delete()`. So `sts_minted` held each process's first decision and
nothing after, and each node's page added its own live tally to the OTHER
node's frozen row. The suite's `cluster` mode caught it in
`sts_portal_sessions`: the issuance PEP read 126 on node A and 142 on node B
around one page load that decided nothing — and 21 then 17 in a run of that job
alone, a number going DOWN that no late-arriving decision can explain. One
process never reads its own row, so `postgres` mode could not see it.
`record()` now sets the row back; `oauth2_monitor.js` always had.

**The store is declared `observation: true`**, because the access PEP decides on
every console, portal and `/admin-api` request, and a journalled row would
otherwise make each of those reads a writing request the cluster barrier holds
for a commit — which rcbj's decision 6 refuses (`cluster/CLAUDE.md`, *What the
barrier cost*). A request that wrote anything else is held and its tally rides
that commit; one whose only row is a tally is answered at once, and its row
reaches the other node within one flush. `tests/cluster_observation_counters.js`
sections 1-3.

### THE SEVENTEENTH DEFECT: the access PEP refused things and audited nothing

Found while writing the page's "where a refusal is explained" note, which named
`xacml.access.refused` — an audit action that did not exist. `xacml_role_pep.ts`
has audited its refusals since it was written; `xacml_access_pep.ts` logged at
`info` level and recorded nothing, so a refusal at a gated surface was findable
in a log file and nowhere in `/admin/audit`.

It became worth fixing rather than worth noting the moment this page began
COUNTING those refusals: **a page that says how many and points at a log for the
reason has to be pointing at a log that has them.** The refusal is audited now,
in the one `return refused(...)` at the end of `decide()`, and only the refusals
— a permit there is every request to every gated surface in the service, which
would push everything else out of a 5,000-event ring within minutes.

Beside it, `xacml.issuance.refused` had never been in `audit.js`'s `ACTIONS`
table, so every one of them landed in the `protocol` category — findable by name
and invisible to anybody filtering the audit log for AUTHORIZATION, which is the
one filter somebody investigating a refusal reaches for. Both are registered now.

## CELLS: `POST /xacml/pip` IS ANSWERED WHERE ITS SUBJECT IS HOMED (#98, 2026-09-28)

What the PIP hands out is a named person's directory attributes, and a person's
entry exists only in their home cell. So the handler reads the query's
`subject-id` leniently (`pipSubjectKey()`: a `urn:uuid:` subject by its
entryUUID, a DN by its RDN value, anything else as a login name) and relays a
query about somebody homed elsewhere WHOLE — **before** the identity is read,
the rate limit counted and the access policy asked, so the home cell counts it,
checks the PEP's certificate (the channel forwards the client certificate and
shims the socket, `common/cell_channel.ts`) and writes the `xacml.pip.query`
audit row. A query that does not parse, or names nobody the routing index
knows, is answered where it arrived, as before. Single-cell mode does not look.

## `access-control` has a third conjunct: every role named as required-all (#454, 2026-10-06) — rule 3cc

`requiredRoles` is ANY-ONE-OF, as the document has always read it
(`any-of-any` over `urn:sts:xacml:required-role`). The admin console's own
operations need two roles of two kinds at once — ADMIN_CONSOLE, which the
console's client confers on the person's token, and ADMIN_READ, which the
person holds — and an any-one-of cannot say "both". So the template conjoins
a third question beside the role and the ownership ones:
`all-of-any(string-equal, required-all-role, role)` over
**`urn:sts:xacml:required-all-role`**, which `xacml_access_pep.ts` fills from
`requiredAllRoles` on the question (`common/access_gate.ts`).

* **An empty bag asks nothing** (`all-of-any` is vacuously true), so every
  surface that names none — every surface but the console's operations — is
  decided exactly as before.
* **A conjunct, not an arm**, for ownership's reason: it narrows and must
  never be a way round the any-one.
* **It is in the decision, not in the gate's code** (rcbj's directive that
  authorization is policy): the gate states the question, and an override of
  `access-control` in a realm's `ou=policies` that leaves the conjunct out
  decides without it. The template is built in and called, not seeded, so
  every realm without an override has it at once.

`tests/access_policy.js` holds the four cases: the conferred role alone,
ADMIN_READ alone, both, and an empty required-all.

## Development only: this family's demonstrations (#585, 2026-10-12)

**None is left (#596, 2026-10-12; #591 P5).** `GET /xacml/protected`, the embedded PEP's demonstration, and `xacml.pepBias`, which only it read, were deleted: the runtime ships no demonstration code, and the `xacml-pep` container's `GET /protected` already was that PEP — the same request through the same builder, the bias as its own option (`PEP_BIAS`), the same section 7.2 rule — in the place a PEP lives (`xacml-pep/CLAUDE.md`). What stays in the runtime:

* **`enforce()`**, for `/admin/xacml/decide`'s what-if, with the bias as an ARGUMENT; the what-if (`GET /admin-api/xacml/decide`) answers `enforcement` (deny-biased, the one the page draws) and `enforcements`, both biases — one decision, two outcomes, which is what flipping the setting used to show. `tests/xacml_pep.js` still holds `enforce()` and the Rust `enforce.rs` to `xacml-pep/enforcement_cases.json`.
* **The monitor** lists two embedded PEPs, not three; a remote PEP's refusals and undischargeable obligations arrive on its heartbeat. (A third embedded one, the fine-grained authorization PEP, joined in #564's P3 — rule 3cz — for a reason of its own, not as the demonstration back.)
* **The tests moved**: `sts_xacml_endpoints.js` sections 2 and 5 read the bias and the obligation rule off the what-if, `sts_xacml_editor.js` asks the PDP through it, and `sts_xacml_remote_pep.js` section 4b asserts the obligation rule IN THE CONTAINER, on policy it pulled. Both throwaway-realm jobs still create their realm in development, as before. A permit-biased PEP is not driven end to end: the launcher's PEP runs one bias, and the two are compared through the shared table instead.
* `GET /xacml` names the trust-anchor door, `POST /admin-api/tls/trust/add` (the open `POST /tls/trust` was deleted by #597), and no longer carries `pep`.
* `STS-XACML-0014` and `0015`, the demonstration PEP's two refusals, are retired; the remote PEP's are its own `STS-XPEP-*` lines.

## The description page is a static surface's shell (#584, 2026-10-12)

`GET /xacml` is this service's own documentation, at a path no specification defines, so #584 made it the description pages' shell (`common/description_pages.ts`, `common/CLAUDE.md` 3cl): the view in `data-sts-state`, drawn in the browser by `xacml/web_xacml_description.ts` from the `describeXacml` catalogs, with `/xacml/description.js` — the one bundle the six description pages share — served on this family's own path. `?format=json`, or an `Accept` preferring JSON where the query names no format, answers the JSON form. The JSON form is the description document, to the byte as before. **The gate is the page's, unchanged and asked first**, and `/xacml/description.js` asks it too: a part of the surface answered to a caller the page refuses would be a part outside the gate. A page load is therefore two access decisions where it was one. The protocol endpoints beneath are not converted (#569's rule). `tests/description_pages.js` holds it.

## `access-control` has a second rule: an owner administers what they own (#607, 2026-10-13)

rcbj: the check that a person owns the role, group, service account or
application they are changing through the management API is XACML policy,
in one place. The template's own argument for a helpdesk role — a new kind of
access is a new Permit rule, under deny-unless-permit, and the first rule is
untouched — is what it became: `:rule:owner-administers-what-they-own`,
beside `:rule:may-reach-it`. An administrator is decided exactly as before;
an owner only by this rule.

**ITS CONJUNCTS, EACH NARROWING AND EACH FAILING CLOSED ON AN EMPTY BAG:**

* the subject authenticated, and holds the role in
  `urn:sts:xacml:owner-required-role` (OWNER_READ or OWNER_WRITE — held ∩
  carried, so absent where the request is not an owner's question);
* `urn:sts:xacml:object-protected` is `false` — asked for, not the absence of
  `true`, so an object the PIP cannot answer for stays closed;
* `any-of-any` over `urn:sts:xacml:owner-identity` (subject) and
  `urn:sts:xacml:object-owner` (resource): the person or a group of theirs
  among the owners;
* the action (`urn:sts:xacml:admin-action`, on the ACTION) is on the list for
  the kind (`urn:sts:xacml:object-kind`) — a parameter per kind:
  `ownerRoleActions`, `ownerGroupActions`, `ownerServiceAccountActions`,
  `ownerApplicationActions`;
* `all-of-any` over `urn:sts:xacml:object-attribute` and
  `ownerApplicationAttributes`: every attribute an application act writes is
  one an owner may write (vacuous for an act that writes none);
* and never the last owner: `remove-owner` / `remove-service-account-owner`
  only with more than one value in `object-owner` (rcbj's decision 3).

`permitOwnerAdministration: no` builds the first rule alone. The defaults
leave out what turns owning into Admin: `create`, delete and rename,
`add-permission` on a role, `set-service-account`, `reveal-secret`, and an
application's scopes, roles, grant types, keys and delegation.
The one flow an owner MAY enable is `oauthAllowedTokenResponseTypes` (#1296,
rcbj's decision): the token response types the application may use, which
the realm must allow first — the registry refuses a value it does not
(`STS-REG-0364`), so owning an application never widens the realm.

**THE PIP ANSWERS THREE MORE DESIGNATORS** (`xacml_pip.ts`'s `ownerFact()`),
out of `common/ownership.ts`: `object-owner` and `object-protected` — the ONE
place it answers a RESOURCE designator, because the object is in the
directory too — looked up once per decision by `object-kind` and
`urn:sts:xacml:object-id`, and `owner-identity` by
`urn:sts:xacml:owner-subject` (the person by username; `subject-id` is the
client a person's token was issued to). An object that is not there answers
empty bags. So `/admin/xacml/decide`, a remote PEP and the management API ask
the same question and get the same answer. The facts and the protections are
argued in `common/CLAUDE.md` (3cn). `tests/owner_administration.js` holds it.

## A FEDERATED AUTHENTICATION'S CATEGORY (#565, 2026-10-19)

Three environment attributes, sent only when a federation partner vouched
for the authentication. The gate's `authorityFactsOf()` reads them from the
event being recorded or the session's latest, and `xacml_role_pep.ts`'s
`authorityAttributes()` puts them in, so a rule about them is inapplicable
to every other sign-in:

| Attribute (`AUTHN_ATTRIBUTE`) | Values |
|---|---|
| `urn:sts:xacml:authn-category` (`CATEGORY`) | `consumer` for a consumer or social provider (a relationship with `fedProvider`), `enterprise` otherwise |
| `urn:sts:xacml:authn-provider` (`PROVIDER`) | the provider: `google`, `discord`, `github`… absent for an enterprise partner |
| `urn:sts:xacml:email-verified` (`EMAIL_VERIFIED`) | `true` or `false`: a consumer provider's address is unverified unless the provider said so |

And one action-id: **`create-account`** (`ISSUANCE.ACCOUNT`), asked by
`federation/federation_sp.ts` before the session of a sign-in that would
CREATE the person, roles waived, with the sign-in's risk facts. No built-in
rule names it, so the risk rules decide it as they decide a session, and it
is the action an operator's rule targets to refuse creation (by category, an
unverified address, a level) while existing people still sign in.
`STS-FED-0179` is its refusal.

## A device-bound session an application requires (#740, 2026-10-25)

Two environment attributes, sent only while `authn.deviceBoundSessions`
is on (`AUTHN_ATTRIBUTE`):

| Attribute | Values |
|---|---|
| `urn:sts:xacml:device-bound-session` (`DEVICE_BOUND_SESSION`) | the fact: `bound`, `skipped`, `pending`, `timedout` or `none` |
| `urn:sts:xacml:device-bound-required` (`DEVICE_BOUND_REQUIRED`) | `true` when the application's passkey profile has `deviceBoundRequired` |

The built-in issuance policy's `device-bound-session` rule denies when
the requirement is `true` and the fact is `skipped` or `timedout`, with
the authentication obligation naming `device-bound-session`. A missing
attribute is an empty bag, and `string-is-in` on one is False, so the
rule does not fire when the feature is off or the profile does not
require a binding. `pending` is not that rule: `XacmlRolePep` holds it
before the policy is asked (`allowed: false`, `deferred: true`, no error
code, not counted). `skipped` and `timedout` are `STS-AUTHN-0462` there
too, so an override written without the rule, and `xacml.enabled` off,
still refuse. `none` and `bound` are not refusals. The fact is computed
in `common/issuance_gate.js`, which does not require the DBSC module.


## `access-control` has a third rule: the report API's rows (#1030, 2026-10-27)

rcbj: it was an absolute mistake that the report API's authorization
decisions bypassed the PDP. `report/rights.ts` decided who may see, run,
edit and delete a definition or a job with `if`s over the token's scope
string and a group's member list; it asks the gate now, on the resource
`report-api` (`common/access_gate.ts`), and decides nothing. The
arrangement is the owner rule's, read the other way round:

* **The owner is the FIRST rule's.** The gate puts the row's stored owner
  in `resource-owner` and the token's `sub` as the subject-id — a
  `urn:uuid:` person or a client — so `may-reach-it` permits an owner their
  own row exactly as it permits a person their portal account. A question
  about the API itself carries no owner and is the first rule's any-one:
  REPORT_USE or REPORT_ADMIN, held now and carried (held ∩ carried,
  `role_permissions.effectiveRoles()`, as the management API).
* **The third rule, `:rule:report-administrators-and-shares`**, TARGETED
  at resource-id `report-api` so no other surface's question trips it,
  conjoins: authenticated; holding a required role; `subject-kind` is
  `user`; and either REPORT_ADMIN among the roles, or the action among
  `reportSharedActions` (`read, run`) AND `any-of-any` over
  `urn:sts:xacml:owner-identity` (the PIP's answer for the person, the
  owner rule's) and `urn:sts:xacml:report-shared-group` (the DNs the
  definition is shared with — a job's, its definition's — as
  `Ownership.dnKey()` compares one). `urn:sts:xacml:report-object-kind`
  says `definition` or `job`, for a realm's own rule.
  `permitReportSharing: no` builds the document without it.
* **An application reaches only what it defined** (rcbj's decision 4): the
  `subject-kind` conjunct keeps it out of the third rule whatever role it
  holds, and the first rule permits it its own rows.
* **Two things the PEP learned for it** (`xacml_access_pep.ts`): the
  subject's `kind` is sent as `urn:sts:xacml:subject-kind` only when the
  caller gives one, so every other surface's request is unchanged; and a
  subject marked `effective` has its register roles LEFT OUT of the union
  — the built-ins alone are read, from the kind — because unioning them
  back would hand a `report:use` token REPORT_ADMIN for a subject who also
  holds it. `label` names the subject in the refusal and the audit row
  where `name` is an identifier.
* **The vocabulary is this service's own**, as the owner rule's is; the
  remote PEP carries none of it, as it carries no passkey vocabulary.

`tests/report_access_policy.js` holds it end to end; `tests/access_policy.js`
is untouched, which is the claim that the other surfaces are.

## Application-scoped fine-grained authorization (#564)

**The RESOURCE application that declares an `authorization_details` type
owns the policy that decides details of that type** (rcbj's decision 1 on
#564; the design and the six decisions are his comment of 2026-10-29). This
is phase 1: the policy model and its lifecycle. The mapping grammar (P2),
enforcement at issuance (P3), AuthZEN against an application's policy (P4),
the console and `/admin-api` (P5) and the protocol tests (P6) follow, each
adding to this section.

### The model

* **The policy is an ordinary `ou=policies` entry carrying
  `xacmlApplication`**, the owner's realm-local identifier. Beside it,
  `xacmlOrphanedAt` once the owner is deleted. Both are facts about the
  DEPLOYMENT, as `xacmlEnabled` is, and not about the document — so
  `xacml_store.ts`'s `write()` CARRIES THEM FORWARD when a caller does not
  name them. `writePolicy()` replaces the entry, and every door that rewrites
  a policy (the editor's save, enable, disable, the root demotion in
  set-root) passes only the document and the flags it read: without the
  carry, one edit in the editor would have turned an application's policy
  into an ordinary one, eligible as the root and sent to every remote PEP.
* **The application names it**: `appFgaPolicy` (the entry name) and
  `appFgaEnforced` (the switch, off by default) on its entry,
  `common/CLAUDE.md` (*Fine-grained authorization: the application's half*).
* **The default document is the `fga-default` template**: one Permit rule
  with no Target under deny-unless-permit, Version 1.0. A REAL decision, not
  a fallback: an empty permit-unless-deny document would answer Permit by
  falling through, which reads in an audit row like a policy that decided,
  and the day somebody deletes the rule this one denies. Its PolicyId is
  `urn:sts:xacml:fga:` and the identifier with every UTF-8 octet outside RFC
  3986's unreserved set percent-encoded (`PolicyBuilders.fgaPolicyId()`) —
  injective, which `slug()` is not (`a.b` and `a-b` slug alike), and a valid
  URI whatever the identifier holds. The ENTRY name is a handle for a
  reader: `fga-`, an 80-character slug, and twelve hex digits of the
  identifier's SHA-256; `-2`, `-3`… when that is taken.

### Never the root, and why the store says it rather than the callers

`root()`'s "the only enabled policy" fallback is the reason. Every
application created gets an ENABLED policy, so a realm with one ordinary
policy would hold two enabled policies the moment somebody registered a
client, the fallback would stop answering, and the realm would decide
NotApplicable to everything. So `root()` ignores an owned row in both halves
(a flagged one too, which only an `ldapmodify` can produce); `repository()`
leaves it out of the PolicyIdReference map (its PolicyId is chosen by whoever
named the application, and an orphan and its successor share one);
`write()` refuses one as the root (STS-FGA-0001); and `xacml_admin.ts`'s
set-root refuses it (STS-FGA-0002) BEFORE demoting the incumbent, which the
store's refusal alone would have left the repository without. The console
draws no make-root control on one. Every caller of `root()` and
`repository()` — the PDP's decide, the three embedded PEPs' repositories,
the remote PEP pull, `GET /xacml`, the console's counts — inherits the
exclusion without an edit; that is why it lives in the store.

### The lifecycle, `fga_policies.ts`

* **Created with the application** on the console's door —
  `createApplication()`, which the console, `/admin-api` and an LDIF import
  all go through. **NOT** a development-mode sighting, an RFC 7591
  registration or this service's own seeded applications: the first two can
  be made by an unauthenticated caller, and a policy per entry would let one
  fill `ou=policies` to `xacml.maxPolicies` and lock administrators out of
  writing policies. Every one of them gets its policy at first enable —
  decision 2's own fallback — as does any application created before 23c.
* **`ensure()` FOLLOWS THE REFERENCE AND NEVER ADOPTS.** A policy that merely
  carries the identifier is not attached. An application deleted through
  LDAP (which bypasses retirement) and created again under the same
  identifier would otherwise inherit a policy written for the one that went
  — exactly what keeping an orphan for audit must not grant. A failed
  reference write takes the new policy back, so no unreferenced live policy
  is left behind.
* **`enable()`** ensures, then refuses while the policy is disabled
  (STS-FGA-0006) or does not parse (STS-FGA-0007): an enforced application
  with such a policy refuses every detail, and the moment to say so is while
  somebody is switching it on. **`disable()`** touches only the switch.
* **`retire()` on deletion**: disabled, `xacmlOrphanedAt` written (RFC 4517
  GeneralizedTime), kept until an administrator deletes it (decision 3).
  **Orphaned is an explicit MARK, not a computation**: "its owner is not in
  the registry" stops being true when an application of the same identifier
  is created again, and the orphan would silently read as the new one's. The
  reference arrives from `deleteApplication()`, read before the entry went.
* **`resolve()`** is what P3 and P4 decide with: the row, parsed, and
  `enforced` — or a failure named and coded: `unknown-application` (0009),
  `no-policy` (0003), `missing-policy` (0004), `not-its-policy` (0005, also
  an orphan), `disabled-policy` (0006), `unparseable-policy` (0007). Each
  carries `enforced`, since only an enforced application's failure refuses.
* **Not by mode.** Nothing here differs between development and product.

**Owned policies have a ceiling of their own (#1210, rcbj, 2026-10-30):
`xacml.maxApplicationPolicies`, default 500 — `applications.max`'s default,
a literal and not a `derived` row (`common/config.js` argues it).** An entry
carrying `xacmlApplication`, orphans included, counts against it and NOT
against `xacml.maxPolicies` (200), which bounds administrators' own; each
kind is bounded only at a CREATE. Both doors hold it: the directory's
`writePolicy()` (`isApplicationPolicy()`, `policyCount(application)`,
STS-FGA-0024 logged) for every caller, and `ensure()` first, so its refusal
says which ceiling and names both settings rather than reaching it as "the
directory refused the entry". Orphans count because they are kept for audit
until an administrator removes them, and counting them against the
administrators' ceiling would let a deleted application's leftovers lock
administrators out. An application created past the cap is still created,
without a policy (STS-FGA-0024, logged under STS-FGA-0010 by the hook), and
gets one at enable once there is room. `/admin/ldap/policies` answers both
counts and both ceilings (`ownCount`/`max`, `applicationCount`/
`applicationMax`), and `state()` the applications' figure for the tab.

### Enabling grants the realm's remote PEPs (#1210)

**`enable()` ends with `grantRemotePeps()`** (`authzen/authzen_admin.ts`,
reached lazily through `loadAuthzenAdmin()`, which owns the directory slot
and both scope attributes), on EVERY enable, so an enable of an enforcing
application re-runs it for a holder that joined `remote-peps` since. Its
answer is `peps` on the result (`granted`, `held`, `failed`); a library that
throws is one `failed` row logged under STS-FGA-0025, never a failed enable.
`state()` carries `peps` (`remotePepsOf()`) for the tab. `authzen/CLAUDE.md`
has the design; what it changes in this family's own rules is one sentence:
**the REMOTE_PEPS group is now a source of AuthZEN permission, at the moment
an administrator enables an application** — rcbj's decision of 2026-10-30.
The older rule beside it is untouched: a registration in `ou=peps` is not a
permission, and nothing here reads `ou=peps`.

`tests/fga_policies.js` holds all of it in a throwaway realm.

### Enforcement at issuance, `fga_pep.ts` (P3) — rule 3cz

**The authorization, PAR and token endpoints ask the owning application's
policy about each detail of its types, once `appFgaEnforced` is TRUE**
(`oauth-oidc/CLAUDE.md` 3am says where in each and why). They ask
`common/fga_gate.ts`, a leaf slot this module fills at 23c — rule 3e both
ways round, `common/CLAUDE.md` argues it — and **the gate REFUSES when
empty**, unlike the issuance gate: the question is only asked of an
application somebody switched on.

* **The policy alone.** `resolve()` (P1), `fga_map.request()` (P2), then
  `xacml.ts`'s new `decidePolicy(policy, request, { repository, resolve })`
  — what `decide()` now goes through for the root — with NO repository: an
  owned policy's PolicyId is chosen by whoever named the application, and
  the store keeps owned policies out of the map for that reason. P4's AuthZEN
  decision against an application's policy uses the same method. The PIP is
  asked only for a `user` subject (AuthZEN's `resolves()` line): a client
  credentials subject, or nobody at PAR, is not a directory entry.
* **Only a Permit with nothing undischargeable is yes** (`enforce()`,
  deny-biased). Deny, NotApplicable and an Indeterminate over a missing
  attribute DENY (`STS-FGA-0014`); a detail the mapping refuses DENIES under
  the mapping's code (0100–0107) — it cannot be put to the policy. A resolve
  failure (0003–0007, 0009) and an Indeterminate the engine reached through
  a processing or syntax error (`STS-XACML-0013`, re-coded `STS-FGA-0015`)
  are OPERATIONAL FAILURES (`server_error`): nobody decided, and a client
  told `invalid_authorization_details` would believe the detail was wrong.
  A throw is a failure too, and still audited.
* **One `fga.decision` audit row per decision**: application, policy entry,
  PolicyId and version, type, definition digest, subject and kind, client,
  stage, grant, outcome, XACML decision, code — and a SHA-256 of the
  detail's canonical JSON, NEVER a value: a detail is one transaction's
  facts, and the audit log is read by people never meant to see them. The
  action is in `audit.js`'s table and its label in the six catalogs.
* **The monitor's `fga` row**, `kind: 'embedded'`, `enforces: true`: this
  process grants or refuses, so allowed and refused are counted as for the
  other two PEPs. Only decisions the PDP REACHED are counted; a resolve
  failure or a refused mapping is audited and not counted, which keeps the
  row's reconciliation (allowed + refused + unenforced = decisions) about
  decisions the engine made.
* **Coverage is enforced at both doors**: `enable()` refuses while a type
  the application declares has a non-empty `uncovered()`
  (`uncoveredTypes()`, `STS-FGA-0018`), BEFORE ensuring a policy, so a
  refused enable writes nothing; and `applications.js` refuses a type
  definition written to an enforcing application that would be uncovered
  (`STS-FGA-0019`, `common/CLAUDE.md`).
* **Not by mode.**

`tests/fga_issuance.js` holds the gate, the PEP over stubs, and the
endpoints end to end in a throwaway realm.

### AuthZEN against an application's policy, `decideAccess()` (P4)

**rcbj's decision 4: resource servers talk to remote PEPs, and FGA is
decided ONLY here, at the AuthZEN endpoint.** An evaluation whose resolved
application has `appFgaEnforced` TRUE is decided against THAT application's
policy instead of the realm root (this amends #563's decision 7;
`authzen/CLAUDE.md`, *What is decided*, carries AuthZEN's half). This
directory's half:

* **One first step for both questions.** `policyOf()` is the resolve and its
  coded failure, logged once, and both `evaluate()` (issuance) and
  `decideAccess()` (access) start with it; both then call `xacml.ts`'s
  `decidePolicy()` with NO repository. So an issuance question and an access
  question about one application cannot come to disagree about which
  document is its policy, or about how a PolicyIdReference in it resolves
  (it does not: the map is the root's, and owned policies are kept out of
  it).
* **What `decideAccess()` does NOT do**, because AuthZEN already does it:
  build the request (AuthZEN's mapping, with the builder's `fgaAccess()`),
  read the answer (decision 8's `outcome()`, which tells a fault by the
  STS-XACML-0013 mark `decidePolicy()` leaves), audit (`authzen.decision`,
  naming the policy) and count. **It is counted on the monitor's `authzen`
  row, never `fga`**: that row is the issuance PEP's and counts
  enforcements, and an AuthZEN answer is enforced by its caller; counting it
  on both would count one decision twice.
* **It answers, never throws**: the PDP's answer with the policy's entry,
  PolicyId and version, or `{ ok: false }` under the resolve's code
  (0003–0007, 0009) or `STS-FGA-0015` for a throw — which AuthZEN answers
  as an ERROR (`STS-AUTHZEN-0046`, 500), never `false` and never the root.
* **The builder, rule 3br**: `fgaAccess({ application })` adds
  `urn:sts:xacml:fga:application` (resource, as `fga()` writes it, so one
  target matches both questions) and `urn:sts:xacml:fga:stage = access`
  (always) to AuthZEN's request, and nothing else. Both identifiers were
  already in `VOCABULARY` and spelt by the Rust builder, so the remote PEP
  needed nothing; an embedded FGA PDP there (future work) would find them.
* **And `fga()` writes no subject when there is no id** (a P3 leftover):
  `principal()` writes `''` for an absent name, which several PEPs mean as
  "nobody", but an application's administrator reads `subject-id == ""` as
  somebody. At PAR, before anybody signed in, the request now carries no
  `subject-id` and no subject kind; the client stays.

`tests/fga_authzen.js` holds it end to end; `tests/xacml_request.js` F7 and
F8 hold the builder.

### The console and `/admin-api` (P5)

**Four more methods on `fga_policies.ts`, so the console decides nothing.**
`reset()` rewrites the application's OWN policy from `fga-default` under
the same entry name — following the reference as `ensure()` does, so an
orphan or somebody else's policy is never rewritten (STS-FGA-0021: create
one instead) — and keeps its enabled flag, because "reset the document" and
"turn it back on" are two decisions. It needs `confirm` (STS-FGA-0020): on
an enforcing application it widens what is allowed at once. `holderOf(row)`
is the one test for "may this policy be removed": the application that
names it in `appFgaPolicy`, or ''. **The orphan mark is not that test** — a
policy left by an application deleted through LDAP carries no mark and is
still named by nobody. `ownedPolicies()` groups `store.fgaPolicies()` by
owner with `known`, `enforced` and each policy's `referenced`; `state(id)`
is the application tab's view (the switch, the reference, the policy with
its editor link, `usable` with the resolve's `code` and `why`, each type's
`uncovered()`).

* **`xacml_admin.ts`'s `delete` refuses a policy an application still
  names** (STS-FGA-0022), before removing anything: the application would
  be left naming nothing, and an enforcing one would refuse every detail
  (0004). The orphan, decision 3's, is removed through the same `delete`.
  `policiesJson()` carries `applicationPolicies` (`ownedPolicies()`), and the
  Policies tab draws the owned rows there instead of in the repository's
  table. Both reach `fga_policies.ts` through a lazy `loadFga()` dep: it is
  built by the composition root at 23c, and a require at load would run
  its slot's build ahead of that.
* **What the console and API act through** is `admin-ui/CLAUDE.md`'s and
  `mgmt-api/CLAUDE.md`'s; the audit rows are the ones P1 writes
  (`xacml.policy.write` for create and reset, the entry's modify for the
  switch, `xacml.policy.delete` naming the orphan's application).

`tests/fga_console.js` holds it.
