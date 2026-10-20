# CLAUDE.md — `portal/`

## A STATIC APPLICATION SINCE #568 (2026-10-12) — READ THIS FIRST — rule 3ck

**The portal is drawn in the browser now**, on the admin console's pattern
(#446). `/portal` and every path under it answer one document
(`portal.ts`), which loads `/portal/portal.js` — the runtime and every page's
renderer — and `/portal/portal.css`. The runtime signs in as the PUBLIC client
`sts-user-portal` (PKCE, `account:manage`, every token DPoP-bound to a key the
browser cannot export, held in memory), draws every page from an
`/account-api` operation and sends every form to the operation that mirrors
it. `account-api/CLAUDE.md` argues the API, its gate and its answer
conventions. rcbj's four decisions on #568: the console's pattern (reversing
#444's D9 for the portal), `/account-api`, the pages for nobody drawn the same
way, and the console-session adoption dropped.

| Files | What they are |
|---|---|
| `portal.ts` | The server half that is left: the shell (drawn and sent through `common/shell_document.ts` since #570, its bytes unchanged), its script and stylesheet, the realm chooser before a sign-in, `/portal/signals/receive`, and the directory slot (`personEntry()`). |
| `account_*.ts` (seven), `portal_*.ts` (fourteen) | Each page family's `/account-api` operations — the page's view and its forms — with the reasoning below. The seven `account_*` modules are the pages that were in `portal.ts`. |
| `web_*.ts` | The browser half: `web_portal_runtime.ts` (sign-in, routing, forms, how an answer is drawn; since #570 `PortalRuntime extends SpaClient extends WebPage`, `common/web_spa_client.ts` and `common/web_page.ts`, whose `publicJson()`, `formFields()`, `realmLinks()`, `targetFragment()` and `saveBase64()` it inherits — `common/CLAUDE.md`, 3cl), `web_portal_shell.ts` (the frame), `web_portal_kit.ts` (`NAV`, the stylesheet, the icons), `web_portal_webauthn.ts` (the ceremonies), `web_portal_pages.ts` (every page's row) and one renderer module per family. |

**WHAT THE SECTIONS BELOW SAY THAT IS NO LONGER SO**, read with this table
rather than rewritten one by one, because most of each section is about what
a page DOES, which did not change:

| The section says | Since #568 |
|---|---|
| a page is drawn by a method of `Portal` and answered by a route here | it is drawn by its `web_*.ts` renderer from its operation's answer |
| `requireSignIn()`, the portal's relying-party session, `sts_portal`, `oidcRp.renewal('portal')` | gone: the token is the session, and `/account-api`'s gate asks what `requireSignIn()` asked — the access policy included |
| a CSRF token on every form (A07) | gone with the cookie it guarded: a request is a DPoP-bound token and a proof by a key no other page holds |
| a write answers 303 with `?done=` | it answers `{ ok, message }` in the person's language; a secret shown once is a `view` drawn in place |
| every page here but a few is `script-src 'none'`, and a page that "has no script" or "runs no script" | every `/portal/*` path is the one shell under `script-src 'self'` and `connect-src 'self'`, and every page runs `/portal/portal.js`; what "no script" still means is that the page needs nothing in the browser beyond drawing its answer and sending its forms |
| `/authn/webauthn.js` on `/portal/keys`, `/portal/activate`, `/portal/devices`; `/portal/copy.js` on `/portal/mfa` | the runtime runs the ceremonies and reveals the Copy buttons (`web_portal_webauthn.ts`); the four scripted-page rows are one in the root `CLAUDE.md` |
| the `Location`-header bug and `oidc_rp.js`'s choke point | the runtime builds its own authorization request under the realm's prefix |
| `NAV` in `portal.ts` | `NAV` in `web_portal_kit.ts`, read by the frame and by `paths()` |
| the console-session adoption (2026-09-30) | DROPPED: single sign-on through `/oauth2/authorize` covers it |

**THE RULE THAT MATTERS MORE THAN THE REST IS UNCHANGED AND IS HELD AT THE
API**: no operation takes a username, an id or a DN naming whose account it
acts on — the person is the token's subject.


## THE FIRST PAGE IN THIS SERVICE THAT BELONGS TO THE PERSON LOOKING AT IT (2026-09-06)

Every browser-facing surface here until now was for somebody else. The sign-in
screen is a step in another protocol's flow. The consent screen asks one
question and leaves. `/admin` is for an operator and is gated on two roles.
**Nothing let a person see what this identity provider knows about THEM, or
change how they authenticate.**

**IT WAS ONE PAGE OF FOUR CARDS UNTIL 2026-09-06 AND IS FOUR PAGES BEHIND A
NAVIGATION COLUMN NOW.** Four cards is a page; six is a scroll, and the control
somebody came for is below the fold of a page about something else.

| Route | Who | What |
|---|---|---|
| `/portal/activate` | **unauthenticated** | spending a single-use activation link to set up a credential |
| `/portal/reset-password` | **unauthenticated** | spending a password reset link an administrator issued (2026-09-13) |
| `/portal` | authenticated | **Overview** — who they are, this session, a summary of how they sign in, and the wider sign-out |
| `/portal/applications` | authenticated | **Applications** — where this identity provider will sign them in |
| `/portal/password` | authenticated | **Password** — the form, and the POST that answers it |
| `/portal/keys` | authenticated | **Security keys** — the list, and a Remove per key |
| `/portal/mfa` | authenticated | **Authenticator app** — the QR code, the typed secret, and the code that confirms it |
| `/portal/signals` | authenticated | **Security activity** — what this identity provider has said about the person over CAEP and RISC (2026-09-10) |
| `/portal/sign-ins` | authenticated | **Recent sign-ins** — the person's own risk assessments of thirty days, each with "this was me" / "this wasn't me" (#62 P6, `portal_sign_ins.ts`; `risk/CLAUDE.md` argues what each answer moves) |
| `/portal/consents` | authenticated | **Consents** — what the person agreed each application may ask for, and a Withdraw per scope and per application that revokes what was issued under it (#172, `portal_consents.ts`); and, under **Administrative consents**, the global consents that answered for them at sign-in, with no button (#537) |
| `/portal/gnap` | authenticated | **GNAP grants** — the GNAP grants the person is the resource owner of, each with its rights, tokens and why it ended, and a Revoke (#432 phase 7, `portal_gnap.ts`) |
| `/portal/signing-key` | authenticated | **Signing keys** — RFC 7523 and RFC 7522 key pairs and TLS client certificates (2026-09-12) |
| `/portal/certificates` | authenticated | **Certificates** — ACME / SCEP enrollment credentials and the certificates issued (2026-09-13) |
| `/portal/callback` | — | the OIDC redirect URI |
| `/portal/signals/receive` | **unauthenticated** | this portal's Shared Signals push endpoint — see the A01 section |
| `/portal/remove-key`, `/portal/signout` | authenticated | the two other POSTs |

**FIVE PAGES SINCE 2026-09-10**, and the fifth is the first here that HANDS
SOMEBODY A CREDENTIAL rather than taking one. **EIGHT SINCE 2026-09-13** —
`NAV` below is the list.

**`NAV` IS THE PAGE LIST AND THERE IS NO SECOND COPY.** `navBar()` draws the
column from it, `headingFor()` titles the page from it, and `paths()` reports it
to `sts_metadata.ts` — so a page added there appears in the column, in the
browser tab and in the endpoint list, and one removed leaves none of the three
behind. `tests/vendored/sts_portal_sessions.js` asserts, for the first four
(Overview, Applications, Password, Security keys), that its own entry is marked
`aria-current="page"`.

**A `GET` AND A `POST` SHARE `/portal/password`.** The form has to live
somewhere now that it is not on the overview, and a form and the handler that
answers it on two addresses is a distinction nobody could state a reason for.
`sts_metadata.ts` is keyed by path and merges the methods, so this costs one
entry rather than two.

**THE GETs ASK THE ACCESS GATE FOR `read` AND THE POSTs FOR `manage-own`.**
Drawing a page is reading. That distinction is the reason the portal has an
action of its own at all — see `common/access_gate.ts`'s `ACTION` — and a
deployment that later lets a helpdesk role READ an account without changing it
needs the two to have been kept apart from the beginning.

## `/portal/applications`: THE ISSUANCE POLICY, ASKED ON SOMEBODY'S BEHALF (2026-09-06)

Every other page here is about the person. This one is about what the account
is FOR, and it is the first page in this service to put the application
registry and the issuance policy together and answer a question a person rather
than an operator would ask: *where will this identity provider actually sign me
in?*

### It asks `common/issuance_gate.js`, and that is the whole design

The same call the nine issuance sites make — the token endpoint, both SAML
profiles, WS-Federation, WS-Trust, the KDC. **The alternative was a second
implementation of the rule and it is the one thing this page must not be.**
Reading `appRequiredRole` off each entry and comparing it with
`roles.rolesOf()` would work today, would be shorter, and would be the first
thing to disagree with the enforcement the moment somebody edited the issuance
policy on `/admin/xacml/policies` — a page telling a person they may sign in to
something the token endpoint then refuses.

A process with no XACML family has no decider, `check()` answers allowed, and
the page lists everything with a sign-in family. That is the gate's own "a
smaller service rather than a broken one", read from the outside.

**It asks once per application PER DISTINCT ISSUANCE KIND**, not once per
application and not once per family. Per kind because `kind` becomes the XACML
`action-id`, and a policy that says something different about an ID Token from
what it says about a SAML assertion is a policy somebody may write. Not per
family because SAML 2.0 and SAML 1.1 both end in `issue-saml-assertion`, so
asking twice is asking one question twice and paying for it.

### It lists what the policy permits and names nothing it does not

The refused entries are COUNTED. That is the convention every enterprise
account portal follows and it is right here for a reason of this service's own:
the registry holds the applications of everybody who uses this identity
provider, and a page naming them all to any signed-in person would be an
application directory rather than an account page. What somebody is told is how
many there are and who decides — true, useful, and names nobody.

**It is not a security boundary and is not offered as one.** `/admin-api`
hands the whole registry to anybody holding an `admin:read` token — a
credential this service will mint for anybody who has the seeded client's
secret, which is a configuration value and not a person. This is a page choosing not to answer a question it was not asked, which
is a different thing from a page that could not.

### Five families count as a sign-in, and the ones left out are counted too

OAuth 2.0, OpenID Connect, SAML 2.0, SAML 1.1 and WS-Federation. **WS-Trust and
Kerberos are deliberately not among them**: both are real issuances the gate
decides, and neither is a person signing IN to an application in a browser,
which is the question this page asks. Shared Signals receivers, SCIM clients,
LDAP binders, SPIFFE workloads, OID4VP verifiers and mutual-TLS clients are not
sign-in destinations at all. Everything left out is counted at the foot of the
page rather than dropped silently.

DECLARED and OBSERVED families both count. An entry an operator created and
ticked SAML 2.0 on has never been seen; one signing people in for a month may
never have been declared anything. Either is an answer to "could I sign in to
this".

### It is a DRY RUN, and the gate has to be told

`preview: true` on the request, honoured in `xacml/xacml_role_pep.ts`. Nothing
is being issued — somebody is looking at a page — so the refusals must not be
written to the audit log as `xacml.issuance.refused` and must not be counted on
`/admin/xacml/monitor` as decisions this service made. Drawing this page for a
person with two permitted applications out of forty would otherwise write
thirty-eight refusal rows into a 5,000-event ring on every load, and read on
the monitor as a service refusing issuance constantly.

**That flag fixed something older than this page.** The console's own dry run at
`/admin/roles` had been writing those rows and moving those counters since it
was written, for issuances nobody had asked for. `issuance_gate.js` needed no
change at all: it passes the request through untouched.

### Each row LINKS to the application, and the link is declared rather than derived

Since 2026-09-10. The page listed the applications a person may sign in to and
gave them no way to reach any of them: a name and a client_id are not somewhere
you can go, and "where is Acme Expenses" is the first question a reader of this
list has.

The link is `appHomePageUrl` off the application's own entry — a registry
attribute added for this, written by hand, by the console, by `/admin-api`, or
by `register()` out of RFC 7591's `client_uri`. `common/applications.js`'s row
for it carries the argument; the half that matters here is that **it is stated
and is never computed from the redirect URIs already on the entry.** That was
the first implementation: take the ORIGIN of the first http(s) redirect URI.
It was rejected because a redirect URI is a CALLBACK — a browser sent to one
carrying none of the parameters it exists to receive gets an error from the
application rather than its front door — and because the origin above it is a
GUESS that is wrong for every application served under a path. **A page whose
links are right often enough that nobody checks them is worse than a page with
no links.**

**AN ENTRY WITH NO HOME PAGE IS DRAWN GREYED OUT AND STILL LISTED.** That is
the ordinary shape of an entry a protocol endpoint created — nothing in a
token request says where the application lives — so it is not an error and it
is not this person's to fix. The name stays the name and simply is not a way
in; the `title` says who can make it one, because a grey name with no
explanation reads as something broken. `linkedName()` is the whole of it.

**http OR https AND NOTHING ELSE**, checked where the value is written AND
again where it is read. Both are needed: the console form and
`POST /admin-api/applications/set` go through `updateApplication()`, and an
`ldapmodify` on TCP 389 goes through neither. The schemes are an ALLOWLIST
rather than a list of ones to avoid — this registry accepts an entry from a
dynamic client registration, so a scheme of somebody's choosing must not be
able to reach an attribute a signed-in person's page renders as an `href`.

### The name is not a launch button; the Sign in links beside it are (#426)

The name goes to the application's own front door and hands it nothing, which
is where a sign-in starts and is exactly what a person would type themselves.
**This heading said "still not a launch button, and that is a refusal rather
than a gap" until #426**, on the ground that this service implemented
identity-provider-initiated sign-on in none of the browser profiles. That was
already out of date — `/saml2/unsolicited` arrived with #189 and the OpenID
Connect Core section 4 link with #120 — and #426 made it a feature: a row
carries one **Sign in** link per protocol it can be started in
(`launches`, from `account_overview.ts`'s `launchableOf()`), each
`/launch/{app}?protocol=…`, the same URL the console shows on the
application's protocol sub-tab. A protocol is offered only where the issuance
policy's dry run permits its family, the application's identity-provider-
initiated switch is on (off by default), and there is somewhere registered to
send it. The OpenID Connect link went straight to the client's
`initiate_login_uri` before #426; it goes through the door now, which records
the launch and obeys the client's switch. `launch/CLAUDE.md` argues the door.

### It is paginated, and the cap is a setting since 2026-09-12

Twenty rows a page. The scan stops at `portal.applicationScanLimit` entries —
1,000 by default — and says when it bit, with the number in force: each entry
costs a policy evaluation per distinct kind, on the one thread that answers
every socket this service holds, which is the stall `common/CLAUDE.md`'s
worker-pool section is about. **This heading said "a guard rather than a setting"** on the
argument that a configuration row would be a knob nobody turns until the day
the page is already slow. The half about the page being slow still holds; what
it left out is the deployment whose registry is past a thousand on purpose,
which could not see its own applications at all short of editing the source.

**THERE IS NO `/admin-api` MIRROR, WHICH IS A DEPARTURE FROM THE STANDING
CONVENTION AND IS ARGUED RATHER THAN OVERLOOKED.** A console page gets a
management API resource in the same change; this is not a console page. The
answer is per-person, and `/admin-api` authenticates a CLIENT rather than a
person — so mirroring it would mean an endpoint that takes a username in a
parameter and answers about whoever is named, which is the exact A01 shape the
rule at the top of this file forbids. **The gate that arrived on 2026-09-09
does not change this and it is worth saying why**: what that gate establishes
is that the CALLER may administer this service, and the question this page
answers is about the SUBJECT — an identity nothing on the request may
nominate. A token is not a person. The feature is still
driven by a test, which is what the convention is for:
`tests/vendored/sts_portal_sessions.js` signs a real browser in and reads the
page.

### What the test asserts, and why the decisive one is a TRANSITION

A page that listed every application would pass "the permitted one is listed"
perfectly. So the assertion that means anything is that GRANTING A ROLE CHANGES
THE LIST: an application narrowed to a role is absent, the role is granted
through `/admin-api/roles/add-member`, and it appears. `xacml/CLAUDE.md` records
the sixteenth defect being exactly a guard that was never true and invisible to
every assertion about a value.

Mutation-tested by turning `roles.enforceIssuance` off, which makes the gate
allow everything: the narrowed application appears and the assertion fires.

The second one is about what is NOT recorded — the monitor's counters and the
audit log are read either side of one page load and must not move.

## `/portal/mfa`: THE FIRST PAGE HERE THAT HANDS SOMEBODY A CREDENTIAL (2026-09-10)

RFC 6238. Every other page in this portal takes a credential or reports on one;
this one MINTS a shared secret and shows it. The design follows from that.

### Two steps, and the first writes nothing

Pressing *Set up* mints a secret and holds it in memory (`totp.enrolmentTtlMinutes`,
per realm, like every other pending record in this service);
`common/credentials.ts` writes the attribute only when a code proves the app
really has it.

**An unconfirmed secret on somebody's entry would be a second factor they
cannot produce.** That is not a hypothetical: open this page, be interrupted,
come back tomorrow — a one-step enrolment has just locked somebody out of their
own account with a form they abandoned. It is the same shape of lockout
`removeKey()` refuses to create, caught before it exists rather than after.

### The QR code is an image this server drew, and the typed secret is not a fallback nobody sees

Until #568 (2026-10-12) `script-src 'none'` covered every page here except
`/portal/keys` (see below, 2026-09-10) and a few states of others the root
`CLAUDE.md`'s table listed, so a QR library running in the browser was never
available on this one — `common/totp.ts` renders an SVG and it arrives as
a `data:` URI, which `img-src 'self' data:` already allowed for the two OID4VC
offer pages.

The transcribable secret is drawn BESIDE it, in groups of four, with the
algorithm, digits and period written out, because scanning is impossible in
three ordinary situations: **the phone IS the browser showing this page**, the
desktop authenticator has no camera, and a `localhost` QR code photographed
from a screen still points at a host the phone cannot reach. The last is the
common case for a mock, which is why this is a first-class half of the page and
not a `<details>` underneath.

### The secret is on a page, which is exactly as dangerous as it sounds

Four things bound it, and they are the four to keep if this is ever reworked:

* `no-store`, like every page here;
* it is only ever drawn for the SIGNED-IN person — the rule at the top of this
  file, and it matters more on this endpoint than on any other, because a
  `username` read from the body would not be an information leak but a
  TAKEOVER: anybody signed in could enrol their own app as somebody else's
  second factor and then hold a factor for an account they do not own;
* **it stops being shown the moment it is confirmed** — the enrolled page
  reports that an app is set up and never the secret behind it, so a browser
  left open here does not become a standing copy of somebody's second factor;
* an unconfirmed secret expires.

### Enrolling again REPLACES, and the button says so

One secret per person, which is a fact about the protocol rather than a policy:
a six-digit code names no credential, so two secrets would mean trying both —
doubling what a guess can hit, and leaving RFC 6238 section 5.2's accept-once
rule with no answer to *which counter was spent*. Somebody who scans a second
code and leaves the first app configured has an authenticator that silently
stopped working, so the warning is on the button rather than in a note below it.

### `start` is a redirect and not a render

A rendered response to a POST is one the browser offers to re-submit, and
re-submitting `start` would mint a SECOND secret and invalidate the code the
person has just scanned. A wrong code, by contrast, REDRAWS THE SAME SECRET:
mistyping six digits is the ordinary case and re-scanning for a typo is the
reason nobody would finish this.

### It is the one page here that is `async`

Because drawing a QR code is. Worth a sentence rather than being left to be
noticed: `common/CLAUDE.md`'s worker-pool section lists exactly four
asynchronous call paths in this service and this is not one of them — the work
is a few hundred microseconds of squares, so it is awaited here rather than
handed to the pool.

### `manage-own` for all three actions, `start` included

Minting a secret and holding it is a change to how this person will sign in,
even though nothing reaches the directory until `confirm`. A deployment that
later lets a helpdesk role READ an account without changing it must not have the
enrolment door on the read side of that line.

## `/portal/keys`: ENROLLING A PASSKEY, AND A BACKUP FOR IT (2026-09-10; *Passkeys* since #470)

**THIS PAGE COULD NOT ENROL A KEY UNTIL THIS DAY**, and it said so in a
paragraph of its own:

> *A key is enrolled DURING A SIGN-IN — tick the security-key box at the
> sign-in screen, and the first use enrols — or when an activation link is
> spent. There is no enrol button here, because a WebAuthn ceremony belongs to
> a sign-in and this page is not one.*

**THE PREMISE IS FALSE.** A WebAuthn ceremony belongs to whoever is asking, and
a signed-in person registering a credential is the ORDINARY WebAuthn flow — it
is how every real relying party does it. What belongs to a sign-in is an
ASSERTION.

### What it cost was the backup

The sign-in screen's checkbox is enrol-on-first-use and is reserved for people
who hold NO second factor yet — correctly, because enrolling there for somebody
who already holds one is the bypass `authn/CLAUDE.md` argues. So there was
**exactly one key per person and no door to add another**: the multi-valued
attribute in `credentials.js`, the credential id WebAuthn puts on every
assertion and the `webauthn.maxKeysPerPerson` setting were all describing a
state nothing could create. A lost key meant an operator clearing it, which is a
support queue rather than a security control — and the other half of that
sentence is that the person holding one key had no way to prepare for it.

### Two steps, and `excludeCredentials` is the part that makes a backup a backup

`credentials.beginKeyEnrolment()` mints a challenge and holds it;
`confirmKeyEnrolment()` verifies what the browser produced and only then writes.
The ROLE is chosen at the start and carried, never read off the answer — the
POST at the far end is the browser's RESULT and says nothing about what was
asked for, which is the rule the sign-in ceremony already follows.

**The keys the person already holds go out with the options.** A conforming
authenticator that recognises one refuses rather than creating a second
credential, which stops the commonest way to get this wrong: pressing Add and
touching the key already plugged in. That produces a second row for one device —
a backup that is lost with the original, which is the exact failure the feature
is against. **This service checks again at the write**, because the list is a
request to the browser like every other ceremony option.

### The attestation is verified, and each key says what it proved (#105)

`confirmKeyEnrolment()` hands the verified ceremony to
`authn/webauthn_attestation.ts` before the credential id is claimed, so a
statement the realm's `webauthn.attestationPolicy` refuses is a refused
enrolment (400, the sentence on the page, the pending enrolment kept for another
try) and nothing is written. What an accepted statement proved is on the key
row — `attestation` — and this page draws it in the person's words
(`attestationText()`): the model the FIDO metadata names and "verified and
trusted", "verified" with no trusted root, "no attestation sent", or "not
verified" where the policy verified nothing. `authn/CLAUDE.md`, *The
attestation statement*, has the rest.

### The recovery codes' Copy button is a script, and the box beside it is the fallback (#224, 2026-10-06)

rcbj: "Right now, the user must select and copy the displayed text. The
resulting formatting is messed up." A fresh set is drawn as a grid, and a
selection across a CSS grid copies as whatever the browser makes of it. So
the card says the codes twice: the grid, to read, and a READ-ONLY BOX holding
them one per line, which a selection copies exactly as drawn. The **Copy all
codes** button writes that box to the clipboard, which no markup can, so the
one response that shows a fresh set (`sendCodesPage()`, the POST of
`generate-codes`) carries `script-src 'self'` for `/portal/copy.js` and nothing
else; every other state of `/portal/mfa` runs no script. With script blocked
the button stays hidden and the box is the whole mechanism. The script reads
only the box beside its button and sends nothing. rcbj asked for the same in
the admin console and then withdrew it: the console never shows a person's
codes (`admin-ui/web_users.ts`, the recovery codes block).

### It is the SEVENTH scripted page in this service and the first in this portal

It arrived 2026-09-10, in a directory whose own file said every page of it was
`script-src 'none'`. (History since #568, 2026-10-12: every portal page now
runs `/portal/portal.js` under `script-src 'self'`, and the ceremony is
`web_portal_webauthn.ts`'s; the argument below is why the page needed a
script at all.)

`app.js` sets `script-src 'none'` as the service-wide default and the rule is
that a page gets an exception only when it CANNOT work without one — several candidates have been
refused on it (the root `CLAUDE.md` lists them), `/authn/totp` among them, which sits next door to a scripted page
and still had to argue its own case.

**A WebAuthn ceremony is a browser API call.** There is no markup that invokes
`navigator.credentials.create()`, no form that produces an attestation object,
and no server-side substitute: the private key is generated inside the
authenticator and never leaves it. That is the same argument `/authn/webauthn`
was granted its exception on, made again rather than cited.

**It is the SAME SCRIPT and not a second one.** `/authn/webauthn.js` reads its
parameters off a `wa-data` element, so this page emits that element and points
at that URL — one implementation of the ceremony in the browser, and a second
copy would be a second place for the base64url handling to go wrong, which has
happened once in that file's history already. **That is not a precedent for
skipping the argument** — the argument above is why the page may have a script
at all; sharing the resource is only how. It is the one entry in the root
`CLAUDE.md`'s table of scripted pages that names a script already there.

**The relaxation goes through `app.contentSecurityPolicy()`** and never a
hand-written header, which is the root `CLAUDE.md`'s rule and the reason it
exists: that builder re-adds `frame-ancestors` and `base-uri` whatever the
caller asks for, and a header written here could lose the framing clause with
the page still working and the script still running. `sendKeysPage()` is used
for every response of both handlers, because a policy that changed between two
states of one page is a policy nobody can reason about.

**The real button is there and is labelled for a person.** With the script
blocked it posts a `finish` with no credential, and the handler answers *your
browser did not run the ceremony* — naming the one step that needs it and saying
the rest of the portal runs no script at all.

### The passkey page (#470, 2026-10-06)

rcbj asked for the passkey screens to follow the FIDO Alliance's passkey
management guidelines (passkeycentral.org, *combining all passkey types*).
What that changed, and why each piece is the way it is:

* **One heading, *Passkeys*, over two groups, in a person's words.** The
  groups are *passkeys on your devices* and *passkeys on security keys* —
  never "synced" and "device-bound". `credentials.keyGroup()` decides which:
  - **the backup eligibility flag first.** A synced passkey reached over
    hybrid is reported `cross-platform`, and it belongs with the devices.
  - **then the attachment.** Windows Hello is device-bound and still a
    device.
  - **then, for a key that recorded neither, its transports.**

  BE, BS and the transports were checked by `webauthn.js` and dropped until
  this change. `addKey()` keeps them now, and `noteKeyUsed()` keeps BS
  current, because BS can change after enrolment.
* **Each row shows:**
  - a server-drawn SVG icon. It is markup, not an image, so `img-src` is
    untouched;
  - the name, from `keyName()`: the label, else the default;
  - the provider;
  - Created and Last used. `lastUsedAt` was recorded and never drawn;
  - Rename and Remove;
  - a *Details* `<details>` with the role, algorithm, attestation, AAGUID,
    backup state and transports. This is a debugging service, so nothing
    technical was dropped, only folded.

  Rename is a `<details>` holding a form, so it needs no script.
* **The provider.**
  - **When a FIDO MDS BLOB is loaded, MDS alone names it** (rcbj, on the
    ticket): the description for the key's AAGUID.
  - Otherwise `authn/passkey_providers.ts`, a short hand-written table of
    credential managers, names it. The community list carries no licence,
    so it was not copied.
  - Which source answered is decided once, at enrolment (`keyProviderFor()`,
    asynchronous), and kept as `provider` and `providerSource`, because a
    page is drawn synchronously.
  - A name proves nothing, and nothing that decides reads it.
* **The two calls to action** are two submit buttons of one form, so the
  button pressed is the `kind`, with no script.
  - *Create a passkey* asks for a discoverable credential and HINTS
    `client-device`, then `hybrid`, with no attachment. That is how the
    2026-09-26 lesson (Linux Firefox refused a hard `platform`) survives.
  - *Use a security key* asks for `cross-platform` and hints `security-key`.
* **The name comes after the ceremony, not before.**
  - The box before it is gone.
  - A key defaults to its provider's name, else "Passkey" or "Security key".
  - The success redirect carries `named=<credentialId>`, and the page opens
    that key's rename form at the top.
* **`POST /portal/rename-key`** follows `remove-key`'s A01 rule: the id comes
  from the body and is looked up among the session's own keys.
  `credentials.renameKey()` is the one writer, also used by
  `POST /admin-api/users/rename-key`. An empty name restores the default.
  It is audited, and sends no CAEP event, because a name is not a
  credential change.
* **The Signal API** (WebAuthn Level 3 section 5.1.10) runs in the same
  shared script, which reads a `wa-signal` element: all accepted credential
  ids, plus the display name, under the person's USER HANDLE (#474) — 64
  random bytes on their entry, unique to one entry in one realm. Until
  #474 the handle was the username, so the same username in two realms
  was one account to a credential manager and the element was drawn only
  where no other realm was defined. Now `signalBlock()` draws it for
  anybody holding a minted handle, and for nobody else: a person whose
  keys all predate #474 shares the old name handle across realms still.
  Every ceremony on this page creates the credential under the handle
  (`data-userid`, from the pending enrolment). The element is never drawn while a
  ceremony is armed, so the page loads one script tag. Every response of
  both handlers and of `remove-key` and `rename-key` goes through
  `sendKeysPage()`, so the script is allowed wherever the element is drawn.
* **Two lanes (#643, `webauthn.pqcAlongsideClassical`)**: while the realm
  offers both, the enrolment form carries a classical / post-quantum radio
  (`KeysPages.laneChoice()`, shared with the activation's setup form) and
  `POST /account-api/keys` `begin` takes `lane`, carried on the pending
  enrolment; the armed ceremony is that lane's handle, name
  (`<username>+ml-dsa` for the post-quantum lane), algorithms and exclude
  list. Each row's Details say its lane. **The Signal API is sent once per
  lane** — the view's `signals`, drawn as `#wa-signal` and `#wa-signal-pqc`,
  each with that lane's handle, name and ids only: one signal under the
  classical handle naming every key would tell the credential manager the
  post-quantum passkeys are unknown in that account. The post-quantum name
  says its algorithm (`<username>+ml-dsa-65`) once every post-quantum key
  uses one. `authn/CLAUDE.md` (*Two lanes*) argues the rest.
* **A post-quantum passkey required (#718)**: each row carries
  `postQuantumRefused`, from `passkeyPolicy.postQuantumRefusal()` asked of
  the key's algorithm under the person's selected profile — the same
  question the sign-in asks, so the page and the refusal cannot disagree —
  and the page draws `#passkey-post-quantum-refused` with
  `portal.keys.postQuantumRefused` (seven languages; a warning, not a
  refusal, so it is translated as `syncedRefused` is). Under
  `registration-and-sign-in` the armed ceremony offers only ML-DSA and,
  with both lanes on, `lanes` is `["pqc"]`, so the page asks nothing and
  `begin`'s `classical` default becomes the post-quantum lane
  (`webauthnPolicy.enrolmentLane()`). `authn/CLAUDE.md` (*A post-quantum
  passkey required*) argues the rest.

`tests/passkey_management.js` holds the credential layer, and
`tests/vendored/sts_portal_backup_keys.js` holds the page over HTTP: the two
buttons, the groups, rename and Last used.

### It is held to the same two address rules as the sign-in screen (2026-09-12)

`authn.rpIdProblem()` refuses a ceremony whose configured `webauthn.rpId` does
not fit the host in product mode, and `authn.expectedOriginFor()` decides the
origin from `webauthn.allowedOrigins` where it is set. The `finish` action asks
both rather than `authn.originOf(base)`, so a key enrolled here and a key used
at `/authn/webauthn` are held to one answer. `authn/CLAUDE.md` argues them.

### `/portal/activate` runs the same ceremony (2026-10-01)

**Until this day the activation page's `key_role` radio enrolled nothing.**
Choosing *a security key instead of a password* spent the link, said "your
account is ready" and sent the person to the sign-in screen to enrol on first
use — which product mode refuses (`STS-AUTHN-0206`), so the only way through
was to go back and set a password. Reported by rcbj as exactly that.

The key is registered on the activation page now, between the password and the
authenticator app, as a `key` step: `beginKeyEnrolment()` with the role and the
`kind` the first page chose (`kindChoice()` is drawn there too), the ceremony
drawn by `activationKeyForm()`, `confirmKeyEnrolment()` on the POST. **What
authorises it is the activation link**, re-checked and claimed on that POST like
every other; the link is spent only when the activation FINISHES, so a key that
will not register leaves a usable link. Every failure draws a fresh ceremony
(`STS-PORTAL-0102`). A key that cannot be started is REFUSED where it was the
only way in (`STS-PORTAL-0101`) and skipped with a warning beside a password
(`STS-PORTAL-0100`), the authenticator app's rule. **It is a scripted page while
the step is drawn**, for this page's argument, through `sendKeysPage()`, with
the same resource and a real button under it — its own row in the root table.

## THE ACTIVATION FLOW LEARNED IT TOO, AND THE LINK IS STILL SPENT LAST

An authenticator is a CHECKBOX on `/portal/activate` and not a fourth radio
button, and that is the whole of what it says about itself: the radio group is
*what signs you in* and exactly one of its values can be true. A one-time code
is not one of those answers — it is a second factor beside whichever of them was
chosen — so it is an independent box, and the *at least one way in* rule
underneath is untouched.

Ticking it costs a second POST, because a secret has to be shown and a code
typed back. **The link is not spent in between**, which is this directory's
existing rule reaching a case it did not have: somebody who ticks the box, sets
a password and then cannot find their phone still holds a usable link, and
opening it again with the box unticked completes the account. The over-HTTP job
asserts that by RE-OPENING the link rather than by reading a flag, because what
somebody in that state actually does is open the link a second time.

**`finishActivation()` is one function because there are several ways in now** —
a plain setup, a security key registered on a second POST, an authenticator
confirmed on a later one, and either that could not be started — and each has to spend the link, write the audit row
and draw the same page. Three copies of that is two chances for one of them to
leave a spent-looking link that still works.

**A refusal does not lose the activation.** If the enrolment cannot be started
at all — the mechanism is off, or product mode will not enrol for somebody with
no entry — the setup FINISHES with what was configured and says what did not
happen. Refusing the whole activation over an optional second factor would
strand somebody who has just set a perfectly good password.

## It is a separate application from the admin console

Not the shell, not the navigation, not the gate — and that is deliberate. The
console's `respond()` draws a sidebar of forty administrative pages and its gate
asks "does this person hold Admin Read", neither of which is anything somebody
managing their own account should meet.

**What they share is `authn.js`'s session STORE**, because there is one answer
in this service to "who is this browser" and a second would be the thing that
eventually disagrees.

**SINCE 2026-09-06 THEY DO NOT SHARE A SESSION, WHICH IS A SHARPER VERSION OF
THE SAME SENTENCE RATHER THAN A REVERSAL.** Both surfaces are relying parties
now, each with its own session and its own cookie, and both rows live in that
one store — told apart by `rpSurface`, the way an API session is told apart by
`credentialKey`. So signing in to the portal does not sign anybody in to the
console, which is what makes them two applications rather than one wearing two
paths; and there is still exactly one register of who is signed in, which is
what rule 3m asks for.

## THE RULE THAT MATTERS MORE THAN THE REST PUT TOGETHER

**No route here takes a username, an id or a DN from a query string or a body.**
Every page reads `sessionOf(req).user.username` and nothing else, so there is no
parameter for anybody to change.

That is OWASP A01 — broken access control, the top of the list — and the shape
it takes is nearly always the same: a handler that reads an identity from the
REQUEST instead of from the SESSION. The portal is exactly the kind of page that
grows one, because every route on it is about a person and the person's name is
right there in the URL of the page that linked to it.

`/portal/activate` is the single exception and it is not one: it takes a username
BECAUSE nobody is signed in, and what authorises it is the token, which is a
credential.

**`/portal/signals/receive` IS UNAUTHENTICATED TOO SINCE 2026-09-10 AND IS NOT
AN EXCEPTION EITHER, FOR A DIFFERENT REASON: IT TAKES NO IDENTITY AT ALL.** It
is this portal's Shared Signals receive endpoint, and what arrives is a signed
Security Event Token addressed to this portal, carrying the bearer token on
this portal's own stream — minted per start and given to nothing but this
service's own transmitter. Nothing in that request names a person whose page
anybody is about to be shown, so the rule above has nothing to bite on.
**It is also deliberately NOT rate limited**, which every credential endpoint
here is: a push is a machine delivering an event that has already happened, and
a limiter would silently drop somebody's account-disabled notice under load.

**`/portal/remove-key` is the case worth understanding**, because it takes an id
from the body and is still safe: `credentials.removeKey()` looks that id up
among **the caller's own keys**, so one belonging to somebody else matches
nothing. `tests/portal_access.js` asserts exactly that, in both directions — one
person cannot remove another's key, and can remove their own, so the refusal is
about whose key it is rather than the operation being broken for everybody.

**AND `/portal/signals` IS THE HARDEST CASE THIS RULE HAS MET (2026-09-10),
BECAUSE THE STORE BEHIND IT IS ABOUT EVERYBODY.** Every other page here reads
the signed-in person's own entry, which makes the rule easy to keep by
accident. This one reads a Shared Signals inbox: ONE stream delivers every CAEP
and RISC event in the realm to this portal, because a receiver is told about
the people it serves and there is exactly one of it. So the narrowing happens
on the way OUT — `listFor(..., { person })` — and the person is still composed
from the session and from nothing else, which is the rule holding rather than
bending.

**THE FILTER FAILS CLOSED, AND THAT IS THE PART TO KEEP.** An identifier
`isAbout()` cannot resolve to an account — a phone number, an opaque id this
service did not compose — is NOT a match. Showing one person another person's
account lockout is a disclosure; failing to show somebody one of their own is
an incomplete page. Those are not the same size of mistake, so the doubtful
case resolves to no, and the foot of the page says so out loud rather than
quietly hiding things. `tests/ssf_receivers.js` asserts the NEGATIVE in every
subject shape this service can compose — including RISC section 3.1's
`subject_type` spelling, which a filter reading only `format` would silently
hide every RISC signal behind.

**AND THERE IS NO CONTROL ON IT**, which is the same rule read from the other
end: a person may not clear the record of what was said about their own
account, so the Clear button is the console's and this page has none.

## The activation link is a credential and is treated as one

A user object arrives from `/admin-api` or SCIM with no way to authenticate.
Something has to let the person set one up, and that something **can complete an
account setup on its own** — no password needed, no second factor, nothing else
to guess. A leaked activation URL is an account takeover.

So: 32 bytes of `randomBytes`; **hashed at rest** with the same scrypt a password
uses (this directory has pages that print every attribute of every entry);
single use; time limited by `security.activationTtlMinutes`; rate limited at both
the GET and the POST; **shown once**, like the bootstrap password and a client
secret.

**IT IS SPENT WHEN THE SETUP FINISHES, NOT WHEN THE LINK IS OPENED.** A link
consumed on a GET would be burned by a browser prefetching it, by a corporate
mail scanner following it, or by the person reloading the page — and each of
those strands somebody with an account they cannot set up.

**IT DOES NOT SIGN ANYBODY IN.** Spending it lets somebody CREATE a credential
and nothing else; the last step of setup is to go and use it at the ordinary
sign-in screen. That is the difference between a setup link and a magic link,
and it is deliberate: a link that both proved identity and granted a session
would be a standing bypass of every mechanism the person is in the middle of
configuring.

**EVERY WAY IT CAN FAIL ANSWERS THE SAME SENTENCE.** Wrong token, expired token,
never issued and no such person are four different facts, and telling them apart
would let anybody with the page discover which usernames have an activation
outstanding.

## The combination that is refused, and why it is refused twice

A security key marked `mfa` is a SECOND factor — it is not a way to sign in by
itself. Choosing it with no password would finish setup with an account **nobody
can use, including its owner**.

That is refused in two places on purpose: at `/portal/activate`, where the
combination would be created, and in `credentials.removeKey()`, where it would
be arrived at later by removing the password. Same rule, both ends.

## THE PORTAL IS AN OAUTH CLIENT OF THIS SERVICE — A PUBLIC ONE SINCE #568

It was a CONFIDENTIAL OpenID Connect relying party from 2026-09-06 to #568:
`sts-user-portal`, `private_key_jwt`, a back-channel code redemption by this
process and a session of its own in `sts_portal`. **It is a PUBLIC client
now**, signing in in the browser (`web_portal_runtime.ts`): the authorization
code flow with PKCE at the authorization server of the realm the portal was
opened in, `resource` that realm's `/account-api` (and its `/admin-api`,
for an owner's pages, since #607), back at
`/portal/callback` — a page the runtime draws, whose callback address the
shell registers on the client entry as the console's does
(`oidcRp.ensureSurfaceCallback()`: learnt in development, refused in product
unless registered). Every token is DPoP-bound (`sender_constraints.js`'s
DPOP_BOUND_PUBLIC_CLIENTS) and the client is exempt from FAPI's
confidential-client rule (`fapi.js`), the console's two arrangements.
Under a FAPI profile it also sends an OpenID `nonce` derived from its PKCE
verifier and refuses an ID Token without it, and under
`oauth2.fapiRequireMtls` it is let through DPoP-bound rather than refused for
having no client certificate (2026-10-12) — `oauth-oidc/CLAUDE.md`, 3cb,
*under a FAPI profile they sign in at all*.

What still holds from the relying-party years:

* **SINGLE SIGN-ON HAPPENS THROUGH THE PROTOCOL, NOT A SHARED COOKIE.** A person
  who signed in anywhere in this realm is answered by `/oauth2/authorize` with
  a code and types nothing — which is also how a console administrator reaches
  their portal now that the adoption is gone.
* **A PERSON WHO SIGNED IN ELSEWHERE IS NOT SILENTLY IN THEIR ACCOUNT PAGE**:
  the portal still has to run a flow, and its token is its own.
* **THE TOKEN DIES WITH THE SIGN-ON SESSION IT WAS ISSUED ON**
  (`STS-ACCOUNT-0008`), which is what the relying-party session's cascade did.

## THE CONSOLE-SESSION ADOPTION (2026-09-30) WAS DROPPED ON #568

It made a portal session from a live console session, because the console's
session outlived its sign-on session by renewing its own tokens and the
portal's code flow then met no sign-on session. Neither side holds a server
session any more: both are public clients whose tokens die with the sign-on
session they came from, so a console administrator following the account
menu's link meets a live sign-on session at `/oauth2/authorize` and is signed
in with no screen. rcbj's decision 4 on #568. `tests/portal_adopts_console.js`
went with it.

## Two sign-outs, and they are two different acts (2026-09-06)

**THE BUTTON IN THE CORNER OF EVERY PAGE** is a form posting to
`/portal/signout`, which the runtime answers (`PortalRuntime.signOut()`): it
forgets the tokens and sends the browser to `/logout`, which ends the sign-on
session — and with it every token issued on it, the portal's included, and
the console's. It has to reach the sign-on session for the reason it always
had: ending only the portal's own state would let the next visit sign straight
back in with nothing typed.

**THE BUTTON AT THE FOOT OF THE OVERVIEW IS STILL `POST /logout`**, the wider
act: every session and credential this identity holds in every protocol. Both
are drawn, each says which it is. That form is not the portal's, so the
runtime leaves it to the browser.

## Several accounts in one browser: one per tab, and the account menu (#561, 2026-10-19)

**The console's arrangement, and its reasoning is in `admin-ui/CLAUDE.md`
8c-iv**; what is the portal's own is here. With `authn.multipleAccounts` off
none of it is stored, sent or drawn: the header, the sign-in's record, the
authorization request and the sign-out's address are the bytes they were.

* **THE TAB'S ACCOUNT** is `{ sub, username }` in sessionStorage
  (`sts-portal-account`), written when `/account-api/me` is read and removed
  when the list says off, and sent as `login_hint` on every sign-in the
  runtime starts — a step-up's among them, so a step-up is of this tab's
  account. `authorizeUrl()` copies a sign-in's extra parameters into the
  request as before, except the runtime's own (`expect`, `another`,
  `login_hint`: `OWN_EXTRAS`), which never leave the tab.
* **THE ACCOUNT MENU** (`PortalShell.accountMenu()`) is a `<details>` AFTER
  Sign out — `tests/portal_refresh.js` 6 holds Refresh and Sign out side by
  side — with a button per other signed-in account and *Sign in with
  another account*. Sign out goes to `/logout?login_hint=<username>`.
  **Since #751 its summary reads *Switch user*** and its panel is drawn with
  no other account signed in too (saying so, `portal.accounts.none`), ending
  on the line that the account the tab leaves stays signed in
  (`portal.accounts.kept`) — the console's group, for the console's reasons
  (`admin-ui/CLAUDE.md` 8c-iv). Off, still not drawn.
  `tests/vendored/sts_multi_account_tabs.js` 2a switches a real tab to bob
  and back to alice from it, nothing typed.
* **A SWITCH** asks over a form typed in, aborts what is in flight —
  `sendOnce()`, `ownerJson()` (the owner token's requests, #607) and the
  token requests — and discards `me`, the page for nobody's locale
  (`nobody`), the form table, the view, the flash, the owner token and
  its scopes, and the client's tokens and key; an answer for another
  subject than the one switched to is refused. **A switch whose sign-in
  cannot be started** (a pushed request the network refused) draws
  *Switching accounts failed* and keeps the tab's account, as the
  console's does (#731, `admin-ui/CLAUDE.md` 8c-iv,
  `tests/multi_account_concurrency_tabs.js` 2).
* **`/portal?accounts=another` IS HOW EVERY OTHER PAGE SIGNS IN AS ANOTHER
  ACCOUNT** (delivery step 6, `common/CLAUDE.md` 3cl). `/authn/login` is
  not a destination — it needs a pending sign-in — so the public pages'
  control links here, and `route()` turns the marker into the portal's own
  authorization request with `prompt=login` and no hint, after reading the
  list: with the setting off the marker is dropped from the address and
  the page is today's. The address is the portal's ADVERTISED one, which
  `GET /authn-api/accounts` answers as `anotherAccount`, because a page on
  another listener (#472) cannot work it out.
* **THE DEVICE PAGE SAYS WHICH ACCOUNT APPROVES** (`/portal/device`,
  `web_device.ts`'s `approvingAs()`). An approval is this tab's account's —
  the access token's subject, on the sign-on session it was issued on — and
  nothing else in the request is per account, so nothing acted as the wrong
  account; but RFC 8628 section 5.4's defence is showing the person what
  they authorize, and with two accounts signed in "you" is no longer
  obvious. So, with more than one live account in the browser's list, the
  request names the account it will be approved as (`device-as`,
  `portalDevice.request.as`); otherwise the page is the one it was. A
  `verification_uri_complete` opened in a new tab has no account of its own
  and signs in as any tab does: the picker where nothing chooses.
* **THE LIST IS FETCHED ONLY WHERE THE SHELL SAYS SO** (`data-sts-accounts`,
  `common/CLAUDE.md` 3cl `web_accounts.ts`).

## A Refresh button beside Sign out (2026-10-09, #538)

Every signed-in page draws **Refresh** to the left of Sign out
(`PortalShell.refreshForm()`): a GET form to the page's own path carrying only
the parameters a page reads to draw itself — `page`, `per`, `<list>Page`,
`stepup`, `gnapstepup`, `enrolled`, `named` (`PortalShell.REFRESH_KEPT`). The
runtime answers it by asking the page's operation again. **Nothing else is
carried**, for #538's reason: a parameter a link put on the URL
(`?user=<somebody>`) must never be drawn back into a signed-in page. A message
a write left is held in the runtime and drawn once, never on the URL, so there
is no `done` to carry or to drop.

## `beginAuthentication()` and not a bare redirect

**THAT RULE IS NOW ONE LAYER DOWN AND STILL DECIDES THE SHAPE.** `oidc_rp.js`
sends the browser to `/oauth2/authorize`, and it is the AUTHORIZATION ENDPOINT
that calls `beginAuthentication()` — so the reason below is why the flow works
at all rather than why this file redirects where it does.

`requireSignIn()` used to send an unauthenticated visitor through
`authn.beginAuthentication()`, exactly as `saml2_sso.ts` and `consent_screen.js`
do. This was a plain `303` to `/authn/login` at first **and it does not work**:
that endpoint draws a form for a PENDING AUTHENTICATION RECORD, and a POST
naming no record is answered `This sign-in form has expired`. The portal is not a
protocol, but it needs a session the same way one does.

`returnTo` is a path on this service, which that function requires and refuses
anything else — so the portal cannot be turned into an open redirect.

### AND THE ACCOUNT-READY PAGE BROKE THAT RULE ON THE SAME DAY IT WAS WRITTEN

Reported by rcbj: follow an activation link, set a password, press **Sign in**,
and get

> `invalid_request` — There is no sign-in waiting under that id, or it has
> expired. Start the request again from the application that sent you here.

The section above is the whole explanation, and the file it is written in is the
file that got it wrong: `POST /portal/activate` ended by linking to
`authn.LOGIN_PATH`. **Nothing was broken except one `href`** — the password was
set, the link was spent, the audit row was written — which is why it survived
being written directly under an argument saying it could not work, and why the
guard for it had to be an over-HTTP job (`tests/vendored/sts_portal_sessions.js`)
rather than anything in process.

**It links to `/portal` now, and the destination is the argument.** That page
has no session either, so `requireSignIn()` mints the pending record and the
browser arrives at the same screen with something behind it. Two properties:

* **The record is minted when the link is PRESSED.** Calling
  `beginAuthentication()` while rendering the account-ready page would work and
  would then expire — somebody who reads a page before clicking would meet the
  very error this replaces.
* **They land on their own account page**, which is the only destination this
  service can name: an activation link belongs to no application and there is no
  flow in progress to resume.

**BOTH BRANCHES NOW GO TO THE SAME ADDRESS**, and what differs is prose. The
`key_role !== 'none'` branch already went to `/portal` — for the enrolment
reason — so the bug was only ever in the *no key* branch, which is the ordinary
one. That asymmetry is worth noticing: the rarer path was right and the common
path was wrong, so the flow most people take was the one that failed.

**AND THE SAME MISTAKE WAS IN TWO OTHER FILES**, found by looking for it rather
than by being told: the federation index's *The sign-in screen* link
(`federation/federation_sp.ts`) and the admin console's 401 for a form posted
with an expired session (`admin-ui/admin.ts`, whose link was ALSO swallowed into
a `<details>` summary and so was not clickable at all). The rule read off all
three: **`/authn/login` is never a destination — link to a page that STARTS a
sign-in, and let it mint the record.**

## The OWASP controls, and where each lives

| | Control | Where |
|---|---|---|
| A01 | identity from the token, never the request | `account-api/account_api.ts`, this directory, and the test files at three layers — see below |
| A02 | scrypt for passwords, activation token hashed | `common/credentials.ts`, `common/crypto.js` |
| A03 | every value through `esc()`; no SQL built from input anywhere | this directory |
| A04 | rate limiting on activation, sign-in and password change | `common/websecurity.ts` |
| A05 | the CSP `app.js` sets on every response | `common/app.js` |
| A07 | a DPoP-bound token on every request (CSRF tokens until #568), the previous session ended on sign-in, no message distinguishing "no such person" from "wrong credential" | `account-api/account_api.ts`, `authn/authn.ts` |
| A09 | every act audited | `common/audit.js` |

**Changing a password requires the current one even though the person is signed
in.** A browser left open on a shared machine must not be an account takeover
with no credential needed. In development mode `verify()` accepts anything, so
it is a formality there — which is correct: development checks no password
anywhere, and a portal that was the one exception would be a surprise rather
than a control.


## A01 IS ASSERTED AT THREE LAYERS AND NEEDS ALL THREE (2026-09-06)

The rule this directory is built on — *no route takes a username, an id or a DN
from a query string or a body* — is checked by three files, and none of them
implies another. Naming only one of them, which the table above did until this
date, invites somebody to think the claim is covered when the layer they are
about to change is not.

| File | Layer | What it could not see |
|---|---|---|
| `tests/portal_access.js` | the CREDENTIAL layer: `credentials.removeKey()` looks an id up among the caller's OWN keys | a route that never reaches that function |
| `tests/access_policy.js` | the POLICY layer: the XACML `access-control` document denies a subject who is not the owner | a handler that hands the PDP the wrong subject |
| `tests/vendored/sts_portal_sessions.js` | the ROUTE, over HTTP, with two real signed-in browsers | nothing above it — this is the one that sends a request |

**THE THIRD ONE EXISTS BECAUSE THE FIRST TWO NEVER SEND A REQUEST**, and that is
not a theoretical gap. It was mutation-tested by making `/portal/password` read
`username` from the body — the exact bug this directory's rule exists to prevent
— and the response still rendered the CALLER'S OWN account while the write went
to the person they had named. Every page-level assertion passed. What caught it
was reading `GET /admin-api/audit` back and checking the ACTOR on the
`portal.password.changed` row.

**So the rule for a new portal route is: a rendered page proves the page, and
only the audit row proves the write.** If a handler changes something, assert
who it was attributed to and not merely what came back.

**`/portal/mfa` HAS ONE OF ITS OWN TOO** (`tests/vendored/sts_portal_totp.js`,
section 3), and on this page the rule protects something sharper than a leak:
enrolling for somebody else would leave the attacker HOLDING that account's
second factor. The decisive assertion is not that the page came back with the
caller's own name on it — it is that the OWNER'S STORED ENROLMENT INSTANT DID
NOT CHANGE, read back through `/admin-api/mfa`. A handler that read a username
from the body renders the caller's own page perfectly and writes to somebody
else, which is the defect that shape of assertion exists to catch.

**AND A NEW PAGE IS A NEW PLACE THE RULE HAS TO BE CHECKED**, which is why
`/portal/applications` got an A01 assertion of its own rather than inheriting
section 3's. That section drives `/portal`; a page added later is a page whose
handler nobody has yet looked at. The check is the same shape — the other
person's name in every parameter this page could plausibly have read, and the
page must be drawn for the session's own person and must not name theirs.

---

## `/portal/signals`: THIS PORTAL IS A SHARED SIGNALS RECEIVER (2026-09-10)

A person's own security activity: what this identity provider has SAID about
their sessions and their account, to this portal, over OpenID CAEP and RISC.
`ssf/ssf_receivers.ts` holds the design, `ssf/CLAUDE.md` argues it, and the A01
half is above. Three things belong here.

**IT IS UNDER *Your account* AND NOT UNDER *How I sign in*.** That section
holds the CREDENTIALS on this person's entry, one page each, and every page in
it is a control — a password form, a key list, an authenticator enrolment. This
is not a control and not about a credential: it is a RECORD, and a reader
arrives at it asking what happened rather than asking to change something.

**IT IS A RECORD AND SAYS SO, INCLUDING THAT THE ACCOUNT'S OWNER CANNOT EMPTY
IT.** A list of what was said about an account would be worth nothing if the
person it is about could clear it, so there is no Clear here — the console has
one, for its own inbox. The page says that in as many words rather than simply
lacking the button, because a missing control reads as an oversight.

**IT NEEDED NO SCRIPT AND HAD NONE, SO THE CLAIM THIS FILE THEN MADE ABOUT
`script-src 'none'` WAS UNCHANGED BY IT.** `/portal/keys` was still the only
exception in this directory (until #568, 2026-10-12, made every portal page
the static shell under `script-src 'self'`). A list of events with a `<details>` per payload is
markup; the argument that page was granted its exception on — a WebAuthn
ceremony is a browser API call and there is no server-side substitute — does
not apply here and was not reached for.

**WHAT IT DELIBERATELY DOES NOT DO IS EXPLAIN THE PROTOCOL.** The wording is a
person's rather than an operator's: where `status().why` would tell an
administrator that `ssf.pushDelivery` is off, this page says the portal is not
currently being told about everything and points at the console — because
somebody reading their own account page cannot change any of those settings and
naming them would be an error message addressed to the wrong reader.

## THE RECOVERY CODES ON `/portal/mfa`, AND THE ONE PLACE IN THIS SERVICE A SET IS EVER SHOWN (2026-09-10)

A card on the authenticator page rather than a page of its own. The console's
filing rule reads the same way here — where a page goes is decided by the
QUESTION it answers — and this answers *how do I get in when my second factor is
not to hand*, which is a sentence about the second factor.

### There is no button that issues a set, and that is the shape of the feature

**THIS SECTION REVERSED ON 2026-09-11.** It read: *a set is created by
`common/credentials.ts` at the moment a second factor is enrolled, once, and
there is no door here or anywhere else that creates one on request — a recovery
mechanism a person has to remember to ask for produces exactly the population it
exists to protect, one person at a time.* That argument is still true and the
cost of dropping it is paid rather than denied; `common/CLAUDE.md` carries it.

A set is GENERATED HERE, by the person, when they ask to see one. Three states
and the middle one is the whole design:

1. **no set** — a prompt, loud where they already hold a second factor, because
   that is the population the automatic issue used to protect and asking is all
   that is left of it;
2. **shown and not yet confirmed** — the codes, and one button. **Nothing is
   stored**, and the page says so in those words: what is on the screen is not
   a credential and works nowhere until *I have saved these codes* is pressed.
   Somebody who writes them down and closes the tab has changed nothing;
3. **confirmed** — counts, and a Replace control that says what replacing costs
   before it is pressed.

### They are shown ONCE, on a POST, and nothing can show them again

**They are not recoverable any more** — hashed with scrypt, the same form
`userPassword` is stored in — so this page cannot show a stored set and neither
can anything else. The *Show my recovery codes* control is gone with the
read-back it named.

What is unchanged is that the one moment they ARE shown is a POST. A GET that
rendered them would put a live credential in a browser history entry, on the back button,
and on the screen of anybody who reloads a page somebody left open; `no-store`
bounds the caches and bounds none of that.

So the list appears exactly ONCE, on the response to the POST that generated
it. There is no second occasion, which is the whole difference hashing made.

## THE OVERVIEW SHOWS THE PERSON'S DIRECTORY ENTRY (2026-09-11)

The *You* section answers *what does this identity provider know about you*,
and until this it answered out of the SESSION: a username, a subject, and
whichever of `email` and `name` the sign-in happened to carry. It draws all
fifty standard inetOrgPerson attributes now, grouped by the three object
classes every person here is filed under, with the LDAP name and the RFC under
every value.

### It draws a FIXED LIST and never the entry, which is the whole design

`common/inetorgperson.ts` is the list and this page is a reader of it.
Iterating the stored attributes instead would have been shorter and is the one
thing this section must not do: **an entry in this directory carries whatever
anybody put on it**, and this service writes four `sts`-prefixed CREDENTIALS
onto that same object. A page that printed the entry would print a TOTP shared
secret the day somebody enrolled an authenticator. That file's header carries
the argument; `tests/vendored/sts_portal_directory_attributes.js` is where it
is held, and every other assertion in that job passes against the wrong
implementation.

### The identity is the session's, and this is the newest place that could have gone wrong

`entryFor()` takes the SESSION rather than a name — there is no call shape in
which a caller supplies a string — because it is the one function in this
application that reads a directory entry, and a `username` reaching it from a
request would be every attribute of anybody's account, to anybody signed in.
The A01 rule at the top of this file has a new reader and the job drives the
attempt.

### The directory arrives through a SLOT, and it is the first this application has offered

`portal.setDirectory()`, filled by `ldap/ldap_server.js` at its require time.
Rule 3e's test answers yes both ways round: this module is at 8a and that one
at 21, so a require from here would register every `/ldap` route and the eight
`/admin/ldap/*` console pages ahead of the authorization server and the
console, and a require the other way would move every `/portal` route behind
the management API.

It carries ONE function and is validated whole. **A process without it is a
smaller portal rather than a broken one**: the section falls back to the two
facts the session carries and says on the page that it is doing so — and those
two are drawn THERE rather than in the table above, which is the half of the
fallback that is easy to get wrong. `email` and `name` used to be rows in that
table; they moved into this block as `mail` and `cn`, so a process with no
directory would otherwise have shown LESS than it did before the feature that
was meant to show more.

### The empty ones are drawn too, behind a `<details>`

Fifty attributes where a typical person holds six would be a wall of nothing,
and showing only what is set would answer *what does this provider know about
me* without ever saying what it COULD know — which on a service that exists to
be explored is the more useful half. So the set ones are drawn plainly and the
rest are one fold per class.

**`<details>` is MARKUP and not script**, which is why it is available at all:
every page of this portal but `/portal/keys` was `script-src 'none'` until #568
(2026-10-12), and the console made exactly this argument for its own collapsible prose. There is no collapse-all and there
will not be one.

### Nothing here can be edited

These attributes are written by an operator, by SCIM, or over LDAP. This portal
changes how somebody AUTHENTICATES and not what the directory records about
them, and the page says so rather than leaving a reader to wonder where the
form is. **Most of them cannot be written through `/admin/users/new` either** —
that form checks against `oid4vc/vc_claims.ts`'s catalogue, which is
twenty-seven claim-bearing attributes rather than this schema's fifty — so
`departmentNumber` and `roomNumber` reach an entry over SCIM or LDAP or not at
all.

## `/portal/signing-key`: THE SECOND PAGE HERE THAT HANDS SOMEBODY A CREDENTIAL (2026-09-12)

A person issues themselves an **RFC 7523 signing key pair** — the same act
`/admin/pki` performs for an operator, through the same two functions
(`pki.issueSigningKeyPair()` and `personAssertions.write()`), writing the same
`stsAssertion*` attributes onto the same entry. What is new is who presses the
button.

**AND SINCE 2026-09-13 AN RFC 7522 ONE BESIDE IT.** The page draws a card per
profile from `SIGNING_KEY_PROFILES`, each with its own Generate and its own
Take off posting a hidden `purpose` (`jwt` or `saml`; absent means `jwt`, which
is what the form posted before, and anything else is refused at the form's
shape). The SAML key pair lands on `stsSamlAssertion*` — the set
`/admin/users?user=` manages — and the two never cross: neither key signs for
the other profile, and taking one off leaves the other working. The one-time
card says what to do with the key it holds — claims and a `kid` for a JWT, an
`<Issuer>`, `<Subject>`, audience and certificate thumbprint for a SAML
assertion. **Three things are shared rather than doubled**: the rate limit
(a key generation costs the same CPU either way), `pki.personSelfService`, and
the error codes, none of which named a profile. The nav label is *Signing
keys*. `tests/vendored/sts_portal_signing_key.js` section 8 is the proof, and
its SAN check exists because a JWT leaf written onto the SAML attributes
verifies exactly like a SAML one — the certificate's subjectAltName is the only
place the difference shows; five mutants, all caught, that one only after the
check was added.

**IT IS THE SAME ACT AND NOT A SECOND IMPLEMENTATION**, which is the whole
reason this page requires `common/pki.js` and `common/person_assertions.js`
rather than calling `/admin-api`. One write path onto a person's entry, whoever
asked: a second one here would be a second answer to *what is on that entry
after an issue*, and the two would agree right up until one of them grew an
attribute.

### What makes it allowable at all

This portal hands out a credential on `/portal/mfa` already, and the bar is the
same one: **it hands a signed-in person a credential for the account they are
signed in to.** The key's entire authority is *this is me* —
`assertion_grant.js` refuses an assertion signed with it that names anybody else
as `sub`, on the registered key and on a certificate presented in `x5c` alike,
and `common/CLAUDE.md`'s rule 3ab argues that refusal at length.

**Without that refusal this page could not exist.** A self-service button that
minted a key able to assert about ANYBODY would hand every person who can sign
in a token as every other person — which is why the rule is enforced in the
grant rather than on the page: a check the page performed would be a check the
`/admin-api` door did not.

### The private key is shown once, and `generate` therefore RENDERS

Every other write here answers 303 with a message on the query string. This one
cannot, for the reason `generate-codes` on `/portal/mfa` cannot: **a redirect
has nowhere to put a credential**, and a query string writes it into a browser
history entry, this service's own access log and every proxy log between here
and the person.

**AND THERE IS NO SECOND CHANCE AT IT.** The key is sealed on the entry and
nothing in this service opens it again — not this page, not `/admin/pki`, not
`/admin-api`. The page says so at the moment it shows it, and *generate again*
is the only answer to having lost it. That is the same position the recovery
codes reached from the other direction, and `tests/vendored/sts_portal_signing_key.js`
asserts it by fetching the page a second time and looking for a PEM block that
must not be there.

### What it deliberately does not ask

No lifetime field, no algorithm field and **no name field**. The first two are
the deployment's answers (`pki.leafLifetimeDays`, and the Issuing CA's own
algorithm) and a person choosing an RSA modulus on their account page is a
question nobody wants asked. The third is this directory's rule: a `username`
in that body would let anybody signed in write a key pair onto somebody else's
entry, which is a takeover rather than a leak. The job above posts somebody
else's name in three plausible parameters and then checks that person's entry
through `/admin-api`.

### Two things this page does that no other page here does

**IT IS RATE LIMITED ON A COST RATHER THAN ON A GUESS.** Every other limiter in
this service counts attempts at something secret — a password, a code, an
activation token. This one counts key generations, because an RSA key pair is
hundreds of milliseconds of CPU in a process that answers six socket families
on one thread. The limit is passed explicitly rather than taken from the shared
default, because what is being protected is the SERVICE and not the account.

**IT WAS THE LITERAL FIVE FOR BOTH BUCKETS UNTIL 2026-09-12**, which made the
ADDRESS bucket five key generations a window for everybody behind one NAT or
proxy. It is `pki.personSelfServicePerIdentity` and
`pki.personSelfServicePerAddress` now, both five by default, passed to
`websecurity.attempt()` as `{ identity, address }` — which that function learnt
to accept beside a bare number, a member left out falling back to the shared
setting for its bucket. `tests/scan_and_rate_limits.js` pins it.

**AND IT HAS AN OFF SWITCH, WHICH `/portal/password` AND `/portal/keys` DO
NOT.** `pki.personSelfService`, on by default, checked at the DOOR as well as
on the page — `authn.js`'s rule about the anonymous button, read again: the page
is markup and the handler is the door, so a form posted by hand while the
setting is off must issue nothing. **Turning it off takes nobody's key away**,
which is the TOTP row's contract (it was `totp.enabled`) word for word: a key
already on an entry goes
on verifying, and what stops is new ones *from the portal* — an operator issuing
from `/admin/pki` is unaffected, which is the point of having the switch.

### Where it is filed, and the argument that was refused

Under **How I sign in**, whose own description is *the credentials on your own
entry, one page each*. The argument for *Your account* — that this key never
signs anybody IN, since there is no browser session at the end of it — was
considered and refused: it is an argument about the section's TITLE rather than
about what the section holds, and moving the heading's meaning to fit one page
would misfile the other three.

## A TLS CLIENT CERTIFICATE, THE THIRD CARD ON `/portal/signing-key` (2026-09-13)

Asked for by rcbj beside the RFC 7523 and RFC 7522 key pairs: a person generates
a TLS client certificate that maps to their identity and installs it in their
browser. `common/tls_client_certificates.js` issues, packages and revokes;
`common/CLAUDE.md` 3ag argues the gate that makes trusting the
service Root safe, and `tls/CLAUDE.md` what a presented certificate is worth.
What is this page's:

* **THE DOWNLOAD IS THE RESPONSE TO THE POST.** `generate-tls-client` renders a
  one-time card with three `data:` links carrying `download` — the `.p12`, an
  encrypted `-key.pem`, the `-chain.pem` — which is the console keytab page's
  arrangement and was the only way a file left a page with `script-src 'none'`;
  the static portal (#568) kept it, the links drawn by the renderer.
  Nothing keeps the private key; the page says so, and the install steps
  (Windows, macOS, Firefox, Linux Chrome, curl) are folds on the same card.
* **THE FILE PASSWORD IS TYPED TWICE, CHECKED, USED ONCE AND NOT KEPT** — not
  audited, not logged. A mismatch is 400 `STS-PORTAL-0040` before any key is
  generated.
* **IT SHARES THE PAGE'S SAFEGUARDS RATHER THAN GROWING ITS OWN**:
  `pki.personSelfService`, the two self-service rate limits (an RSA key
  generation costs the same CPU whatever it certifies), the CSRF token. The one
  number of its own is the cap, `pki.personTlsClientCertificateMax`, counting
  valid certificates only.
* **A LIST WITH A REVOKE PER VALID ROW**, and the serial in that form is looked
  up among the signed-in person's own certificates, so another person naming it
  gets 400 `STS-PKI-0171` — `/portal/remove-key`'s arrangement. Revoking is real
  revocation (the CRL, OCSP, and every door that reads a certificate refusing
  it), with two reasons a person
  can honestly give: `cessationOfOperation` and `keyCompromise`.
* **A PACKAGING FAILURE REVOKES THE CERTIFICATE AT ONCE** (`STS-PORTAL-0042`): its
  key is gone, and a valid certificate nobody can present or knows to revoke is
  worse than a line on a list.
* **WHERE IT WORKS IS ONE ADDRESS SINCE 2026-09-16**, and the card says so:
  `GET /tls/sign-in` on the host the page was reached at. It named two — the
  8443 and 9443 listeners, built from `tls.port` and `tls.mutualPort`, because
  this module is required long before `tls/tls_server.js` and could not ask for
  the bound ports without moving routes — and both listeners and both settings
  were deleted. `tlsListenerUrls()` now builds the address from the page's
  `base` (`helpers.baseUrlOf(req)`), so it needs no setting and no require and
  honours `global.publicBaseUrl` and the realm prefix. **The same commit
  deleted the signing-key half of this page with it** — `SIGNING_KEY_PROFILES`,
  `signingKeyProfile()`, `heldProfile()`, `freshInstructions()`,
  `profileCard()` — and took a `req` its callers never passed, so every
  `GET /portal/signing-key` answered 500 and the card said `localhost`; both
  were restored on 2026-09-16, and `sts_portal_signing_key` is what caught it.
  **The card also stopped promising a port that REQUIRES a certificate**: the
  main port asks every connection for one and requires none, so it is the
  browser that decides to send it.

**NO `/admin-api` MIRROR**, for this page's standing reason: the answer is
per-person. An operator revokes one on `/admin/pki`'s revocation pane, where it
is listed like every other leaf of the `tls-client` authority.
`tests/vendored/sts_portal_signing_key.js` section 9 is the over-HTTP half; the
handshake was `tests/tls_client_certificates.js` in process, because no launcher
published 9443 to a job — **a certificate now arrives on the port every job
already uses**, which is the deletion's one gift to this page.

## THE SIGN-IN CAN BE REFUSED FOR A SECOND REASON, AND THE 503 SAYS WHICH (2026-09-12)

`oidcRp.beginSignIn()` used to fail for one reason — `sts-user-portal` gone or
without a secret — and the page said *which is what has happened*. In product
mode it can also refuse because this portal is being reached at an address that
entry does not carry as a redirect URI, which `common/oidc_rp.ts` now refuses
rather than writing the address onto the entry (an invented `Host` header would
otherwise plant a callback on this service's own client). The reason is in
`started.why` either way; `started.reason` says which kind it is, and the note
under it names the kind of fix — an administrator registering the address, or
restoring the entry.

**A PASSWORD SET HERE IS HELD TO THE REALM'S PASSWORD POLICY IN PRODUCT
MODE** — its length, symbol, uppercase and digit rules and its history — on
`/portal/password` and on `/portal/activate` alike, because both go through
`credentials.setPassword()`, which is the one place the rule is asked. It was
`security.passwordMinLength` for a few hours on 2026-09-12; `common/CLAUDE.md`
3ac argues the profile. Both pages already drew `set.errors[0]`; what they
gained is `passwordRulesNote()`, which prints the rules ABOVE the button from
`credentials.passwordRules()` — the function the refusal is built beside — so
the sentence read before typing and the rule applied afterwards cannot differ.
In development mode the note says nothing is checked rather than listing rules
nobody applies. **An activation link still sets up somebody provisioned with no
credential**: `/admin-api/users/create` generates a password by default since the
same day, so a caller that means to send a link creates with
`credential: "activation"` or `"none"`.

## `/portal/certificates`: A PERSON'S OWN ENROLLMENT CREDENTIALS AND CERTIFICATES (2026-09-13)

ACME and SCEP authenticate with a credential bound to ONE directory entry — an
External Account Binding key and a single-use challenge password
(`common/cert_enrollment.ts`, rule 3ag). An administrator makes one for anybody
on `/admin/acme` and `/admin/scep`; this page is where a person makes one for
THEMSELVES, lists the certificates ACME, EST and SCEP issued them, and revokes
one. EST needs nothing made first — the person's username and password are its
credential — so its card only lists the labelled addresses.

* **THE IDENTITY IS THE SESSION'S.** Every credential is created for
  `{ kind: 'person', id: session.user.username }`; the form has no name field.
  A delete is checked against THIS person's credentials before anything is
  deleted, and a revocation passes `{ entry }` to the core — so a kid, a
  challenge id or a serial belonging to somebody else is answered exactly as one
  that does not exist (`STS-PORTAL-0048`, `-0049`), and the page is not an
  oracle for what other people hold.
* **A SECRET RENDERS AND NEVER REDIRECTS**, `/portal/signing-key`'s rule: the
  HMAC key and the challenge password are on the 200 that made them, with
  `no-store`, once.
* **IT SHARES THE SELF-SERVICE LIMITS** (`pki.personSelfServicePerIdentity` and
  `…PerAddress`) under its own bucket name, `portal-enrollment`; a protocol
  turned off in the realm is refused at the door as well as hidden on the page
  (`STS-PORTAL-0050`).
* **IT IS A FILE BESIDE `portal.ts` REGISTERED THROUGH `register(context)`**:
  the shell, the sign-in, the CSRF field and the escaping are private to
  `portal.ts`, which hands them over at the foot of its own routes. That keeps
  the route order the column's and the new file to what is new.

**THE TLS CLIENT CERTIFICATES THIS PORTAL ISSUES DIRECTLY are
`/portal/signing-key`'s third card and are NOT listed here** — they come from
the `tls-client` authority, these from `acme`, `est` and `scep` — and this page
links to that one.

## `/portal/app-passwords`: THE PASSWORDS A PERSON GIVES THE CLIENTS THAT CANNOT DO A SECOND FACTOR (2026-09-22, #101)

`portal_app_passwords.ts`, registered after `/portal/certificates` through the
same `register(context)` and for its reason. In product the five password-only
doors refuse a second-factor person's own password (`authn/CLAUDE.md`), and
this is where they make what those clients send instead.

* **Behind a full sign-in**: the portal's own, so the session already met
  whatever the account asks for. `manage-own` for both POST actions, CSRF on
  both, the make rate limited (`portal-app-password`, the shared window).
* **The identity is the session's.** A revoke names an id; one that is not
  this person's is a 404 (`STS-PORTAL-0078`), never an oracle.
* **The password is shown on the 200 and never on a redirect**, `no-store`,
  `/portal/certificates`' rule; a revoke is a 303 with `done=`.
* **No script, a real submit button**, and **one checkbox per door with its own
  name** (`door_ldap`, ...): the portal's form parser keeps the last of a
  repeated name, so five boxes called `door` would scope a password to one.
* The page says which doors refuse this person's password
  (`credentials.passwordOnlyDoors()`), lists each app password with its last
  use, and each make and revoke is a CAEP `credential-change` with
  `initiating_entity` `user`. `/portal/mfa` links here while the doors refuse
  them. The console's twin is on the person's `/admin/users` page, and
  `/admin-api/users/{create,revoke}-app-password` and `GET
  /admin-api/users/app-passwords` are the API (rule 7).

## `/portal/kerberos`: A KEYTAB FROM THE PERSON'S OWN PASSWORD (2026-09-22, #59)

`portal_kerberos.ts`, registered after `/portal/app-passwords` through the same
`register(context)` and for its reason. It draws the person's Kerberos principal
in this realm and the public half of their keys, and makes them an MIT keytab.
`kerberos/CLAUDE.md` (*A PERSON'S KEYTAB*) argues the design; four things are
this page's:

* **The form asks for the CURRENT PASSWORD, and that is the design, not a
  formality.** The keytab is DERIVED from it — a stored key is never read back
  out — and asking is also the re-authentication a password-equivalent export
  needs. It is `credentials.verifyAsync()` with `secondFactor: 'session-held'`
  (`/portal/password`'s declaration: this session already met the second
  factor), counted against the SAME `password-change` budget, so the page is no
  second set of guesses for whoever finds the browser open. A wrong password is
  `STS-PORTAL-0080` and a register refusal `STS-PORTAL-0081`, both audited.
* **Nothing on the account changes**: same password, same kvno. The console's
  twin is a password RESET and says so; this page is not one.
* **The keytab is shown on the 200 and never on a redirect**, `no-store`, as a
  `data:` link with a `download` attribute beside the base64 — the console's
  keytab page's arrangement, and no script.
* **The register is required LAZILY** (`defaultDeps()`'s `personKeys`): the
  portal is built at 8a in the require order, and requiring
  `kerberos/krb5_person_keys` there would load the principal database and the
  keytab writer ahead of the Kerberos modules for a page nobody has asked for.

In development the keytab holds the development KDC's key
(`krb5.userPassword`), the password is not checked (nothing is), and the page
says both.

## `/portal/consents`: WITHDRAWING WHAT YOU AGREED TO (2026-09-23, #172)

`portal_consents.ts`, registered after `/portal/sign-ins` through the same
`register(context)` and for its reason. Until #172 a person could not read back
what they had agreed on the consent screen, and only an administrator could
withdraw it. `common/CLAUDE.md` (3t, *Withdrawn means withdrawn*) argues what a
withdrawal does; four things are this page's:

* **The same functions as `/admin/consent`**: `consent.revoke()` for one scope,
  `consent.revokeApplication()` for everything one application holds — so the
  tokens are revoked, the instant recorded and a later refresh refused exactly
  as when an administrator does it. The page says so above the buttons.
* **The identity is the session's.** The form names an application and a
  scope, which name one of the signed-in person's OWN consents; one that is not
  on their entry is refused 400 (`STS-PORTAL-0085`), the `/portal/keys`
  credential id's arrangement. `manage-own`, CSRF on the POST, and the
  withdrawal audited as `consent.revoke` with the person as actor.
* **A scope under GLOBAL consent is listed apart, under Administrative
  consents, with no button (#537).** The override is the operator's
  configuration of the application, so it is not the person's to withdraw.
  Until #537 nothing about the person was written, so the page could only say
  so in a sentence. Now the authorization endpoint records each scope a global
  consent answered for the person (`oauthConsentApplied`,
  `consent.noteApplied()`, the first time only). The section draws the records
  that still stand (`consent.appliedConsentsOf()`): the application still
  carries the global consent, and the person has not also agreed to the scope
  themselves. It is not paged, because global consent is configured on a
  handful of applications. A sign-in made before #537 recorded nothing.
* **No script, real forms**, paged by application (twenty per page). The
  console's and the API's counterpart of *Withdraw everything for this
  application* is `revoke-application-consent` (rule 7).

## `/portal/gnap`: THE ACCESS YOU GAVE THROUGH GNAP (2026-10-03, #432 phase 7)

`portal_gnap.ts`, registered after `/portal/consents` through the same
`register(context)`. Until it, only the client (RFC 9635 section 5.4) and an
administrator could see or end a GNAP grant. Four things are this page's:

* **A page of its own, not a section of Consents** — weighed and argued in its
  header: a grant is a state machine with object-shaped rights, tokens, a
  lifetime and a reason it ended, and its one control ends the whole grant;
  the consent register holds GNAP's remembered approvals only as digests. Two
  meanings of "withdraw" under one heading is what this navigation exists to
  avoid. Under *Your account*, beside Consents, for Consents' reason.
* **The same view as the console and the API**: `gnap/gnap_console.ts`'s
  `personGrantsView()`, which the GNAP grants tab of `/admin/users` and
  `gnapGrants` on `/admin-api/users?user=` also draw, so a person and an
  administrator cannot see different things. Revoking is
  `gnap_grants.ts`'s `revokeGrantBy()` through `revokeOwnGrant()` — the one
  path the client's DELETE takes — so tokens, finalization and CAEP are the
  same whoever ends it. The page says so above the cards.
* **The identity is the session's.** The form names a GRANT, and
  `revokeOwnGrant()` refuses one whose resource owner is not the signed-in
  person, or one with nothing live left (`STS-PORTAL-0163`, 400) — the
  `/portal/keys` credential id's arrangement. `manage-own`, CSRF on the POST,
  and `gnap.grant.revoke` audited with the person as actor:
  `tests/vendored/sts_gnap_core.js` section 15 asserts the ACTOR, this
  directory's rule that only the audit row proves the write.
* **Under cells (#98) it lists this cell's grants**, which is normally all of
  them (a grant moves to its resource owner's home before approval), and says
  so in a note when the service has several cells — never a partial list
  presented as the whole. No script, twenty grants a page, no token value
  ever drawn.

## `/portal/delegate`: WHO MAY ACT FOR YOU (2026-09-23, #108)

RFC 8693 section 4.4's `may_act` "makes a statement that one party is
authorized to become the actor and act on behalf of another party", and the
owner's decision on #108 is that the statement is the PERSON's: `stsMayAct` on
their own entry, the DN of one person or application in the realm. Every access
token issued about them then carries `may_act` naming that party
(`../common/delegation_policy.ts`, `mayActClaimFor()`), and a token exchange of
one by anybody else is refused in every mode. `portal_delegate.ts` draws it the
way `portal_app_passwords.ts` draws its page — a file beside `portal.ts`,
`register(context)`, a real submit button and no script — in *Your account*.

**The form names the DELEGATE, never whose delegate it is**: the identity is the
session's, this directory's rule. `credentials.setMayAct()` refuses a DN naming
nobody and the person themselves (`STS-AUTHN-0227`); the page answers 400 with
`STS-PORTAL-0086` and the store's sentence. An administrator's
`stsNotDelegated` on the account is SAID on the page, because it makes whatever
the person names moot. An administrator sets the same attribute from the
person's `/admin/users` page and `POST /admin-api/users/set-may-act`.

## `/portal/self-issued`: THE WALLET KEYS THAT SIGN YOU IN (2026-09-23, #129)

The SIOPv2 subjects enrolled on the person's own entry, each with a Remove,
and — while `oid4vp.signInSelfIssued` is on — **Enrol a wallet**, a link to
`/authn/wallet?siop=1&enrol=1`. **It enrols only a key the person PROVES**:
the wallet answers a SIOPv2 request started from the sign-on session this
browser already holds, and `oid4vc/vc_signin.ts` enrols the verified subject
for that session's person and sends them back here with `?enrolled=1`.
Nothing is typed, because a DID pasted into a box could be somebody else's —
the one person it would then let in. The removal form names the SUBJECT,
never whose it is (`STS-PORTAL-0087` when it is not theirs).
`portal_self_issued.ts` draws it the way `portal_delegate.ts` does. An
administrator enrols by value from `/admin/users` and `/admin-api`
(`oid4vc/CLAUDE.md`, 3ba).

**Since #693 (2026-10-20) each row says HOW it was enrolled** — *Proved with
your wallet* (`proof: wallet`) or *Added by an administrator* (`admin`, by
value, unproven) — because a subject released to a relying party must be one
the person proved, and the person is the one who can tell. **Proving a
subject that is already theirs proves it again** rather than being refused:
that is how an administrator's entry becomes a proved one, and how a did:web
whose document now names another key is re-pinned — the one re-pin flow,
chosen because it costs nothing new: the same link, the same transaction,
the same `siop.enrol()`. The enrolment writes `portal.siop.enrol` (the
removal's shape, `STS-VC-0094` on a refusal) from `oid4vc/vc_signin.ts`,
where the enrolment happens. The pin itself is `oid4vc/CLAUDE.md`'s (3ba).

## `/portal/wallet`: A CREDENTIAL ABOUT YOURSELF, INTO YOUR OWN WALLET (2026-10-12, #589)

The third page here that HANDS SOMEBODY A CREDENTIAL, and the first whose
credential leaves this service to be held somewhere else: a pre-authorized
OpenID4VCI Credential Offer (Appendix H.2, or H.3 deferred) of one of the
realm's credential configurations, for the person's OWN wallet. It was the
product behaviour of the demo issuer's `/issuer/offer` until rcbj decided on
2026-10-12 that it is a real self-service feature; `oid4vc/CLAUDE.md` has
that history and `makeOffer()`, which the demo issuer called too until it left
for the development companion on #594 (which links a person here for a
pre-authorized offer).

* **Two operations** (`portal_wallet.ts`): `GET
  /account-api/credentials/offerable` (the page's view: the configurations,
  named as the issuer's metadata names them, the two modes, the offer's
  lifetime) and `POST /account-api/credentials/offers` (`configuration`,
  `mode`). The paths are the API's names for the resource rather than the
  page's, because a native application holding `account:manage` asks for an
  offer with no page in sight; `mirrors` ties them to `GET` and `POST
  /portal/wallet` as rule 7's twin asks.
* **THE SUBJECT IS THE TOKEN'S**: the offer names `caller.username` and the
  token's `sub`, and a body naming anybody is ignored — the A01 rule above.
* **IT IS MADE ON THE SIGN-ON SESSION THE TOKEN WAS ISSUED ON**
  (`caller.signOn`), which CAEP reports as `session-presented` naming
  OpenID4VCI. Where the token registry no longer says
  which session that was — it is capped — or the session continued without
  signing in, the offer is REFUSED (`STS-PORTAL-0590`) rather than made on
  nothing; signing in again cures it. `STS-PORTAL-0310` is the same answer
  for a device link, for the same reason.
* **THE OFFER IS SHOWN ONCE, IN PLACE**: the POST answers the offer and the
  page's `view` with it, and the runtime draws it without a URL — the
  pre-authorized code and the Transaction Code beside it must not reach the
  address bar or the history. A reload shows the form again, and a new offer
  is a new code.
* **THE QR CODE IS DRAWN IN THE BROWSER** (`common/web_qr.ts`, here until #572 moved it beside the sign-in surface, which draws one too), from the offer BY
  REFERENCE, which is short enough to scan; the open-in-wallet link carries
  the offer by value as the `openid-credential-offer://` URI a native wallet
  registers for (`haip-vci://` where `oid4vci.walletInvocation` says so,
  `vc_offers.ts`'s `offerScheme()`), and the configured web wallet
  (`oid4vci.walletUrl`) gets a second link — **none by default since
  2026-10-12**, when that setting stopped defaulting to the embedded
  debugger's `http://localhost:3000`. Under the links the page says what to
  do when nothing opens (`wallet-no-app`). A third-party wallet redeems the
  pre-authorized code naming no client, which the authorization server's
  metadata says it may (`pre-authorized_grant_anonymous_access_supported`,
  OpenID4VCI 1.0 section 12.3); before that member a wallet defaulted to
  sending a client_id of its own, which product refuses unregistered. `/portal/mfa`'s QR code is an image the server drew, because
  its secret is the server's to show; here the answer is a URI and the
  picture is only a way of showing it, so the renderer makes it. `web_qr.ts`
  requires nothing, emits inline SVG (the portal's `img-src` admits no
  `data:` image) and is held module for module to the `qrcode` package the
  server uses, for every level and mask (`tests/portal_wallet.js`, A).
* **THE ELEMENT IDS ARE THE DEMO ISSUER'S** — `offer_qr`, `tx_code`,
  `offer_uri`, `open_in_wallet` — so a reader of either screen finds the
  same things.
* **Filed under the credentials section**, beside *Self-issued IDs*, for the
  signing keys' reason: what it hands over is a credential about the person,
  on their own sign-in.
* `tests/portal_wallet.js` holds the operations, the refusals and the page's
  round trip through the bundle; three protocol jobs make their offers here
  (`oid4vc/CLAUDE.md`).
* **THE CREDENTIALS ISSUED TO THE PERSON, AND REMOVE** (#661, rcbj 2026-10-16).
  The view's `issued` was `vc_issued.ts`'s `historyForSubject(caller.sub)`
  (one entry per issuance since #670, below): every credential still on one
  of the person's rows, newest first, with
  its state and the last event their wallet sent to the Notification
  Endpoint. The issuer mints the Credential Response's `notification_id`
  BEFORE it records the credential so the two are linked; the wallet's
  report is shown and disowns nothing. A row goes when its last credential
  expires, so this is what the register holds, not everything ever issued.
  **Remove** is `POST /account-api/credentials/remove` (`id`), mirrored by
  `POST /portal/remove-wallet-credential` because `POST /portal/wallet` is
  the offer. rcbj chose REVOKE AND KEEP IN THE HISTORY over hiding a row
  (2026-10-16): `removeForSubject()` sets that one credential's status-list
  entry INVALID, revokes its issued-register row and stamps it removed,
  which `disownedReason()` refuses at sign-in — the one credential, not an
  `ldp_vc` row's siblings, which `disown()` would take. **No protocol lets
  an issuer delete a wallet's copy** (OpenID4VP is a verifier asking;
  OpenID4VCI's notification runs wallet to issuer), so the page says the
  person must delete it in the wallet (`wallet-remove-note`). The id is a
  digest of the row and the credential, looked up among the CALLER's rows
  only: another person's is refused as unknown (`STS-PORTAL-0591`).
  The history is PAGED twenty at a time, as `/portal/sign-ins` and
  `/portal/claim-sources` are (`page`, `paging`, `kit.pageNav()`), and both
  forms carry the page they were on so the view an act answers is that
  page. `tests/portal_wallet_history.js` holds it.
* **ONE ROW PER ISSUANCE, ITS BATCH COPIES UNDER IT** (#670, rcbj
  2026-10-17). The issuer advertises `batch_credential_issuance.batch_size`
  (`oid4vci.batchSize`, 4), so a wallet sends four proofs and takes four
  credentials from one Credential Response, each bound to a different key
  of its own with its own status-list entry — and the list showed four rows
  for one "Add to your wallet". **They were never one register row** (the
  brief for #670 expected they would be; the code says otherwise): a JOSE
  row is keyed by its credential
  and an `ldp_vc` row by its holder key. What the copies share is the
  response's `notification_id`, so `vc_issued.ts`'s `issuancesForSubject()`
  groups by it (`oid4vc/CLAUDE.md`). The view's `issued` is one entry per
  issuance — configuration, format, issued, its state (the copies' where
  they agree, else `mixed` with `counts`, drawn "3 of 4: Valid"), Remove —
  and its `copies` are drawn in a `<details>` fold under the row: "Copy 2
  of 4", the wallet key (the first twelve characters of the RFC 7638
  thumbprint, with the whole thumbprint and, for `ldp_vc`, the holder's
  `did:jwk` as the tooltip — twelve characters of a `did:jwk` are
  `did:jwk:eyJ` for every key, which is why the visible part is always the
  thumbprint, as on the console's sign-out page), the status-list index,
  and a Remove of its own where the issuance has more than one. While
  `batchSize` is over one the pane says batching is on, how many copies,
  and that it is so verifiers cannot link presentations by the key
  (`wallet-batch-note`); at one it says nothing about batching. **A page
  counts issuances.** **REMOVE IS STILL ONE OPERATION**:
  `POST /account-api/credentials/remove`'s `id` is an issuance's (every copy
  still good) or a copy's (that copy alone). The two are digests of
  different strings and cannot collide; both are the same act on the same
  resource, with the same refusal (`STS-PORTAL-0591`, on an id not on one of
  the CALLER's rows), the same audit action (`portal.vc.remove`, its detail
  saying `scope`, `removed` and `copies`) and the one portal path, so a
  `scope` member could only restate the id and would add a mismatch to
  refuse. The answer says `scope` and `removed`; one CAEP signal per act.
  **The console has no list of a person's issued credentials to keep in
  step**: its sign-out page (`logout/logout.ts`'s `wallet-credential`) lists
  register ROWS, one per wallet key, because a global sign-out disowns a
  row, and already shows each one's key the same twelve characters long.
  `tests/portal_wallet_batch.js` holds it.
* **THE SIGNING ALGORITHM, CHOSEN PER OFFER** (rcbj, 2026-10-16). One
  `<select name="signingAlg">` under the configuration and mode radios: every
  configuration's `signingAlgs` (the configured default first, post-quantum
  drafts named as drafts in `ALG_NOTES`), each option's `data-for` naming
  its configurations and `data-default-for` those it is the default of. The
  runtime's `wireDependentSelects()` (`data-depends-on="configuration"`)
  shows only the checked configuration's and selects its default; the first
  configuration's are drawn so already, for a browser without the script. A
  value not in the configuration's list is refused (`STS-PORTAL-0592`); the
  default is not recorded as a choice, so a change of the setting before
  the wallet redeems still applies. `oid4vc/CLAUDE.md` has where it goes.

## `/portal/devices`: A PERSON'S OWN DEVICES (2026-09-23, #130; #164 phase 2, 2026-09-26)

The entries in `ou=devices` the person owns, the applications that used
each, whether its Native SSO secret is live, its keys and whether each is
attested, and how it was registered; a Remove each (`STS-PORTAL-0088` when
the device is not theirs). It asks `authn` about sessions directly, because
the portal is loaded before the authorization server whose `sessionIsLive()`
says the same. `portal_devices.ts`, drawn the way `portal_self_issued.ts`
is; `common/device_enrolment.ts` holds everything that is not a page.

**SINCE #164 PHASE 2 THE PERSON REGISTERS A DEVICE HERE BY PROVING A KEY**
(decision 6b), two ways:

* **A JWK proof.** *Get a challenge* issues one bound to the portal session
  (`devices.challenges`, per realm, persisted, one per session and purpose,
  answered once across the cluster, `devices.challengeTtlSeconds`). The
  device signs a `device-key-proof+jwt` JWS over `{ nonce, aud, iat }`
  (`aud` is this page's absolute address), or answers with an Apple App
  Attest object whose clientDataHash is the challenge's SHA-256, and the
  person pastes it. An `x5c` in the JWS is an Android Key Attestation.
  **No script**: a browser cannot sign with a device's key, so the page is a
  form carrying what the device made. A device APP drives the same act
  through `POST /portal/devices/challenge` and `POST /portal/devices/proof`
  (`application/json` only, the portal session's cookie; the challenge is
  the anti-forgery token — a forgery can neither read it nor sign over it —
  which `device_enrolment.ts` argues).
* **Linking a WebAuthn platform credential** the person enrolled on
  `/portal/keys`, proven by a FRESH assertion over a challenge from here,
  spent through `credentials.spendAssertion()` (the challenge claim and the
  signature counter a sign-in advances). A roaming (`cross-platform`) key is
  refused: it identifies no device. It is attested when its REGISTRATION
  attestation (#105) verified and was trusted.

**THE PAGES SAY WHICH KEYS CAN BE LINKED (2026-09-26).** A person holding only
a YubiKey found the link card with no form and nothing naming the key it had
passed over, and `/portal/keys` labels every key "security key" and did not say
which were roaming. Both pages now ask `credentials.keyKind()` — one answer for
the Kind column on `/portal/keys`, the note under it, the link card's list of
keys not offered (named with the model a trusted attestation gave) and
`beginLink()`'s refusal.

**SUPERSEDED BY #470 (2026-10-06)**: the three-way radio described next became
two calls to action — *Create a passkey* and *Use a security key* — and its
lesson is kept by sending *Create a passkey* with NO attachment, only hints
(see *The passkey page*, above). The paragraph is kept for why.

**AND `/portal/keys` ASKS WHERE THE KEY LIVES (2026-09-26).** The page asked for
"a security key" and let the browser choose, and with `webauthn.residentKey` (the
passkey policy's since #527) at `discouraged` Chrome and Edge offered a USB key or a phone and never the
device's own authenticator — so nothing a person enrolled could be linked. The
form now offers *Built into this device* (a platform authenticator and a
discoverable credential, `preferred` unless the setting says `required`) and *A
security key I carry* (cross-platform), carried on the pending enrolment as
`kind` and handed to `webauthnPolicy.creationOptions(rpId, kind)`. Only the
kinds `webauthn.authenticatorAttachment` allows are drawn
(`authenticatorKinds()`); a setting naming one wins over the choice. The kind is
a REQUEST to the browser like every other ceremony option and nothing checks
what came back — the recorded attachment is what Devices reads. **The default
is a third answer, *Let my browser choose*** (`kind=any`, the request as it
was), and **a ceremony the browser could not run abandons the pending
enrolment** and draws the form again with the browser's error: the first
version defaulted to *Built into this device* and kept the enrolment armed, so
Linux Firefox — which has nothing built in — could register no key at all and
never get back to the choice. `tests/vendored/sts_portal_backup_keys.js`
section 1a holds both.

**THE LINK STEP IS A SCRIPTED PAGE, AND ITS OWN ROW IN THE ROOT TABLE.** A
fresh assertion is `navigator.credentials.get()` and no markup makes it, which
is `/portal/keys`' argument and `/authn/webauthn`'s, made again here from
scratch because the rule says "the page next door" is not one. It runs
`/authn/webauthn.js` — the SAME resource, in `get` mode — and the relaxed
policy (`app.contentSecurityPolicy()`, so `frame-ancestors` stays) is sent
ONLY on the page that draws an armed ceremony; every other state of the page
runs no script. The button under it is real: with the script blocked it posts
a `link-finish` with no assertion, answered by a sentence.

**Product refuses a key with no attestation that chained to a trusted root**
(`mode.acceptsUnattestedDeviceKeys()`, `STS-DEVICE-0024`); development
registers it self-asserted. Refusals are `STS-DEVICE-0016`–`0028`; the page
and the JSON doors never take an identity from the request.

**The scripted link step is driven in a real browser** by
`tests/vendored/sts_portal_device_webauthn.js` (#258): Chrome's virtual
authenticators, the roaming key refused, the page with its script blocked,
the armed policy, the link, and a later sign-in recognising the device.
**In product it can only assert the refusal**: Chrome re-mints the virtual
authenticator's self-signed attestation certificate at every registration,
so no anchor makes its key attested, and product links nothing less — so
the device and its recognition are asserted in development (`memory` mode).
`tests/device_enrolment.js` still holds `finishLink()` in process.

## `/portal/ciba`: SIGN-IN REQUESTS (2026-09-23, #131)

CIBA's authentication device, by rcbj's decision: the backchannel
authentication requests waiting for the person — the client, the scopes and
the `binding_message` the client also shows, so the person can tell the
request is the one they started — with Approve and Deny, and the person's
CIBA user code, set (4 to 64 characters, hashed as a password is) or
cleared. A form names a REQUEST, never a person, and one not waiting for the
person looking is refused (`STS-PORTAL-0089`–`0091`). **An approval is as
strong as the request asks**: a request whose `acr_values` the session does
not meet is not approved; the page offers the portal's own sign-in again
with those `acr_values` and `prompt=login` (`oidc_rp.ts`'s `acrValues`
option), returning to `?stepup=<id>`, and Approve takes after that.
`portal_ciba.ts`, registered through `register(context)` as
`portal_devices.ts` is. `oauth-oidc/CLAUDE.md` (3bc) carries the protocol.
**An approval is single sign-on** (#239, #240, 2026-09-26). The approval
records the sign-on session it was made on (`facts.sessionId`), and the
tokens are issued on that session, so its end revokes their refresh token. It
is also CAEP's `session-presented`, via `OpenID Connect CIBA`. A denial
honours nothing and sends nothing.

**AND GNAP GRANTS WAITING FOR THEIR OWNER (#432 phase 6, 2026-10-03).** A
GNAP request naming this person while somebody else was at the approval page,
or offering no interaction (RFC 9635 sections 1.4 and 2.4, with
`gnap.ownerApproval` on), is listed in an *Access requests* section below the
CIBA requests. The page was chosen over a second approvals page because it IS
the page where a person answers what a client asked while they were
elsewhere; what is reused is its mechanism — the session is the identity, a
form names a request (`gnap-approve` / `gnap-deny` with the request's own id,
never a person), one answer, the step-up through the portal's sign-in with
the acr values the rights need (`?gnapstepup=<id>`) — and NOT CIBA's store:
the request is a GNAP grant held and continued by `gnap/`, and
`gnap/gnap_approval.ts` lists and answers it, reached LAZILY (the portal is
built at 8a, GNAP at 23d). Each right has the approval page's checkbox; the
repeated `right` field is read off the raw body (`helpers.bodyValues()`), as
the approval page reads it. A request not waiting for this person is
`STS-PORTAL-0243`, an approval short of the rights' acr `STS-PORTAL-0244`.
The person asking (whoever was at the page) is named on the card: an owner
judging a request for their access needs to know who wants it.

**AND THE OWNER CHECK AND THE LIMITS, AS ON THE APPROVAL PAGE (#432 phase
5).** Each right's limits are drawn under it with the approval page's own
controls (`common/limits_form.ts`, a static utility imported directly
because it loads nothing of GNAP's engine), and the form's schema reads the
post with them stripped off; `gnap_approval.answer()` is handed the request
and a reader of the raw body, asks `grants.approverRefusal()` after the
step-up (`STS-GNAP-0862`: a person named on a request is not thereby the
owner of what it names) and reads the lowered limits back (`0866` raised,
`0867` failing the type's schema), all before the answer is claimed.

## `/portal/claim-sources`: CONNECTED CLAIM SOURCES (#147, 2026-09-24)

The setup phase of OpenID Connect Claims Aggregation, the person's own. Every
Claims Provider the realm registered is listed; **Link** sends the person to
it (an authorization code flow with PKCE), and it sends them back to
`/portal/claim-sources/callback`, where the tokens are redeemed and sealed on
their entry; **Unlink** removes them. `portal_claim_sources.ts`, registered
through `register(context)` as `portal_ciba.ts` is; `oauth-oidc/CLAUDE.md`
(3bh) carries the protocol.

**ITS REDIRECTS ARE ABSOLUTE, ON `baseUrlOf(req)`**, because a bare
`/portal/...` Location is answered by the DEFAULT realm: nothing adds the
realm prefix to a Location on the way out. The job found it — the callback
sent a person linked in one realm to the default realm's portal.
`portal_devices.ts`'s Remove is absolute too since #164 (2026-09-26). Every
other portal page's 303 is still a bare path (`portal_ciba.ts`, the MFA
pages), which is the same defect in a non-default realm and is left for its
own change.

**THE CALLBACK IS BOUND TO THE BROWSER BY A COOKIE OF ITS OWN, NOT BY THE
SIGN-ON COOKIE (2026-10-12).** #568 first bound it to the browser's
`sts_session`; but that cookie is one per origin at `Path=/` whatever realm
minted it (`authn/CLAUDE.md`, `consoleSession()`), so a provider that is
another trust realm on the same origin overwrote it at its own sign-in, and
every such link was refused `STS-PORTAL-0300` while the page said nothing —
`sts_claims_aggregation` found it, with the refusal's text lost on a static
shell. Link's answer now sets `sts_claim_link`, a random secret scoped to
the realm's callback path (HttpOnly, SameSite=Lax), the flow keeps its
SHA-256, and the callback wants that cookie (`0300`) and the sign-on session
the token was issued on still live and the person's, asked by its id
(`STS-PORTAL-0303`). The cookie is cleared on every callback. The page draws
the callback's `problem` and `done` from its operation's `problem` and
`notice`.

## EVERY PORTAL LIST THAT CAN GROW WITHOUT A BOUND IS PAGED (#313's sweep, 2026-10-12)

The console's rule (`admin-ui/CLAUDE.md`, *EVERY LIST THAT CAN GROW WITHOUT A
BOUND IS PAGED*) holds here too. Three lists broke it and page now, twenty a
page, each answer carrying the slice and a paging member beside it
(`page`, `pages`, `per`, `total` — the portal's shape since #172):

| Page | List | Moves on | Was |
|---|---|---|---|
| `/portal/claim-sources` | `providers`, the realm's Claims Providers (`ou=claimproviders` grows with what an operator registers) | `page`; `linked` counts the person's links over every page | the whole register |
| `/portal/sign-ins` | `rows`, the person's assessed sign-ins of thirty days | `page`; paged IN THE STORE (`limit`/`offset`, `total` from the count), so a page reads twenty rows | the risk engine's default fifty, silently truncated |
| `/portal/email` | `sent`, the outbox's messages to the person | `sentPage`, beside `sentPaging` — named because the page holds other things than the list | the newest twenty, silently truncated |

`PortalKit.pageNav()` (`web_portal_kit.ts`) draws the control for a list that
moves on a parameter of its own and carries the reader's other parameters,
less `notice`, `problem` and `done`, which belong to the moment they were
said. The three older lists (consents, GNAP grants, the overview's
applications and signals) still draw their own `?page=` controls.

**Left unpaged, each with its bound**: devices (`devices.maxPerPerson`),
app passwords (`appPasswords.maxPerPerson`), passkeys
(`webauthn.maxKeysPerPerson`), enrolled certificates
(`pki.enrollmentMaxCertificatesPerEntry`), TLS client certificates
(`pki.personTlsClientCertificateMax`), EAB keys and SCEP challenges (10 a
person), self-issued subjects (10), CIBA and GNAP requests waiting (each
expires with its request), administrative consents (`portal_consents.ts`
argues it), and `/portal/wallet`'s credential configurations — a `<select>`
over the realm's configurations, not a table, and a menu is drawn whole so it
can be chosen from.

## `/portal/reset-password`: THE SECOND UNAUTHENTICATED PAGE (2026-09-13)

**Send a reset link** on a person's `/admin/users` page stores a hash of a
32-byte token and an expiry on the entry (`stsPasswordResetToken`,
`stsPasswordResetExpires`, `security.passwordResetTtlMinutes`), REMOVES the
current password into the history, signs the person out everywhere, and hands
the administrator `…/portal/reset-password?user=<name>&token=<token>` once.
This page spends it. It is `/portal/activate`'s shape and for its reasons, with
three differences:

* **GET checks the link before drawing the form** (rate limited on
  `password-reset`, `STS-PORTAL-0070`) and answers ONE sentence for every way a
  link is wrong — none issued, expired, mismatched, incomplete — with the real
  reason on the audit row (`portal.password-reset.refused`, `STS-PORTAL-0071`).
  Telling them apart to the requester would say which usernames have a link
  outstanding.
* **POST checks it again**, then refuses a mismatch and the reserved password
  (`STS-PORTAL-0072`) and whatever `credentials.setPassword()` refuses —
  the policy and the history (`STS-PORTAL-0073`) — with the form redrawn.
* **On success it spends the link, clears `pwdReset`, clears the rate-limit
  bucket, audits `portal.password-reset`, and sends a CAEP `credential-change`
  (password, create, initiated by the user)** through
  `ssf/account_signals.ts`. It signs nobody in: the page links to `/portal`,
  where the ordinary sign-in happens with the new password, for
  `/portal/activate`'s magic-link argument.
* **A RECOVERY FOR A PASSKEY HOLDER (#724, `common/CLAUDE.md` 3cq).** The
  POST asks the recovery question before it claims the link
  (`recoveryCheck()`): under `recoveryAssurance: operator-only` a link the
  person asked for themselves (`stsPasswordResetSource: self`) is refused
  403, `STS-AUTHN-0380`, with its own sentence, and stays unspent; an
  administrator's is not. A spent link then leaves a pending recovery
  (`credentials.noteRecovery()`), and `/portal/activate`'s finish does the
  same for somebody who held a passkey before the link was issued. The
  sign-in after either is held by `authn.ts` (`authn/CLAUDE.md`).

## SEVERAL NODES: A LINK IS CLAIMED BEFORE ANYTHING IS SET (2026-09-14, #46)

`POST /portal/activate` and `POST /portal/reset-password` claim their link in
the store (`credentials.spendActivation()` / `spendPasswordReset()`) after the
link has checked out and before a password is set, so one link POSTed to two
nodes at once sets one password. **`holdLinkClaim()` keeps the claim only for
the response that FINISHES** — `finishActivation()` and the reset's success
page mark it — and gives it back on every other answer: a mismatch, a refused
code, the authenticator step drawn before the link is spent (a 200 that does
not finish), a dropped connection. So a link behaves exactly as it did on one
node except that two requests cannot both finish it. A claimed link is the one
sentence every link failure is, audited under `STS-AUTHN-0183`.

## `portal_mail.ts`: `/portal/email`, `/portal/verify-email` and `/portal/forgot-password` (#63, 2026-09-22)

Three pages over the mail channel (`common/CLAUDE.md`, 3ay), in a file beside
`portal.ts` that is registered exactly as `portal_app_passwords.ts` is.

- **`/portal/email`** follows this portal's rule: it is signed in, and the
  identity is the session's. It shows the address on the person's own entry,
  whether it is verified, a button that mails a verification link to it, the
  one category of message that may be declined, and what was sent to them —
  never a body. It is under *Your account* for Security activity's reason: it
  is what this service SAYS, not a credential.
- **`/portal/verify-email` and `/portal/forgot-password` are the third and
  fourth pages nobody is signed in to**, beside `/portal/activate` and
  `/portal/reset-password`, and they take a username for those pages' reason:
  nobody is signed in, and what authorises them is the TOKEN, or nothing at
  all.
  - The verification GET draws a button and spends nothing, because a mail
    scanner follows every link.
  - The forgot-password page answers ONE sentence, before the work is done, so
    neither the words nor the timing say whether an account exists. It answers
    404 wherever `mail_uses.resetOffered()` says no.
  - It carries no CSRF token, because nobody is signed in to forge a request
    as. A cross-site POST can at most send a person a link they did not ask
    for. That is bounded by the rate limits and the mail ceiling, and it
    changes nothing until the link is used.
- **The reset form's sentence changed with it**: "no password you had before
  works once it is set" rather than "your old password no longer works",
  because a self-service link removes nothing until it is used.

## RESOURCES I OWN (#604, 2026-10-12)

rcbj: a section of the column, *Resources I own*, with Roles, Groups, Service
accounts and Applications, "driven by the owner fields". `portal_owned.ts`
answers four GETs, `/account-api/owned/<kind>` (`KINDS`), each mirroring
`/portal/owned/<kind>`; `web_owned.ts` draws them; `NAV`'s `owned` section
lists them after *Your account*. A resource is the person's when one of its
owner values — a role's `owner`, a group's `owner`, a service account's
`stsServiceAccountOwner`, an application's `appOwner` — names the person's
entry or a group the directory says they are in (`groupsOfUser()`); each row
says which (`via`). The owners are set on the console's Owners tabs, and an
owner may add and remove other owners (#607). The person is the token's, as
everywhere here. Everything is reached lazily at request time.
`tests/portal_owned.js` holds it.

**rcbj, 2026-10-13: no list of the person's groups under the table** — each
row's `via` already names the group that makes it theirs — **and a pager on
every page**, one page or many (`pageNav(..., always)`).

### AND ONE OF THEM, ADMINISTERED (#607, 2026-10-13)

rcbj: a person updates what they own from here, through the MANAGEMENT API,
and the check that they own it is the access-control policy's owner rule —
not repeated in `/account-api` (`mgmt-api/CLAUDE.md` *OWNERS*,
`xacml/CLAUDE.md`, `common/CLAUDE.md` 3cn). So:

* **EACH ROW OPENS ITS PAGE**, `/portal/owned/<kind>?name=<id>` — the same
  path, so the column and the heading need nothing — unless the row is
  `closed` (`portal_owned.ts` asks `ownership.protectionOf()` for the rows on
  the page), which says so instead.
* **THE PAGE IS DRAWN FROM `/admin-api`**: a `PortalPage` may carry
  `admin(query)`, the management API path whose GET answers it for that
  query, and the runtime reads it with the OWNER TOKEN; the view is
  `{ owned: { status, answer, canWrite, query } }`. A refusal — the owner
  rule's sentence, or why there is no owner token — is drawn, in English.
* **ITS FORMS POST THERE**: `data-admin="/admin-api/<kind>/<action>"`, sent
  as JSON with the owner token (`submitOwned()`; `fields.<attribute>` and
  `lines.<attribute>` become an `update-fields` body's `fields`), and the page
  is drawn again with the answer's message, a regenerated client secret said
  once, or the errors. The controls are the template's default owner
  actions; a realm whose policy narrows them refuses, and the refusal is
  drawn. Without `owner:write` the page draws no form.
* **THE OWNER TOKEN** (`web_portal_runtime.ts`): the sign-in names TWO
  resources — this realm's `/account-api` and `/admin-api` (RFC 8707,
  `SpaClient.formOf()` repeating the parameter) — and asks for
  `owner:read owner:write` beside `account:manage`. The code is redeemed for
  the account API, and the management API's token is REFRESHED from the same
  grant with `/admin-api` as its resource when an owner's page asks; the
  refresh token keeps both resources (`oauth-oidc/CLAUDE.md`), and one
  rotation chain serves both. The authorization server issues the owner
  scopes only to a person who owns something, so `scope` on that answer is
  what `canWrite` reads. The shell names `/admin-api`'s listener where it is
  elsewhere (`data-sts-api`, and `connect-src`).

## CONNECTED ACCOUNTS (#565, 2026-10-19)

`/portal/connected-accounts` (`portal_connected_accounts.ts`,
`web_connected_accounts.ts`) is where a person connects a consumer or social
provider to their own account. It is two `/account-api` operations, on the
claim sources' pattern: Connect answers `location`, the provider's address.
**There is no callback of this page's own**: the provider answers at the
federation module's assertion consumer service, where every check of a
federated sign-in is made, and `federation_sp.ts`'s `finishConnect()` writes
the link and sends the browser back with `done` or `problem`. The browser
binding is the federation module's `sts_fed_link`, set on Connect's answer.

The account-takeover checks are this page's, before anything starts:
* a sign-on session (`STS-PORTAL-0610`) whose risk is LOW or unscored
  (`STS-PORTAL-0611`, a refusal, never a step-up);
* an authentication within `federation.connectRecentAuthMinutes`, or the
  answer is `stepUp` (`prompt=login`, `max_age`).

**Any authentication counts as recent, not only a password**, a departure
from the plan's "authenticated locally" (2026-10-19). A person whose account
a provider made has no password here, and proving that provider again proves
the account. The federation module and the directory are reached at request
time (8a-acct is before 10c and 21). `federation/CLAUDE.md` has the
federation half.

