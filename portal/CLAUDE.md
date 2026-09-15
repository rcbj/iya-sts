# CLAUDE.md — `portal/`

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
| `/portal/callback` | — | the OIDC redirect URI |
| `/portal/remove-key`, `/portal/signout` | authenticated | the two other POSTs |

**FIVE PAGES SINCE 2026-09-10**, and the fifth is the first here that HANDS
SOMEBODY A CREDENTIAL rather than taking one.

**`NAV` IS THE PAGE LIST AND THERE IS NO SECOND COPY.** `navBar()` draws the
column from it, `headingFor()` titles the page from it, and `paths()` reports it
to `sts_metadata.js` — so a page added there appears in the column, in the
browser tab and in the endpoint list, and one removed leaves none of the three
behind. `tests/vendored/sts_portal_sessions.js` asserts, for each of the four,
that its own entry is marked `aria-current="page"`.

**A `GET` AND A `POST` SHARE `/portal/password`.** The form has to live
somewhere now that it is not on the overview, and a form and the handler that
answers it on two addresses is a distinction nobody could state a reason for.
`sts_metadata.js` is keyed by path and merges the methods, so this costs one
entry rather than two.

**THE GETs ASK THE ACCESS GATE FOR `read` AND THE POSTs FOR `manage-own`.**
Drawing a page is reading. That distinction is the reason the portal has an
action of its own at all — see `common/access_gate.js`'s `ACTION` — and a
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

`preview: true` on the request, honoured in `xacml/xacml_role_pep.js`. Nothing
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

### It is still not a launch button, and that is a refusal rather than a gap

The link goes to the application's own front door and hands it nothing, which
is where a sign-in starts and is exactly what a person would type themselves.
It does not START one. This service implements identity-provider-initiated
sign-on in none of the four browser profiles — `/saml2`'s own page lists it
among what is not implemented — so a link that began one would have to invent a
request the application never asked for and is not expecting. The page says so.

### It is paginated, and the cap is a setting since 2026-09-12

Twenty rows a page. The scan stops at `portal.applicationScanLimit` entries —
1,000 by default — and says when it bit, with the number in force: each entry
costs a policy evaluation per distinct kind, on the one thread that answers
every socket this service holds, which is the stall `CLAUDE.md`'s worker-pool
section is about. **This heading said "a guard rather than a setting"** on the
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
`common/credentials.js` writes the attribute only when a code proves the app
really has it.

**An unconfirmed secret on somebody's entry would be a second factor they
cannot produce.** That is not a hypothetical: open this page, be interrupted,
come back tomorrow — a one-step enrolment has just locked somebody out of their
own account with a form they abandoned. It is the same shape of lockout
`removeKey()` refuses to create, caught before it exists rather than after.

### The QR code is an image this server drew, and the typed secret is not a fallback nobody sees

`script-src 'none'` covers every page here except `/portal/keys` (see below,
2026-09-10), so a QR library running in the browser was never available on this
one — `common/totp.js` renders an SVG and it arrives as
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

## `/portal/keys`: ENROLLING A SECURITY KEY, AND A BACKUP FOR IT (2026-09-10)

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

### It is the SEVENTH scripted page in this service and the first in this portal

It arrived 2026-09-10, in a directory whose own file said every page of it was
`script-src 'none'`.

`app.js` sets `script-src 'none'` everywhere and the rule is that a page gets an
exception only when it CANNOT work without one — four candidates have been
refused on it, `/authn/totp` among them, which sits next door to a scripted page
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

### It is held to the same two address rules as the sign-in screen (2026-09-12)

`authn.rpIdProblem()` refuses a ceremony whose configured `webauthn.rpId` does
not fit the host in product mode, and `authn.expectedOriginFor()` decides the
origin from `webauthn.allowedOrigins` where it is set. The `finish` action asks
both rather than `authn.originOf(base)`, so a key enrolled here and a key used
at `/authn/webauthn` are held to one answer. `authn/CLAUDE.md` argues them.

### What is still not done

**`/portal/activate`'s `key_role` radio still enrols nothing.** Choosing *a
security key instead of a password* spends the link, says "your account is
ready" and writes an audit row about a credential that does not exist — leaving
an account nobody can sign in to. It needs this same ceremony on an
UNAUTHENTICATED page, where the link is the credential that authorises it, and
that is the next piece of work rather than a decision.

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

**`finishActivation()` is one function because there are three ways in now** — a
plain setup, an authenticator confirmed on the second POST, and an authenticator
that could not be started — and each has to spend the link, write the audit row
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

## THE PORTAL IS AN OIDC RELYING PARTY (2026-09-06)

`requireSignIn()` sends an unauthenticated visitor through **the authorization
code flow**, as the registered client `sts-user-portal` — an ordinary entry
under `ou=applications`, seeded at startup in every realm. It does not reach for
the sign-on session at all: the browser goes to `/oauth2/authorize`, the sign-in
screen is reached only because the AUTHORIZATION ENDPOINT decides it needs one,
and what comes back is a code that buys an ID Token that establishes the
portal's OWN session in its own cookie (`sts_portal`).
`common/oidc_rp.js` runs it and argues it.

Three things about it are this directory's:

* **AND SINCE 2026-09-11 THAT SINGLE SIGN-ON REACHES THE CONSOLE, IN EVERY
  REALM, AND IT DID NOT BEFORE.** The portal's flow has always run in the
  AMBIENT realm — `/portal` is a person's own account in the realm they are in —
  and the console's ran in the DEFAULT realm wherever it was reached. An
  authorization endpoint can only answer out of the realm it is reached in, so
  inside a realm the two surfaces were asking two different authorization
  servers and neither could see the other's sign-on session: **signing in at
  `/realm/acme/portal` and then opening `/realm/acme/admin` meant signing in
  again, and so did the other direction.** Nothing here changed — the console's
  flow moved to the ambient realm to meet this one. `admin-ui/CLAUDE.md` argues
  what that cost the console and `common/oidc_rp.js` holds the split.
* **A `Location` HEADER IS NOT MARKUP, AND THIS SURFACE IS WHERE THAT COST
  SOMETHING.** `app.js` rewrites every root-relative `href`, `action` and `src`
  in an HTML response into the current realm — which is what carries this
  portal's own links inside `/realm/acme` — and a redirect header is none of
  those. The seven `requireSignIn()` call sites pass a constant built from
  `BASE`, which is `/portal` with no prefix on it, so a sign-in at
  `/realm/acme/portal` completed the flow in acme, was handed a session in acme,
  and was then redirected to the DEFAULT realm's portal — which correctly has no
  session for that person and asks them to sign in again. **A sign-in that works
  and then immediately asks again, with nothing in the flow having failed.** It
  is fixed at `oidc_rp.js`'s one choke point rather than at the seven call
  sites, and idempotently, because the console passes an address that already
  carries the prefix and a caller should not have to know which kind it holds.
* **A PERSON WHO SIGNED IN ELSEWHERE IS NOT SILENTLY IN THEIR ACCOUNT PAGE.**
  Reading `authn.sessionOf()` would have meant exactly that — any sign-in
  anywhere in this service silently opening somebody's own account page,
  without this application ever having asked. Now the portal has to run a flow,
  and single sign-on is what makes that flow invisible when there IS a sign-on
  session: the authorization endpoint answers with a code and nobody types
  anything. **That is single sign-on happening through the protocol rather than
  through a shared cookie**, which is the distinction worth being able to
  demonstrate on a mock.
* **THE SECTION BELOW USED TO SAY `appAuthnMechanism`-style: "NO application —
  the portal is not one".** It is one now. What made that sentence right was
  that no entry existed and naming one would have put a fiction in the
  registry; what makes it wrong is that the entry is real, seeded by this
  service, and is what the role gate is handed.
* **ENDING THE PORTAL'S SESSION ALONE DOES NOT END THE SIGN-ON SESSION**, and
  the next visit signs the person straight back in without a screen. That is
  what every real relying party does, and the cascade runs the other way:
  ending the SIGN-ON session ends the portal's with it. **WHICH IS WHY THE SIGN
  OUT BUTTON ENDS BOTH** — see below.

## Two sign-outs, and they are two different acts (2026-09-06)

**They were on one page when this was written and the page split under
them.** The narrow one moved into the shell and is now in the corner of
ALL FOUR pages, which is the same decision rather than a new one — a
person who wants out should not have to find the page it lives on first.
The wider one stayed where it was, at the foot of the Overview.

**THE BUTTON IN THE CORNER OF EVERY PAGE IS `POST /portal/signout`.** It
ends the portal's own relying-party session AND the sign-on session it was
derived from, and clears both cookies. It has to end both: this portal is a
relying party, so ending only its own session would leave the next visit
running the code flow, meeting the live sign-on session, and coming back in
with nothing typed — a Sign out button that visibly does not sign anybody out.
The cascade in `dropSession()` then ends anything else derived from that
sign-on session, the admin console included, and the page SAYS so rather than
reaching further than its label quietly.

**THE BUTTON AT THE FOOT OF THE OVERVIEW IS STILL `POST /logout`**, and it is the wider
act: every session and credential this identity holds in every protocol —
tokens, tickets, offers, LDAP binds. Both are drawn, each says which it is, and
the heading over the second one says it reaches further. Two controls that do
different things is not duplication; one control that quietly did the wider
thing would be.

Three details worth keeping:

* **The CSRF token is checked on the sign-out**, like every other form here. A
  sign-out fired from another site is the classic "harmless" CSRF that is not:
  somebody's session ending under them repeatedly, with no way to stay signed
  in. The refusal writes `portal.signout.csrf`, beside the success's
  `portal.signout`, for the reason every refusal here is registered in
  `audit.js` — a log of only what worked is a log of everything except the
  attack.
* **It does NOT go through `requireSignIn()`**, which is deliberate rather than
  an omission: that function redirects a person with no session into the
  authorization code flow, which for a sign-out would send somebody who is
  already signed out off to sign IN. A sign-out asked of a browser with no
  session is answered with the page saying they are signed out, because that is
  true.
* **The sessions it ends each write their own `session.end`** through
  `dropSession()`. The `portal.signout` row is the ACT and does not count them
  again — rule 3c, read as it is everywhere else here.

## `beginAuthentication()` and not a bare redirect

**THAT RULE IS NOW ONE LAYER DOWN AND STILL DECIDES THE SHAPE.** `oidc_rp.js`
sends the browser to `/oauth2/authorize`, and it is the AUTHORIZATION ENDPOINT
that calls `beginAuthentication()` — so the reason below is why the flow works
at all rather than why this file redirects where it does.

`requireSignIn()` used to send an unauthenticated visitor through
`authn.beginAuthentication()`, exactly as `saml2_sso.js` and `consent_screen.js`
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
(`federation/federation_sp.js`) and the admin console's 401 for a form posted
with an expired session (`admin-ui/admin.js`, whose link was ALSO swallowed into
a `<details>` summary and so was not clickable at all). The rule read off all
three: **`/authn/login` is never a destination — link to a page that STARTS a
sign-in, and let it mint the record.**

## The OWASP controls, and where each lives

| | Control | Where |
|---|---|---|
| A01 | identity from the session, never the request | this directory, and THREE test files at three layers — see below |
| A02 | scrypt for passwords, activation token hashed | `common/credentials.js`, `common/crypto.js` |
| A03 | every value through `esc()`; no SQL built from input anywhere | this directory |
| A04 | rate limiting on activation, sign-in and password change | `common/websecurity.js` |
| A05 | the CSP `app.js` sets on every response | `common/app.js` |
| A07 | CSRF tokens, the previous session ended on sign-in, no message distinguishing "no such person" from "wrong credential" | `common/websecurity.js`, `authn/authn.js` |
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
`ssf/ssf_receivers.js` holds the design, `ssf/CLAUDE.md` argues it, and the A01
half is above. Three things belong here.

**IT IS UNDER *Your account* AND NOT UNDER *How you sign in*.** That section
holds the CREDENTIALS on this person's entry, one page each, and every page in
it is a control — a password form, a key list, an authenticator enrolment. This
is not a control and not about a credential: it is a RECORD, and a reader
arrives at it asking what happened rather than asking to change something.

**IT IS A RECORD AND SAYS SO, INCLUDING THAT THE ACCOUNT'S OWNER CANNOT EMPTY
IT.** A list of what was said about an account would be worth nothing if the
person it is about could clear it, so there is no Clear here — the console has
one, for its own inbox. The page says that in as many words rather than simply
lacking the button, because a missing control reads as an oversight.

**IT NEEDS NO SCRIPT AND HAS NONE, SO THE CLAIM THIS FILE MAKES ABOUT
`script-src 'none'` IS UNCHANGED BY IT.** `/portal/keys` is still the only
exception in this directory. A list of events with a `<details>` per payload is
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
`common/credentials.js` at the moment a second factor is enrolled, once, and
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

`common/inetorgperson.js` is the list and this page is a reader of it.
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
Rule 3e's test answers yes both ways round: this module is at 8b and that one
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
every page of this portal is `script-src 'none'`, and the console made exactly
this argument for its own collapsible prose. There is no collapse-all and there
will not be one.

### Nothing here can be edited

These attributes are written by an operator, by SCIM, or over LDAP. This portal
changes how somebody AUTHENTICATES and not what the directory records about
them, and the page says so rather than leaving a reader to wonder where the
form is. **Most of them cannot be written through `/admin/users/new` either** —
that form checks against `oid4vc/vc_claims.js`'s catalogue, which is
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
which is `totp.enabled`'s contract word for word: a key already on an entry goes
on verifying, and what stops is new ones *from the portal* — an operator issuing
from `/admin/pki` is unaffected, which is the point of having the switch.

### Where it is filed, and the argument that was refused

Under **How you sign in**, whose own description is *the credentials on your own
entry, one page each*. The argument for *Your account* — that this key never
signs anybody IN, since there is no browser session at the end of it — was
considered and refused: it is an argument about the section's TITLE rather than
about what the section holds, and moving the heading's meaning to fit one page
would misfile the other three.

## A TLS CLIENT CERTIFICATE, THE THIRD CARD ON `/portal/signing-key` (2026-09-13)

Asked for by rcbj beside the RFC 7523 and RFC 7522 key pairs: a person generates
a TLS client certificate that maps to their identity and installs it in their
browser. `common/tls_client_certificates.js` issues, packages and revokes;
`common/CLAUDE.md` 3ag argues the gate that makes the listeners' trust in the
service Root safe, and `tls/CLAUDE.md` the listeners. What is this page's:

* **THE DOWNLOAD IS THE RESPONSE TO THE POST.** `generate-tls-client` renders a
  one-time card with three `data:` links carrying `download` — the `.p12`, an
  encrypted `-key.pem`, the `-chain.pem` — which is the console keytab page's
  arrangement and the only way a file leaves a page with `script-src 'none'`.
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
  revocation (the CRL, OCSP, the listeners refusing it), with two reasons a person
  can honestly give: `cessationOfOperation` and `keyCompromise`.
* **A PACKAGING FAILURE REVOKES THE CERTIFICATE AT ONCE** (`STS-PORTAL-0042`): its
  key is gone, and a valid certificate nobody can present or knows to revoke is
  worse than a line on a list.
* **WHERE IT WORKS** is drawn from `tls.port` and `tls.mutualPort` on the host the
  page was reached at, because this module is required long before
  `tls/tls_server.js` and cannot ask for the bound ports without moving routes.

**NO `/admin-api` MIRROR**, for this page's standing reason: the answer is
per-person. An operator revokes one on `/admin/pki`'s revocation pane, where it
is listed like every other leaf of the `tls-client` authority.
`tests/vendored/sts_portal_signing_key.js` section 9 is the over-HTTP half; the
handshake is `tests/tls_client_certificates.js`, because no launcher publishes
9443 to a job.

## THE SIGN-IN CAN BE REFUSED FOR A SECOND REASON, AND THE 503 SAYS WHICH (2026-09-12)

`oidcRp.beginSignIn()` used to fail for one reason — `sts-user-portal` gone or
without a secret — and the page said *which is what has happened*. In product
mode it can also refuse because this portal is being reached at an address that
entry does not carry as a redirect URI, which `common/oidc_rp.js` now refuses
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
(`common/cert_enrollment.js`, rule 3ag). An administrator makes one for anybody
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
* **IT IS A FILE BESIDE `portal.js` REGISTERED THROUGH `register(context)`**:
  the shell, the sign-in, the CSRF field and the escaping are private to
  `portal.js`, which hands them over at the foot of its own routes. That keeps
  the route order the column's and the new file to what is new.

**THE TLS CLIENT CERTIFICATES THIS PORTAL ISSUES DIRECTLY are
`/portal/signing-key`'s third card and are NOT listed here** — they come from
the `tls-client` authority, these from `acme`, `est` and `scep` — and this page
links to that one.

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
  `ssf/account_signals.js`. It signs nobody in: the page links to `/portal`,
  where the ordinary sign-in happens with the new password, for
  `/portal/activate`'s magic-link argument.

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
