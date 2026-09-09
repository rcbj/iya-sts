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
| `/portal` | authenticated | **Overview** — who they are, this session, a summary of how they sign in, and the wider sign-out |
| `/portal/applications` | authenticated | **Applications** — where this identity provider will sign them in |
| `/portal/password` | authenticated | **Password** — the form, and the POST that answers it |
| `/portal/keys` | authenticated | **Security keys** — the list, and a Remove per key |
| `/portal/callback` | — | the OIDC redirect URI |
| `/portal/remove-key`, `/portal/signout` | authenticated | the two other POSTs |

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

### There is no launch button, and that is a refusal rather than a gap

This service implements identity-provider-initiated sign-on in none of the four
browser profiles — `/saml2`'s own page lists it among what is not implemented —
so a link from here would have to invent a request the application never asked
for and is not expecting. A sign-in starts at the application. The page says so.

### It is paginated, and the cap is a guard rather than a setting

Twenty rows a page. The scan stops at 1,000 entries and says when it bit: each
entry costs a policy evaluation per distinct kind, on the one thread that
answers every socket this service holds, which is the stall `CLAUDE.md`'s
worker-pool section is about. A configuration row would be a knob nobody turns
until the day the page is already slow.

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

**`/portal/remove-key` is the case worth understanding**, because it takes an id
from the body and is still safe: `credentials.removeKey()` looks that id up
among **the caller's own keys**, so one belonging to somebody else matches
nothing. `tests/portal_access.js` asserts exactly that, in both directions — one
person cannot remove another's key, and can remove their own, so the refusal is
about whose key it is rather than the operation being broken for everybody.

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
portal's OWN session in its own cookie (`sts_mock_portal`).
`common/oidc_rp.js` runs it and argues it.

Three things about it are this directory's:

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

**AND A NEW PAGE IS A NEW PLACE THE RULE HAS TO BE CHECKED**, which is why
`/portal/applications` got an A01 assertion of its own rather than inheriting
section 3's. That section drives `/portal`; a page added later is a page whose
handler nobody has yet looked at. The check is the same shape — the other
person's name in every parameter this page could plausibly have read, and the
page must be drawn for the session's own person and must not name theirs.
