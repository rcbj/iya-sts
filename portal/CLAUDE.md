# CLAUDE.md — `portal/`

## THE FIRST PAGE IN THIS SERVICE THAT BELONGS TO THE PERSON LOOKING AT IT (2026-09-06)

Every browser-facing surface here until now was for somebody else. The sign-in
screen is a step in another protocol's flow. The consent screen asks one
question and leaves. `/admin` is for an operator and is gated on two roles.
**Nothing let a person see what this identity provider knows about THEM, or
change how they authenticate.**

Two routes, and they are not the same kind of thing:

| Route | Who | What |
|---|---|---|
| `/portal/activate` | **unauthenticated** | spending a single-use activation link to set up a credential |
| `/portal` | authenticated | their own information, their password, their security keys |

## It is a separate application from the admin console

Not the shell, not the navigation, not the gate — and that is deliberate. The
console's `respond()` draws a sidebar of forty administrative pages and its gate
asks "does this person hold Admin Read", neither of which is anything somebody
managing their own account should meet.

**What they share is `authn.js`'s session**, because there is one answer in this
service to "who is this browser" and a second would be the thing that eventually
disagrees.

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

## `beginAuthentication()` and not a bare redirect

`requireSignIn()` sends an unauthenticated visitor through
`authn.beginAuthentication()`, exactly as `saml2_sso.js` and `consent_screen.js`
do. This was a plain `303` to `/authn/login` at first **and it does not work**:
that endpoint draws a form for a PENDING AUTHENTICATION RECORD, and a POST
naming no record is answered `This sign-in form has expired`. The portal is not a
protocol, but it needs a session the same way one does.

`returnTo` is a path on this service, which that function requires and refuses
anything else — so the portal cannot be turned into an open redirect.

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
