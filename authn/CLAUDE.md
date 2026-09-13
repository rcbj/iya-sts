# authn/

The authentication service and the WebAuthn relying party. **This is not part of
any protocol**, which is the point of it having a directory of its own rather
than living under `oauth-oidc/` where the screen used to be rendered.

| File | What it is |
|---|---|
| `authn.js` | The sign-in screen, the session store, and the pending-authentication record. |
| `webauthn.js` | The relying party's half of WebAuthn Level 3. |

**A THIRD ENDPOINT LIVES IN `/authn/*` AND IS NOT IN THIS DIRECTORY.**
`/authn/spnego` — sign in with a Kerberos ticket — is
`kerberos/spnego_authn.js`, and the split is a dependency rather than a filing
mistake. This module is #8 in the require order because `oauth2.js` reads the
session it owns; every Kerberos module is #15 and below so that the KDC's routes
are not dragged to the front of the router. A require from here to there would do
exactly that AND close a cycle, since that module needs `startSession()`.

**It needed no inverted hook either**, which is worth saying because rule 3e's
list is six slots long and a seventh is the obvious move. The only two things
this module needs to know are the PATH — declared here, as `SPNEGO_PATH`, in a
space this module already owns — and whether the door is open, which is
`krb5.spnegoAuthentication` and is read from `config.js` by both files. Rule
3e's test is whether a require would close a cycle or move a route; here nothing
has to point anywhere.

**Three exports exist for it and for nothing else**: `SPNEGO_PATH`,
`pendingFor()` (read-only, and it sweeps an expired record on the way past
exactly as it does for the screen) and `completeAuthentication()`. The last is
one function rather than an exported `pending` and an exported
`returnToCaller()` because the two acts are one act — a record left behind is
one somebody can spend twice, and a redirect written at a second call site is a
second place for RFC 9700 section 4.12's 303-not-307 to be got wrong. It takes
no error parameter, deliberately: a Kerberos sign-in that fails draws a page
with the password screen linked from it, because the person can still sign in,
and telling the calling protocol `access_denied` would end a flow that has not
failed.

**`webauthn.js` is here and not in a directory of its own** even though WebAuthn
is one of the sixteen protocol families, because it is the other half of ONE act
of authentication: it shares the pending record, the choice between its two roles
is made at the password screen, and it owns no session of its own. Splitting them
would put the two halves of one ceremony in two places and leave the pending
record crossing a directory boundary for no gain.

**It OWNS THE SESSION.** `ws-federation/wsfed.js`, `saml/saml2_sso.js` and
`admin-ui/admin.js` take it from here through the exported `startSession` /
`sessionOf` / `endSession`, and `oauth-oidc/oauth2.js` reads the session and
never writes one. Do not give any other module a session store to "decouple" it:
two stores would each look correct alone and never see each other, and the
symptom is a sign-on that silently is not single.

**`startSession()` TOOK A SIXTH ARGUMENT FOR FEDERATION, AND IT REPLACED A
DOUBLE-COUNT RATHER THAN ADDING A FEATURE.** This function has always recorded
the authentication ITSELF — that is what makes a WS-Federation sign-in appear on
`/admin/users` without `wsfed.js` knowing the console exists. `../federation/`
broke that assumption in two places at once: `methodPhraseFor()` answers "sign-in
screen (password)" for an `amr` it does not recognise, which is exactly wrong for
somebody who never saw this screen at all, and the attributes a foreign identity
provider asserted have to ride the identity funnel to the directory with no other
way in. The obvious alternative — the caller calling
`stats.recordAuthentication()` and then this — was written first and produced TWO
authentication records for one sign-in, so `/admin/users` counted every federated
arrival twice and the audit log carried a duplicate of each. **A caller passing
nothing behaves exactly as every existing caller did**, which is the property to
keep if this is ever reworked.

**IT REQUIRES `../federation/federation.js`, AND THAT DIRECTION IS THE
ARRANGEMENT RATHER THAN AN ACCIDENT.** The sign-in screen offers a button per
usable federation partner (`federation.loginButtons`), because a person standing
at this screen is in the middle of SOMETHING — an authorization request, a
`wsignin1.0`, an `AuthnRequest`, the console — and `record.returnTo` is that
something, whole. Handing it to the federated flow is what lets a foreign
identity provider satisfy any protocol this service speaks.

The require goes to the REGISTER and never to `federation_sp.js`: that module
requires THIS file — it has no sign-in screen of its own and calls
`startSession()` directly — so a require back would close a cycle. The register
in the middle is what both halves can safely reach, and it registers no route, so
nothing about requiring it can move one. The call is wrapped: **the sign-in
screen is the last thing in this service that may fail to draw**, so a register
that throws costs the buttons and never the password field underneath them.

**FOUR DOORS END A SESSION AND `dropSession()` IS THE ONLY PLACE ONE STOPS
EXISTING.** `/oauth2/logout`, WS-Federation's `wsignout1.0`, SAML 2.0's
`/saml2/slo` and the protocol-independent `/logout` are four protocols' words
for one act. Two functions sit over that one body and the split is what the
callers need rather than a refactor:

* `endSession(req, res)` reads the cookie and clears it — the browser's own
  sign-out.
* `endSessionById(id, via)` names a session the caller has no cookie for, which
  is every session `/logout` and `/admin/logout` end that is not their own.
  `clearSessionCookie(res)` is exported beside it so that a caller ending its
  OWN session through the list can still drop the cookie.

**What `dropSession()` does BESIDES the delete is the whole reason it exists**:
the RFC 9700 section 2.2.2 refresh revocation, and the single `session.end`
audit row. A `sessions.delete()` anywhere else would be a sign-out that revoked
nothing and logged nothing, and from the outside it would look identical. That
is also why both functions RETURN the session as it was: the federated lists a
sign-out has to fan out to — `wsfedRealms`, `saml2ServiceProviders`,
`oidcClients` — live on the object being discarded.

`sessionsOf(username)` and `sessionById(id)` are the readers `/logout` needs to
draw a row for a session that is not the caller's. Neither expires anything:
`sessionOf()` stays the one that reads the cookie and sweeps what it finds
expired, because an observer that quietly ended sessions while reporting on them
would be changing the thing it describes — the same rule `audit.js`'s actor
resolver follows.

## `consoleSession()` — the one reader that crosses a realm boundary, and the ADMIN CONSOLE is its only caller

The session store is `realms.map()`, so `sessionOf()` answers out of the ambient
realm's partition and a session minted in `acme` does not satisfy the default
realm's `/oauth2/authorize`. That is right, it is what `realmSupport()` promises,
and it does not change.

**What changed is that the console asks a different question, and it had to,
because of a fact about the COOKIE rather than a change of mind about realms.**
`startSession()` writes `sts_session` at `Path=/` — one name, one path, for
every protocol here, deliberately and for a reason that predates realms by
months. So a browser holds exactly ONE session id for this whole origin whatever
realm minted it, and the console's realm switcher (a link to the same page in
another realm) was not merely landing on the sign-in screen: signing in there
OVERWROTE the only cookie slot the browser has, so switching back landed there
too. **One sign-in per click, forever, with nothing expired and nothing
misconfigured** — the two realms were taking turns holding one cookie.

The function that fixed that was `sessionAnywhere(req)`: it asked the ambient
realm first, through `sessionOf()` so the common case was byte-for-byte what it
had been, and then every other realm's partition by name. **It is
`consoleSession(req)` now and it asks ONE realm** — the default — and the
paragraph below says why the change was forced rather than tidied. It still
returns `{ session, realm, foreign }`, and it still sweeps an expired session
out of the realm that holds it exactly as `sessionOf()` does.

**THE FUNCTION IS `consoleSession()` AND IT ANSWERS "THE DEFAULT REALM'S", NOT
"ANY REALM'S" — and the paragraph below this one used to say the opposite.** The
old argument was explicit about its own premise: *the authorization behind it was
never per realm, because Admin Read and Admin Write are groups in the ONE shared
directory, so `rbac.rolesOf()` returns the same answer in every realm.* **That
premise became false on 2026-08-25**, when the embedded directory became a
subtree per realm. Each realm has its own `ou=groups` now, so a session minted in
`acme` still opening the console would mean anybody who can create a realm can
grant themselves both roles inside it and walk back out into the default one —
the realm feature would have become a privilege escalation.
`ldap/ldap_server.js` pins `admin_rbac.js`'s whole directory to the default realm
for that reason, and this function is the other half of the same decision. **The
two have to agree**: a gate that accepted an `acme` session while the roster
could only name default-realm people would let somebody in and then insist they
were nobody.

**Two things make this the boundary already drawn rather than a hole in it, and
both have to stay true if anything here is reworked:**
* **It grants nothing else.** `gateStateFor()` in `admin-ui/admin.js` is the only
  caller, and the only thing it answers is "may this browser read this console".
  No token is issued on the session it finds and no assertion names it. Every
  protocol module still calls `sessionOf()` and still sees its own realm's
  partition only.
* **Ending it still ends it.** What comes back is the one object in whichever
  realm's map holds it, so `/logout`, `/admin/logout` and an expiry sweep in the
  owning realm all shut the console with it. There is nothing separate here to
  end.

**Do not give a second caller this function by analogy.** The test it passed is
the one in the first bullet — that the decision it feeds is already realm-shared
— and there is exactly one such decision in this service. A protocol endpoint
reaching for it would be single sign-on across realms, which is the thing a realm
exists to refuse.

The console SAYS which realm holds the session when it is not the one being read,
on the banner and beside the switcher. Showing it silently is how somebody comes
to believe the realms share the rest of it as well, and the next thing they
conclude is that `/oauth2/authorize` would have taken the same cookie.

---


**`authn.js` is the authentication service, and it is not part of any protocol.**
The sign-in screen used to be rendered inside `GET /oauth2/authorize`: no session
meant a 200 with the login form in the body, at the authorization endpoint's own
URL. It is now its own endpoint and its own module, and the protocol endpoints
send people to it:

```
GET /oauth2/authorize (no session)
    -> 302 /authn/login?authn=<id>          the request is stashed with a
                                            return URL built from its own query
    -> the screen; POST /authn/login        the session cookie is established
    -> 302 back to /oauth2/authorize?<the original query, minus prompt>
    -> the session is there this time, so the response goes out per spec
```

Four things about that are load-bearing:

* **The service knows nothing about OAuth.** It never reads `client_id` or
  `redirect_uri`. What the screen shows about the request it interrupted arrives
  as `details` rows the CALLER wrote, because only the caller knows what its own
  parameters mean — the `issuer_state` note, for one, which says whether the
  request came from a Credential Offer this issuer actually made.
* **A refusal comes back rather than being answered there.** Cancel returns to
  the caller with `authn_error=access_denied`, and the caller turns that into
  its own protocol's refusal. `redirectBack()` in `oauth2.js` knows about
  `response_mode`, and in `form_post` the answer is not a redirect at all but a
  self-submitting form — protocol knowledge stays in the protocol module. The
  authorization endpoint checks for that parameter BEFORE it checks the session,
  or a refusal would be answered by sending the person straight back to the
  screen they just declined.
* **`returnTo` is checked to be a path on this service.** It is built by the
  caller and never read off the query string, and it is checked anyway: an
  authentication service that will redirect a browser to an arbitrary URL after
  signing somebody in is a credential phishing tool with a login screen in front
  of it.
* **It owns the SESSION**, and `wsfed.js` and `admin.js` take it from here.
  `oauth2.js`'s old note said the session lived there "because this module owns
  the login flow the session comes out of" — which is exactly the sentence that
  moved it, now that the login flow has. `oauth2.js` reads the session and never
  writes one. The WebAuthn second factor moved with it for the same reason: it
  is the other half of one act of authentication, and it shares the pending
  record.
* **WEBAUTHN IS TWO ROLES ON ONE SCREEN and the ceremony cannot tell them
  apart.** `use_webauthn` is the second factor after a password (session
  `amr ["pwd","hwk"]`, `acr "mfa"`); `webauthn_only` is the PRIMARY credential
  with no password read at all (`amr ["hwk"]`, `acr "1"` — ONE factor, since
  the ceremony asks for user verification as `preferred` rather than
  `required`). Four things there are load-bearing. The choice is made at the
  password screen and CARRIED on the pending record, because the ceremony's own
  POST is the browser's result and nothing in it says what somebody chose a
  screen ago. `webauthn_only` WINS where a hand-made POST sets both, since the
  boxes cannot be made exclusive on a screen that runs no script. A caller that
  demanded a second factor (`forceMfa`, from `acr_values`) is refused the
  passwordless path SERVER-SIDE — `disabled` is a property of a browser and not
  of a request. And `methodPhraseFor()` exists because there are three outcomes
  now: the two-way conditional it replaced asked whether `hwk` was present and
  called a passwordless sign-in a password one. Anything downstream that reads
  `hwk` to mean "two factors" is wrong for the same reason — `wsfed.js`'s
  `authnMethodsFor()` was, and now tests for `hwk` AND `pwd`.

---

## THIS MODULE KEEPS NO CREDENTIAL STORE, AND FOR FOUR DAYS IT KEPT THE WRONG ONE (2026-09-10)

`webauthnCredentials` was a `realms.map({ persist: 'authn.webauthnCredentials' })`
holding ONE key per person. It survived a restart and it was still the wrong
store, because **`common/credentials.js` already held the security keys** — on
the person's own directory entry, multi-valued, each carrying the ROLE it was
enrolled in. That is the store `mechanismsFor()` reads, and `mechanismsFor()` is
what `/portal/keys`, `/admin/users`, `removeKey()`'s last-way-in refusal and
this module's OWN `mfaRequired` check all consult.

**`credentials.addKey()` had no caller anywhere in the service.** So the second
store was not merely a duplicate; it was the only one being written, and the one
everything READ was empty. What that cost:

| | |
|---|---|
| `mechanismsFor().mfaKeys` | `0` for everybody, for ever |
| `mfaRequired` from a key | never true |
| the second sign-in | **a password alone**, box unticked, no second factor asked for |
| `GET /authn/webauthn` | its own gate refused everybody |
| `/portal/keys` | listed and removed keys that could not exist |
| `/portal/activate`'s key choice | spent the link, said "your account is ready", enrolled nothing |

**THE BYPASS IS THE THIRD ROW AND IT IS WHY THIS IS A SECURITY FIX RATHER THAN
A TIDY-UP.** Enrolling a key was an opt-in that lasted one sign-in. Anybody who
knew the password signed in without it — and the account looked, on `/portal/keys`,
exactly like an account with a second factor on it.

### What it is now

Three changes and one deleted map:

* **`webauthnPage()` draws from `credentials.keysOf()`**, filtered to the role
  the pending step is about, so `mode` is an ASSERTION for anybody who holds a
  key of that role and `allowCredentials` is a LIST — a person may hold several
  and the specification has expected that since Level 1.
* **The registration branch calls `credentials.addKey()`** with the role off
  `step.passwordless`, after seeding the entry — the order is load-bearing now,
  because that function writes an ATTRIBUTE and answers "there is nobody called
  that in this realm's directory" when there is no entry. **A refused write is
  a refused ceremony**: the old code could not fail (a map takes anything), and
  reporting success on a credential that was not recorded would sign somebody
  in with a key that will not work next time. It is also where the
  `webauthn.*` policy finally bites.
* **The assertion branch picks the key by `keyForAssertion()`**, on the role AND
  the credential id the browser named. `allowCredentials` is a hint to the
  browser; that function is the enforcement. The counter goes back through
  `credentials.noteKeyUsed()`, which is the one place it is recorded.

### `keyForAssertion()` is a function because it is a rule, and because of a mutant

A `primary` key must not answer a SECOND-FACTOR step: it signs somebody in on
its own, so accepting one there would let a person satisfy *a password AND a
second factor* with a credential this service already considers sufficient by
itself.

It is EXPORTED, for one test and no caller. The state that makes it worth
asserting is one person holding TWO keys — the only shape that tells *check the
one the browser named* from *check the first one you find* — and **no door in
this service can build it**, because the sign-in screen's checkbox is the only
enrolment there is and it is reserved for people who hold no second factor yet.
`tests/webauthn_policy.js` builds it through the credential layer. That mutant
survived the over-HTTP job, which is the third time this repository has recorded
*a surviving mutant is telling you about the fixture*.

### What is still missing, and it is a door rather than a store

**There is no way to enrol a SECOND key, and `/portal/keys` and
`/portal/activate` still cannot enrol a first one.** A WebAuthn ceremony needs
script, every page of the portal is `script-src 'none'`, and the six-scripted-pages
rule says a seventh needs its own argument made from scratch. Until that is
done: `webauthn.maxKeysPerPerson` cannot be exceeded because it cannot be
reached above one, the multi-key `allowCredentials` list is exercised by no
door, and the activation flow's *a security key instead of a password* still
records an intention and produces no credential — which is a link spent on an
account nobody can sign in to.

## `setSessionObserver()` — the one INVERTED HOOK this module offers

Added 2026-09-03 for the CAEP profile. `ssf/caep.js` needs to know when a
session starts, is presented and ends, because that is what a CAEP event is
*about* — and it cannot be required from here: this module is **8** in
`server.js`'s require order and `ssf/ssf.js` is **23b**, so a require the other
way would register every `/ssf` route here, ahead of `oauth2.js`, ahead of the
admin console, ahead of ldap, scim and spiffe. That is rule 1, and it would
close a cycle besides. So this module holds a function and `ssf/ssf.js` fills
it at its own require time, exactly as `admin.setSignalsReporter()` works one
layer up.

**It is advisory, and `notifySession()` swallows everything the observer
throws.** The reason is the one `audit.js` gives about its actor resolver: the
observer is a nicety and the sign-in it decorates is real work. A Shared
Signals transmitter that cannot build an event must not be able to turn a
working sign-in into a 500 — and that is reachable, because building one signs
a JWS and pushing one dials out to somebody else's endpoint.

**It is also fire-and-forget.** Nothing waits for it. A sign-out that blocked
on a receiver's TCP timeout would be a sign-out that hangs, and the person
signing out has nothing to do with whether a receiver is up.

### Three call sites, and the flag that keeps the third honest

| Where | Kind |
|---|---|
| `startSession()`, last, after the cookie and the audit row | `established` |
| `oauth-oidc/oauth2.js`'s authorization endpoint, through `notePresented()` | `presented` |
| `dropSession()`, after the delete and before the audit row | `revoked` |

`revoked` fires **after** the session is out of the store and **before** the
audit row, which is the only order that works: the observer needs the session
as it *was* in order to name the subject, and emitting while the session was
still in the store would be a transmitter telling a receiver to stop trusting
something this service still honoured.

**`notePresented()` drops the FIRST presentation of a brand-new session**, and
without that the feature would be noise. Every sign-in here ends with the
browser coming back to the authorization endpoint, which *is* a presentation —
so the simplest possible flow would report `established` and `presented` a few
milliseconds apart, every time, and the event that is supposed to mean *single
sign-on happened* would mean nothing. `startSession()` sets
`firstPresentationIsTheSignIn` on the session and `notePresented()` spends it,
which is exact rather than a time window.

It is **not** called from `sessionOf()`, which looks like the obvious place and
is not: that function is called several times per request, so an event there
would be several events for one act.

## It checks no password

## TWO KINDS OF BROWSER SESSION, ONE STORE (2026-09-06)

`/admin` and `/portal` are OpenID Connect relying parties of this service's own
authorization server now, so this module holds two kinds of browser row:

| | Created by | Cookie | Read by |
|---|---|---|---|
| SIGN-ON | `startSession()`, at the screen or any other credential | `sts_session` | `/oauth2/authorize`, `/wsfed`, both SAML profiles — every protocol family |
| RELYING PARTY | `startRelyingPartySession()`, from a verified ID Token | `sts_admin`, `sts_portal` | the surface that minted it, and nothing else |

**They are one store because rule 3m says so** — `logout.js` reads this map,
`/admin/sessions` draws it, CAEP observes it, and a second register would be a
second answer to "is somebody signed in" with the wrong half being whichever
surface a reader happened to open. It is the same arrangement the KEYED API
sessions already have: told apart by a FIELD (`rpSurface`) rather than by a
store of their own.

Four things about a relying-party session:

* **IT IS NOT AN AUTHENTICATION AND NOTHING RECORDS ONE.** The person
  authenticated at the authorization endpoint and `startSession()` counted it
  there. A second `recordAuthentication()` would double every console sign-in
  on `/admin/users` — the defect `federation_sp.js` shipped once and the reason
  `startSession()` has a sixth argument.
* **IT NAMES THE SIGN-ON SESSION IT CAME FROM AND DIES WITH IT.** The cascade
  is in `dropSession()`, the one place a session ends, so every door that ends
  one ends the sessions derived from it. `relyingPartySessionOf()` also checks
  the parent on every read, because a cascade reaches only the store it walks
  and "the person signed out" is exactly the case that matters.
* **IT IS NOT EXTENDED BY USE** and expires when its parent would.
* **ENDING ONE DOES NOT END THE PARENT.** That is the direction a real relying
  party has: sign out of the application and the identity provider still knows
  you, so the next visit is silent. `/logout` is what ends everything for an
  identity — **and it is why each surface's own Sign out button ends BOTH**
  (2026-09-06): `POST /admin/signout` and `POST /portal/signout` end the
  relying-party session and then call `endSessionById()` on the parent, because
  a button that ended only the first would be a sign-out whose next click signs
  the person straight back in through the code flow with nothing typed. Those
  two handlers are the only callers that end a parent on purpose;
  `admin-ui/CLAUDE.md` and `portal/CLAUDE.md` argue them.

## `clearSessionCookie()` TAKES A NAME AND APPENDS (2026-09-06)

Two changes to four lines, and the first was a live bug found by writing the
Sign out buttons rather than by reading anything:

* **IT IGNORED THE COOKIE NAME IT WAS ALREADY BEING PASSED.**
  `oidc_rp.js`'s `endSessionFor()` has called
  `authn.clearSessionCookie(res, surface.cookie)` since the day it was written,
  and this function took one argument — so a hosted surface signing somebody
  out cleared the SIGN-ON cookie and left its own in place. The symptom was
  mild and misleading, which is why it survived: `relyingPartySessionOf()`
  refuses a cookie naming a session that is gone, so the surface looked signed
  out while the browser went on presenting a dead id and the provider's cookie
  disappeared instead of the application's.
* **IT APPENDS RATHER THAN SETS.** A sign-out on a hosted surface clears TWO
  cookies on one response — the surface's own and the sign-on session's — and
  `res.set('Set-Cookie', …)` REPLACES the header, so the second clear threw the
  first away. `setCookieHeader()` is deliberately left as a SET: a set is one
  cookie per response, and making it append would put a rotated session id on
  the wire beside the one it replaced with the browser free to keep either.

`consoleSession()` still exists and still has one caller — the console REPORTS
the sign-on session behind its own; it is no longer what lets anybody in.

* **It checks no password.** The username typed at `/authn/login` becomes the
  identity in every token and every assertion — for every protocol, since
  2026-08-26, when WS-Federation gave up the screen of its own that used to post
  to `/wsfed/login` and started arriving here through `beginAuthentication()`
  like the other three browser SSO profiles.

One password IS rejected, here and in three other places:

* **One password is rejected** — the literal string `invalid` on the password grant,
  on WS-Trust and at the WS-Federation sign-in screen — so a negative test has
  something to fail on in every protocol here.

## `beginAuthentication()` does not always answer with this module's screen

Since 2026-08-26 it takes an `application` — the identifier the caller's own
protocol presented, a `client_id` from `oauth2.js`, an entityID from
`saml2_sso.js`, a relying party id from `saml11_sso.js` — and what comes back
is now one of FOUR things:

| What the entry names | What comes back |
|---|---|
| ONE usable relationship, auto-redirect on | `/federation/login/{id}` — the partner, directly |
| SEVERAL usable, auto-redirect on | `/authn/select-idp?authn={id}` — the CHOOSER |
| the mechanism `spnego` | `/authn/spnego?authn={id}` — the KERBEROS DOOR |
| anything else | `/authn/login?authn={id}` — this module's screen |

**The caller cannot tell them apart and must not.** What a protocol module
asked for is "get this person authenticated and bring them back to `returnTo`",
and which identity provider does the authenticating — or whether the person was
asked which — is not its business. That is the property the partner buttons at
the foot of the screen have had all along. What changed is first that nobody
has to press one, and then that where there IS a choice it is between THIS
APPLICATION'S partners rather than every relationship in the register.
`federationFor()` is the whole of it, and its header carries the four checks
and why each is made at the READ rather than at the write.

**No pending record is SPENT on the first path**, and that is not an
optimisation: the browser goes to a foreign identity provider and comes back to
`/federation/acs/{id}`, which finishes the sign-in through `startSession()`
without this screen ever being drawn. A record minted there would be one nothing
could ever spend. The CHOOSER is the opposite case — it draws a page, so it
needs the record, and it reads the same one the screen would have, out of the
same store and with the same ten-minute expiry.

**THE KERBEROS DOOR IS ALSO THE OPPOSITE CASE, and for a different reason worth
knowing rather than looking like an inconsistency.** `/authn/spnego` never
LEAVES this origin: the 401 and the token are one URL fetched twice, the record
is what carries `returnTo` across those two fetches, and it is also what the
fallback link on every page of that door points back into. That is why the door
takes an `?authn=` and no `returnTo` of its own — there is no open-redirect
surface on it at all.

### The Kerberos branch, and what it loses to `forceMfa`

`mechanismFor()` can now resolve to `spnego`, from either source, and
`beginAuthentication()` then redirects to `/authn/spnego?authn={id}` instead of
drawing anything. **It loses to `forceMfa` and says so at INFO**, exactly as
`forcePasswordless` does and for the identical reason: a ticket claims whatever
its own flags claim — `amr ["pwd"]` for `pre-authent`, `["hwk"]` for
`hw-authent`, both for both, nothing for neither — so it cannot be PROMISED to
answer a caller that demanded two factors.

What that costs is not nothing and is worth stating: somebody at a domain-joined
machine holding a perfectly good hardware-backed ticket is sent to a password
box. The alternative is to send them to the door and find out — and the door
cannot refuse at that point, because by the time the flags are readable the
ticket has been accepted and the only options left are to mint a session
claiming one factor or to throw away a successful authentication. Refusing to
PROMISE is the honest half of that, and the button on the screen is withheld
under `forceMfa` for the same reason.

### `appAuthnMechanism` — the generalisation of `appFederationRelationship`

An application entry may now DECLARE how its people authenticate, from the same
closed vocabulary `fedAuthnMechanism` uses (`federation.MECHANISM_IDS`). One
table for both, because they answer the same question from two sides, and two
tables would have drifted the first time either grew a value.

It exists because `spnego` had no way of being asked for: the pair beside it can
say "send my people to a federated identity provider" and cannot say "my people
hold Kerberos tickets", which is the commonest integrated-authentication
deployment there is.

`declaredMechanismFor()` reads it, and three properties are load-bearing:

* **An empty value is not `password`** — it is "this entry says nothing". Every
  entry in the field holds an empty one, so reading it as an explicit "use the
  screen" would have switched off every `appFederationRelationship` in existence
  in one commit.
* **`federation` falls through to the list**, because it IS what naming a
  relationship already implied, said out loud. Declaring it while naming nothing
  usable is REPORTED rather than falling quietly back to a password box.
* **The checks are made at the READ**, for `federationFor()`'s reason exactly:
  it is a string on a directory entry that `ldapmodify`, the console and the
  management API can all reach, and the setting that decides whether `spnego`
  will work is settable at runtime. A check made at the write would be a check
  about the past — and `spnego` declared while `krb5.spnegoAuthentication` is
  off is exactly the state that would otherwise put somebody in front of a 403
  halfway through a sign-in.

### `/authn/select-idp`: the chooser, and why it is not the screen with its form hidden

An entry may name SEVERAL relationships — `appFederationRelationship` is
multi-valued since 2026-08-26 — and they need not share a protocol: a SAML 2.0
partner and an OpenID Connect one are the ordinary pair. When more than one of
them is usable there is a question to put to the person, and
`federationFor()` deliberately returns NO single `relationship` in that case,
so the redirect branch above cannot fire and pick the first partner for
somebody.

**It is a page of its own.** The alternative was this module's own screen with
its form suppressed, and that was refused: that page carries `username`,
`password`, `kc-login` and `kc-cancel`, it POSTs to a handler that signs
somebody in on a typed name, and every one of those element ids is what four
tests and a person's muscle memory look for. Hiding the form leaves a page that
is a sign-in screen in everything but what it shows — and the first time
somebody re-added a field to it, the chooser would grow a password box nobody
asked for.

**`appFederationAutoRedirect` still decides whether a SCREEN is drawn.** It
means what it always meant — "without the sign-in screen" — and with several
partners that is this page, which is the screen's job done without the screen.
FALSE with several named is therefore the screen itself, with one button per
partner under the password box, exactly as FALSE has always behaved with the
partners plural. What the setting never means is "pick one for them": there is
no value of a boolean that can say which identity provider somebody's employer
is.

**The unusable values are PRINTED there, one banner each.** A list of three
whose middle value names a disabled relationship draws two buttons, and two
buttons is exactly what a correct list of two draws — so the difference has to
be said in words, and each is a different entry for an operator to go and fix.

**The list is resolved AGAIN when the page is drawn**, not taken from the
redirect that produced it, and the record's copy is replaced with the answer.
The record lives ten minutes and the register has four doors; a relationship
disabled in between would otherwise be a button leading to a refusal at a
foreign service. If fewer than two partners are left, the screen is drawn
instead — and because the record was updated, the screen agrees with what the
chooser just found.

**There is no "none of these" escape**, deliberately. This page is reached
because an application was configured to authenticate its people elsewhere, and
an escape hatch to the password box would be that configuration meaning
nothing. Every relationship being unusable is the one case where this page is
not drawn at all: `federationFor()` reports no usable partner and the screen
appears with the problems on it.

**It is the ONE branch that draws no page that has to say so in the LOG.** With
the auto-redirect on and exactly one usable value, an entry naming three
partners of which two are disabled works perfectly and shows nobody anything —
so `beginAuthentication()` logs the other values' problems at INFO. There is no
banner to put them on and the flow succeeding is exactly why nobody would go
looking.

**`returnTo` is checked twice, here and again in `federation_sp.js`**, which
that module's decision 4 already argued for its own reasons. Two checks on one
value is deliberate: this one catches a caller's bug and that one catches
somebody handing the federated entry point a `returnTo` of their own.

### The screen's partner list, and the one setting it deliberately ignores

`federatedOptionsHtml()` has two halves now. An application that NAMES
relationships gets THOSE partners and only those — offering the rest of the
register beside them would put the discovery step back one line below the
configuration that narrowed it — and that half **ignores
`federation.loginButtons`**, which the generic list still respects.

**All of them, not the first.** The attribute holds a list, and this screen is
what a person meets when the auto-redirect is OFF — which is precisely the
configuration that says "let them choose". One button for a list of two would
make that setting mean the opposite of what it says.

The asymmetry is the point rather than an oversight. That setting exists so
that a service with no federation configured has a sign-in screen byte for byte
the one it always had, and an application whose entry names a partner *is*
federation configured. The auto-redirect above cannot consult a screen setting
either — it never draws a screen — so honouring it here would make one
configuration behave two ways depending on an unrelated boolean.

`federatedButtons()` renders both lists, because two copies of an anchor
carrying a `returnTo` is two chances to drop the `returnTo` from one of them,
which produces a federated sign-in that succeeds and lands the person on a page
nobody asked for.

## `mechanismFor()` — the TWO places a sign-in can be redirected from, and the one order

`federationFor()` above is no longer the only thing consulted, and the honest
way to describe the change is that this module now has to arbitrate. Since
2026-08-26 an identity-provider-side federation relationship may carry
`fedAuthnMechanism` — `password`, `password-mfa`, `webauthn`, `spnego` or
`federation` —
which says what this service does when THAT PARTNER asks it to authenticate
somebody. See `federation/CLAUDE.md`, where the attribute is argued.

The two answer different questions, which is why both exist:

* a **relationship** answers "a partner has sent somebody here; what do I do?"
* an **application entry** answers "where do this application's people sign
  in?" — in TWO attributes since 2026-08-26, `appAuthnMechanism` (the explicit
  statement) read before `appFederationRelationship` (the implicit one)

`mechanismFor()` is the ONLY function that reads both, and it reads them in one
order: **the relationship first** (it is the more specific statement — an entry
under `ou=applications` may be a federation partner AND an ordinary OAuth
client, registered by two different people), then the application entry's
`appAuthnMechanism`, then its `appFederationRelationship`, and the screen last. Nothing else in this service may consult either directly, because
two orders is no order.

**An empty mechanism is not `password`.** `authenticationFor()` returns `null`
for a relationship that declares none — which is every relationship created
before the attribute existed — and this function then behaves exactly as it did
when `federationFor()` was the whole of it. That is the entire compatibility
argument, and it is why the empty case returns null rather than a default.

### `forcePasswordless`, and why nothing a caller passes can set it

`forceMfa` is a demand the CALLING PROTOCOL made — a `RequestedAuthnContext`, a
`wauth` — and it arrives in `opts`. `forcePasswordless` is a mechanism an
OPERATOR configured, and it arrives from the register; there is deliberately no
`opts.forcePasswordless`, because a caller asking for a passwordless sign-in is
a caller choosing somebody else's authenticator for them, which is a deployment
decision and not a request parameter.

**When both would be on, `forceMfa` wins and says so at INFO.** Passwordless
WebAuthn is `amr ["hwk"]` and ONE factor, however phishing-resistant it is, and
one factor does not answer a request for two. They cannot both be on from the
register — one enum value, one mechanism — so the collision is always
protocol-versus-configuration, which is exactly the case where the protocol's
demand is the one that must not be quietly downgraded.

### The hidden input is not the enforcement

`loginPage()` renders a hidden `webauthn_only` when the mechanism demands one,
and `use_webauthn`/`webauthn_only` are drawn `checked disabled` so a person can
see what has been decided for them. **None of that is a control.** A disabled
checkbox posts nothing and a hidden one is deleted by anybody with the
developer tools open, and the POST that arrives then looks exactly like an
ordinary password sign-in — so `handleLogin()` reads `record.forcePasswordless`
as well and the record wins. A configured mechanism a client can opt out of is
not a mechanism.

### `record.mechanismProblem`, beside `record.federation`

Both sources report an unusable relationship as a `problem` string, and the
screen prints it rather than falling silently back to the password box. **Every
one of them, deduplicated.** The attribute holds a list, so an entry naming
three partners of which two are disabled has two things wrong with it — showing
one would have somebody fix it, reload, and meet the next. They overlap by
construction, though: when the application entry is what decided the sign-in,
`mechanismFor()` copies that entry's FIRST problem onto the record, so a plain
concatenation prints it twice and reads as two faults. They
fail DIFFERENTLY, though, and that is why the problem is carried on the record
and not only inside `federation`: an application entry naming an unusable
relationship still produces a `federation` object to hang it on, while a
BROKERING relationship whose onward partner is disabled produces no such object
at all — there is nothing usable to describe. Reading it from one place is what
stops the second case being the silent fallback the first was made loud to
prevent.

### `usableServiceProvider()` is federation.js's, and used to be written out here

The four checks `federationFor()` makes on a relationship id — it exists in
this realm, it is service-provider-side, it is enabled, it is fully configured
— are now one function in `federation/federation.js`, because
`fedAuthnRelationship` gave them a second caller. **`usableServiceProviders()`
beside it is the same four over a LIST**, and it is a function rather than a
`map().filter()` here for one reason: it KEEPS the unusable rows with the
sentence written about each. Filtering them out at the call site is what makes
a list of three with one disabled indistinguishable from a correct list of two. A relationship id on an
application entry and one on another relationship are the same string,
checkable the same four ways, and two implementations of "would this actually
work" would answer differently the first time one of them learned a fifth.

---

## THE SECOND SECOND FACTOR, AND THE DAY `mfaRequired` STARTED MEANING SOMETHING (2026-09-10)

RFC 6238 one-time codes. `/authn/totp` is the screen, `common/totp.js` is the
mechanism and `common/credentials.js` holds the enrolment; this file's part is
the two things a sign-in has to decide — **whether a second factor is demanded,
and which one**.

### The bug that was not a bug until something read the flag

`credentials.mechanismsFor()` has reported `mfaRequired` since the portal was
written. `/portal/keys` drew it as *a password alone will not sign you in*.
**Nothing at this door read it.** A person who had enrolled a security key in
the `mfa` role signed in with a password and an unticked checkbox, exactly like
somebody who had enrolled nothing — so the sentence on that page was a
description of an intention rather than of the service.

That was invisible for the same reason the `ALL_AUTHENTICATED_USERS` defect was:
the only way to reach the second-factor path was to TICK THE BOX, and every test
that exercised it ticked the box. Nothing ever asserted the negative — that
somebody who had enrolled one could not get in without it — because until there
was a mechanism that could be enrolled without a browser ceremony, writing that
test meant driving WebAuthn.

**The order in `handleLogin()` is now: the passwordless path, then WHAT THIS
PERSON HOLDS, then the checkbox.**

| The person | What they ticked | What is asked for |
|---|---|---|
| holds nothing | nothing | nothing — one factor, as before |
| holds nothing | `use_webauthn` | the ceremony, which ENROLS on first use |
| holds an `mfa` key | anything | the key |
| holds an authenticator app | anything | **the code** |
| holds both | anything | the key, with a link to the code |
| holds a `primary` key | `webauthn_only` | the passwordless ceremony, unchanged |

### The checkbox cannot override an enrolment, and here that is a bypass

`record.forcePasswordless`'s argument, read a second time: *a configured
mechanism a client can opt out of is not a mechanism*. It matters more here
than there, and the reason is the enrolment-on-first-use behaviour of the
security-key screen. If the box still won, somebody who knew a TOTP user's
password could tick it, register a brand new authenticator of their own, and be
signed in having never met the second factor the account is configured for.
That is not a weaker second factor; it is none.

**What it costs is worth stating rather than discovering.** Somebody who
already holds a second factor **cannot enrol a SECURITY KEY at this screen any
more** — the box is what enrolment goes through, and it is now reserved for
people who hold no second factor yet. The other two doors are unaffected: an
activation link enrols a key, and `/portal/mfa` enrols an authenticator app.
That person's own row under `/admin/users` is where an operator clears a factor
so that somebody can enrol a different one — it was `/admin/mfa` for a few hours
on 2026-09-10, and `admin-ui/CLAUDE.md` records where the two halves of that page
went.

### One pending register for both mechanisms

`pendingMfa` carries a `factor` and an `alternate` now and there is no second
map beside it — rule 3m, read as it is everywhere else here: a second store
would be a second answer to *is there a sign-in waiting for a second factor*,
and the wrong half would be whichever screen a reader happened to open.

`alternate` is resolved when the step is MINTED and not when a page is drawn,
which is what stops the *use a code instead* link offering a mechanism the
person has not got. Both screens now have a GET as well as a POST for exactly
that link, and **each of them checks that the person really holds the factor it
is about to draw** — a link is markup, and a hand-made GET of
`/authn/webauthn?mfa=…` must not reach the ENROLMENT ceremony for somebody
whose account is configured for an authenticator app. That is the bypass above,
arriving through a different door.

### The code is checked for real, and this screen is the second SPNEGO

`common/totp.js`'s header carries the argument at length and it is the one
`kerberos/CLAUDE.md` already makes: Kerberos cannot be permissive because the
password there IS the key, and RFC 6238 cannot be permissive because the code
IS the comparison. A verifier that accepted any six digits would leave no
artifact to inspect, no failure to demonstrate and nothing for a client author
to test their authenticator integration against.

**And unlike a password it costs a tester nothing**, which is the half that
made it easy to decide: the permissiveness elsewhere exists so somebody can
type any name and get a token about it, and here the person has ALREADY been
let in under whatever name they typed. The code is checked against a secret
this service generated and showed them ninety seconds ago.

### What the session claims, and the fourth branch of `methodPhraseFor()`

`amr ["pwd","otp"]` and `acr "mfa"`. `otp` is RFC 8176's registered value and
its registry entry names RFC 4226 and RFC 6238 by number, so there was nothing
to invent — and `acr "mfa"` is honest here in a way it is not for a passwordless
WebAuthn sign-in: two factors really were presented.

`methodPhraseFor()` grew a branch rather than letting `otp` fall through,
because the fall-through answers *sign-in screen (password)* — which for
somebody who typed a password AND a code is a report that quietly loses the
second factor. That is the identical defect the passwordless ceremony had
before this function replaced the two-way conditional it started as.

### The refusal SAYS which, where the sign-in screen says nothing

The password screen hides whether a sign-in failed for a wrong password or for
a person who holds no credential, because either answer is account enumeration.
**Nothing is enumerable at this door.** The person has already presented a first
factor, so the only new fact on offer is about their own account — and *that
code has already been used* against *that code is not right* is the difference
between waiting thirty seconds and concluding your authenticator is broken.

### Rate limited, and this is the endpoint where it matters most

Six digits is a million values, the window forgives a step either side, and the
comparison is real in both modes — so an unthrottled door here is about one
chance in 333,000 per attempt at somebody's second factor. It uses
`websecurity.attempt('mfa-code', …)`, both buckets, the same pair the password
screen uses. **A refused code redraws the page and KEEPS the step**: mistyping
six digits is the ordinary case, and throwing away a password step that
succeeded would make the commonest mistake the most expensive one. The step's
own five-minute expiry is what bounds the window; the limiter bounds the
attempts inside it.

### There is no enrolment on this screen, which is the whole difference from `/authn/webauthn`

That page registers a key on first use and a session comes out of it. **This one
only ever verifies.** Enrolling an authenticator means being SHOWN a shared
secret, so it has to happen somewhere the person is already authenticated
(`/portal/mfa`) or somewhere a credential authorises it (`/portal/activate`). A
sign-in screen that handed out a shared secret to whoever typed a password would
be a second factor anybody could set up for themselves.

---

## A SESSION THAT RAN OUT USED TO SAY NOTHING (2026-09-04)

Every sign-out door in this service goes through `dropSession()` —
`/oauth2/logout`, WS-Federation's `wsignout1.0`, SAML 2.0 Single Logout,
`/logout`, `/admin/logout` and now `/admin/sessions` — so all of them write the
`session.end` audit row and emit CAEP's `session-revoked`.

**AN EXPIRY DID NEITHER.** It was a bare `sessions.delete(id)` in the two
lookups, so a session that ran out vanished with no audit row and no event: the
receiver that had been told the session was ESTABLISHED was told nothing when it
ended, which is the failure CAEP exists to prevent arriving through the most
ordinary cause there is.

**AND IT WAS WORSE THAN LATE, IT WAS CONDITIONAL.** Both deletions were lazy —
they happen when the session is next LOOKED UP. Somebody who closes the browser
is never looked up again, so nothing ever fired at all, while the same session
sat in the map hours after it had expired, live to anything counting sessions.
That is why this needed a SWEEP and not merely a shared function.

Three things about it are decisions:

* **`expireSession()` is the one place a session ends by running out**, called
  by both lazy lookups and by the sweep. `via` says which noticed it, because
  "it expired and somebody came back" and "it expired and the sweep found it"
  are the same act at different moments and the log should not have to guess.
* **The sweep is armed by the FIRST session this process creates**, and
  `unref()`'d. A process that signs nobody in — the parent project's in-process
  Kerberos jobs, `npm test`, `node env/generate_defaults.js` — never arms a
  timer it would then have to be shut down for. It is the shape of decision the
  worker pool makes about forking nothing until the first post-quantum job.
* **It sweeps every realm and runs INSIDE each one.** The store is
  `realms.map()`, so a bare `forEach` walks the ambient realm's partition and a
  timer has no ambient realm: without `realms.run()` it would sweep the default
  realm's sessions every time and leave every other realm's to accumulate.
  Running in the realm is also what makes the event right rather than merely
  present, since the observer builds a subject from the realm's own issuer.

**THE EVENT SAYS `policy` AND NOT `user`.** `caep.js`'s rule for a `revoked` act
was `admin` when an administrator did it and `user` otherwise, and an expiry is
neither — a lifetime this service configured ran out, which is what CAEP section
2 means by a policy evaluation. Without that this event would have gone out
claiming the person signed themselves out, which is not vague but false. The
notice carries `initiatingEntity` and `expired`, and `reason_user` becomes
"Your session expired" rather than "You have been signed out".

## The session records the protocol it was started through

`startSession()` puts `via` on the session as well as handing it to
`recordAuthentication()` and to the observer. It was in neither place the
session lives, so *what is this session* could only be answered fully by the
CAEP register — which `ssf/ssf.js` fills, and a process without it lost the
answer entirely. `/admin/sessions` reads it off the store that owns the session.

It is the protocol the sign-in came THROUGH and not the only one the session
serves: every browser family here reads this same session, so a row saying
`SAML 2.0` may well be carrying OIDC relying parties too. That is what the
*Carries* column on that page is for, and why the two are drawn separately.

## AN UNAUTHENTICATED SESSION, AND THE THIRD BUTTON THAT STARTS ONE (2026-09-05)

Every session this module held used to be one somebody had signed into. That
was not a policy, it was the only thing the code could produce — and it made
two of the six built-in roles in `common/roles.js` names a policy could match
and nothing could ever hold. `ALL_UNAUTHENTICATED_USERS` in particular was
unreachable at every one of the nine issuance sites.

`authn.unauthenticatedSessions` — **OFF by default** — puts a third button on
the sign-in screen, `Continue without signing in`, and pressing it starts a
real session that records `authenticated: false`.

### It is NOT Cancel, and that is the distinction to keep

Cancel was already there and is untouched: it answers `access_denied` to the
calling protocol and creates nothing. Both buttons are somebody declining to
type a password; only one of them is declining the APPLICATION.

| Button | The flow | The session |
|---|---|---|
| Sign In | continues | authenticated |
| Continue without signing in | **continues** | **unauthenticated** |
| Cancel | ends, `access_denied` | none |

A person who wants out presses Cancel. A person who wants in without saying who
they are presses the middle one, and the flow goes on — tokens may well be
issued, and what the session carries is the fact that nobody authenticated.

### The setting is checked at the DOOR and not only on the page

The page is markup; the endpoint is the door. A form posted by hand with
`action=anonymous` while the setting is off must not mint a session that the
console then lists and that an application's required role is then decided
against. `tests/vendored/sts_roles_builtin.js` posts exactly that form as its
sixth mutant.

### The username in the form is IGNORED, and the principal is stable

Whatever is typed above the button is not read. A session that took the typed
name and called itself unauthenticated would claim two things at once — that
this is somebody in particular, and that nobody proved it — and every
downstream reader would have to decide which half to believe.

`ANONYMOUS_USERNAME` is `anonymous`, exported because the console and the tests
must mean the same string by it. **It is STABLE rather than one per session**,
which is the decision most likely to be undone. A fresh identity each time
would keep the sessions apart on `/admin/sessions` — and it would also seed a
directory entry per session, put a new row on `/admin/users` every time
somebody pressed the button, and leave `anonymous` a name that could never be
granted a configured role, because it would be different by the time anybody
typed it. One entry, many sessions, is the choice `identityKeyOf()` already
makes for everybody else.

It goes through `recordAuthentication()` like any other sign-in, which is what
gives it that entry — but with `method: 'declined'` and a note saying so, so
the funnel counts "an identity was established at a door" without claiming a
credential was checked. `amr` is empty and `acr` is `'0'`: RFC 8176 read
literally, since there are no methods to name.

## THE SIGN-IN GATE ASKED THE WRONG QUESTION, AND IT MADE ONE ROLE UNUSABLE

Found on 2026-09-05 by the first test ever written against the built-in roles.

The role gate at this module's own SESSION door was asked with
`authenticated: false`, and the comment above it argued the case: the session
does not exist yet, so saying `true` would be "flattering the request".

**It was wrong, and the cost was the role.** Look at where that gate runs — the
reserved password has already been refused twelve lines above it, so everything
this mock does by way of checking a credential has happened, and the request IS
the act of authenticating somebody. What has not happened is the SESSION, and
*the session does not exist yet* is a different sentence from *nobody has
authenticated*. The old code collapsed them.

So an application whose `appRequiredRole` was `ALL_AUTHENTICATED_USERS`
**refused every sign-in at this screen** — the one role most likely to be
configured could never be satisfied by anybody, and the refusal named the
person and the role and looked entirely deliberate.

**Why it survived:** `tests/vendored/sts_roles.js` narrows an application to a
CONFIGURED role, and the register answers those the same either way. Only a
built-in role can see the difference. That is the general lesson rather than a
detail about this bug — a computed role and a configured one exercise different
halves of the gate, and a suite holding only the second cannot see the first.

**A refusal here is still the page again with the reason on it**, which is
unchanged and deliberate: `record.returnTo` is a path on this service belonging
to the protocol module that started the sign-in, and bouncing somebody back
into an authorization endpoint that would refuse them a second time is a loop.
That makes this door refuse differently from every other one, which is why
`sts_roles_builtin.js` has a `refusedAtTheScreen()` of its own and asserts both
doors — the screen, and the authorization endpoint for a session carried here
from elsewhere.

## `ISSUANCE.SESSION` IS ASKED AT THE FUNNEL NOW, NOT AT ONE DOOR (2026-09-06)

A session IS an issuance — `ISSUANCE.SESSION` has been in
`common/issuance_gate.js`'s list since it was written — and it was asked at
exactly ONE door: this module's own sign-in screen. **Five other paths minted a
session and never asked**: a federated assertion (`federation_sp.js`), a SPNEGO
ticket (`spnego_authn.js`), a client certificate (`tls_server.js`), a WS-Trust
UsernameToken (`wstrust.js`), and this file's OWN WebAuthn funnel.

So an application narrowed to a role refused a password sign-in and admitted the
same person through any of the five. Federation is where that cost most, for the
reason `federation/CLAUDE.md` gives about its bugs being security bugs: the
person authenticated somewhere else entirely and everything this service knows
about them came out of somebody else's document.

**IT MOVED INTO `startSession()`**, which is the one place a session is created
— the same argument `signJwt()` makes about being the single counter. Five call
sites is four that remember and a sixth added later that does not.

Four things about it are load-bearing.

* **IT REFUSES BY RETURNING NULL AND NEVER BY THROWING.** Two callers —
  `tls_server.js` and `wstrust.js` — wrap this in a `try` that treats a failure
  as bookkeeping which must not break an exchange already completed. That is
  correct for a defect in this function and exactly wrong for a refusal, which
  would be swallowed and the session started anyway. A null is a value they have
  to look at. `tests/api_sessions.js` mutation-tests both halves.
* **`gated: true` IS THE OPT-OUT AND ONLY THIS FILE'S SCREEN PASSES IT.** That
  door asks BEFORE drawing anything, so a refusal is a screen with a reason on
  it rather than a failure half-way through a sign-in; asking twice would be one
  refusal reported in two shapes. The default is therefore SAFE — a sign-in path
  added tomorrow is gated without its author knowing this exists.
* **A SIGN-IN THAT NAMES NO APPLICATION IS STILL ALLOWED**, which is not a
  weakness added here: `issuance_gate.check()` has always allowed when nothing
  named an application, because there is then no requirement to check. It is
  what keeps every existing caller unaffected, and it is why each door passes
  the application it knows about — `record.application` here, `fedApplication`
  in federation, the SPNEGO record's.
* **THE REFUSAL IS AUDITED AS `session.refuse`**, beside `session.start`. A
  sign-in that was refused by policy and one that never happened look identical
  in every other record this service keeps.

**WS-TRUST IS THE ONE CALLER THAT DOES NOT FAIL THE EXCHANGE ON A REFUSAL**, and
that is argued where it is: the RSTR was already permitted in its own right
through `ISSUANCE.WSTRUST_TOKEN`, and the browser session a UsernameToken
exchange also starts is a side effect rather than the product. Refusing the
token there would refuse a credential the policy had just allowed.

---

## A MACHINE ENDPOINT REGISTERED UNDER A FRONT DOOR MINTED AN ARRIVAL SESSION PER REQUEST (2026-09-10)

`ARRIVAL_PATHS` is a list of FRONT DOORS, matched by PREFIX, and its own comment
already names the failure it exists to prevent: *"giving a cookie to a callback
or a metadata fetch would mint a session for a machine that will never send it
back — one row per metadata poll, for ever."* That is why the list is entry
points rather than families.

**A PREFIX MATCH CANNOT PREVENT IT FOR A MACHINE ENDPOINT REGISTERED UNDER A
FRONT DOOR, AND ON 2026-09-10 TWO OF THOSE ARRIVED.** This service's own admin
console and user portal became Shared Signals receivers, each hosting a receive
endpoint at `/admin/signals/receive` and `/portal/signals/receive`. Both are
under a prefix on that list. What arrives at them is `ssf/ssf_http.js` POSTing a
Security Event Token over the loopback interface — a server-to-server request
that carries no cookie, will never send one back, and is answered 202 with an
empty body.

So every delivered event minted an arrival session. **A service telling its own
console about every sign-in minted a second session for every session**, and
the CAEP profile guarantees there is an event per sign-in, per presentation and
per sign-out. They expire on `AUTHN_TTL_MS` and so it is not a leak that grows
without bound — which is the reason it would have gone unnoticed: what it
produces is `/admin/sessions` and `/admin/metrics` carrying rows for a browser
that never existed, in a service whose whole job is to let somebody read those
pages and believe them.

`NOT_ARRIVAL_PATHS` is the fix and it is an exclusion HERE rather than two paths
moved out of `/admin` and `/portal`. The path is what says WHICH RECEIVER a SET
was delivered to, and a receiver's endpoint living somewhere other than the
receiver would be the tidier version of a worse design — `ssf/CLAUDE.md` argues
why a receiver hosts its own endpoint.

**THE TEST FOR A THIRD ENTRY** is the one question: *is this path reached by a
BROWSER that will hold a cookie?* If yes it belongs on neither list and the
prefix already handles it. If no, and it sits under a front door, it belongs
here. Anything else — a metadata document, a callback, a well-known — is
already outside both prefixes and needs nothing.

**IT WAS FOUND BY RUNNING THE SERVICE AND COUNTING**, not by reading either
file. Both comments were correct and neither could see the other.

## `/authn/backup-code`: THE THIRD SECOND-FACTOR SCREEN, AND THE ONLY ONE A SIGN-IN NEVER ASKS FOR (2026-09-10)

A person whose second factor is not to hand — the phone is lost or flat, the
security key is in a drawer at home — types one of the recovery codes they were
issued, and it signs them in once and is spent.

### It is never the factor, and that is a property of the model rather than of this screen

`credentials.mechanismsFor().secondFactor` answers `webauthn` or `totp` and
never this, and `mfaRequired` is deliberately not true of somebody who holds
only a set. So the ONLY way here is a link out of one of the other two screens,
carrying a step id they already hold: `pendingMfa`'s `backup` flag is resolved
when the step is MINTED, exactly as `alternate` is, so a link is never drawn for
somebody with no unspent code.

**`backup` is a separate field from `alternate` even though they are drawn
beside each other**, and the distinction is worth keeping: `alternate` names the
OTHER MECHANISM THIS PERSON IS CONFIGURED FOR and the two screens swap between
them, while a recovery code is configured for nobody and stands in for whichever
of the two they cannot produce. One field carrying both would make *what is this
person's second factor* a question with a wrong answer.

**The link is drawn LAST on both screens**, after the ordinary alternative. The
codes are a finite, single-use resource issued once, and a link offered above
*use a code from your authenticator app instead* would spend them on a phone
that was merely in the next room.

### The GET decides nothing and refuses a set that is spent

Like `GET /authn/totp`: it draws the page for a step that already exists. What
it adds is a check that an UNSPENT code exists at all, because a link is markup
and this is a door — a screen asking for a credential that cannot exist reads as
a service that has lost it, and a hand-made GET must not produce one.

### The spend is a REFUSAL when it will not write, which is the opposite of the code screen next door

`POST /authn/totp` treats a failed counter write as a warning: the
authentication succeeded and the worst case is a replay inside ninety seconds.
Here a failed spend refuses the sign-in, because a recovery code that cannot be
marked spent is a permanent credential. `common/credentials.js` carries the
argument and `verifyBackupCode()` is where it is enforced, so this endpoint has
no branch of its own for it.

### It has NO SCRIPT, and the argument is made again rather than cited

A person reads a string off a piece of paper and types it into an input. So it
is served under the service-wide `script-src 'none'` and `sendBackupCodePage()`
sets no policy of its own — which is `/authn/totp`'s position, argued the same
day, and the root `CLAUDE.md`'s rule is that a new scripted page needs its case
made from scratch and *the same as the page next door* is not one. Copying
`sendWebauthnPage()` because it is in the same file would have added an eighth
entry to that inventory for a page with no script on it.

### `amr` is `otp` and that is a choice among the registered values

RFC 8176 registers nothing for a recovery code. Inventing one would put a string
in `amr` that no relying party can look up — the exact fake this profile refuses
everywhere else — and `otp`'s registry entry describes *one-time password*,
which a single-use recovery code is by the plainest reading. `acr` is `mfa`
because two factors really were presented: a password and something from a list
only this person holds. **A recovery code is a WEAKER second factor than the one
it stands in for and there is no vocabulary here in which to say so** —
downgrading to `1` would claim ONE factor when two were checked — so the audit
row and `/admin/sessions` are where which mechanism it was is recorded.

## THE SESSION CLOCKS ARE SETTINGS, AND ONE FUNCTION SAYS WHETHER A SESSION HAS ENDED (2026-09-12)

`SESSION_TTL_MS` (an hour), `AUTHN_TTL_MS` (ten minutes) and `MFA_TTL_MS` (five)
were literals, and there was no idle timeout anywhere — the first thing a
deployment's security review asks for and the one thing nobody could set. They
are `authn.sessionLifetimeS`, `authn.pendingTtlS` and `authn.mfaStepTtlS` now,
with `authn.sessionIdleTimeoutS` beside them, and every default is the literal
it replaced. **The idle timeout's default is ZERO and zero means none**, which
is why it is read by a function of its own rather than `secondsSetting()`, whose
fallback would turn a deliberate zero into an hour.

Four things are load-bearing:

* **THE LIFETIME IS STAMPED AT CREATION; THE IDLE TIMEOUT IS CHECKED AT READ.**
  A lifetime is a property a session was issued with, so a change reaches the
  next one. An idle timeout is a policy about how long this service goes on
  honouring a session nobody is using, so `sessionEnded()` — THE ONE PLACE the
  question is answered — asks it every time a session is looked up
  (`sessionOf()`, `relyingPartySessionOf()`, `consoleSession()`, the
  keyed-session lookup) and on every sweep, and `logout/logout.js` asks the same
  function.
* **AN IDLE SESSION IS ENDED, NOT MERELY REFUSED.** It goes through
  `expireSession()` like an absolute expiry, so it writes the `session.end` row
  and the CAEP `session-revoked` every other ending writes, with a reason that
  says which limit ran out.
* **A READ IS NOT A WRITE UNLESS AN IDLE TIMEOUT IS IN FORCE.** `lastSeenAt` is
  touched by `noteSessionUsed()` only then, and at most once a second, because
  `sessionOf()` is called several times per request and the store's journal
  sees `set()`. With no idle timeout — the default — nothing a session carries
  changes on a read, which is what this service always did.
* **USE OF THE CONSOLE OR THE PORTAL IS USE OF THE SIGN-ON SESSION BEHIND IT.**
  Somebody working in the console presents only the console's cookie, so without
  `relyingPartySessionOf()` touching the parent too, the sweep would idle the
  sign-on session out underneath them and the cascade would end the console
  session they are using. An ARRIVAL session is exempt: it has an inactivity
  window of its own on the screen's clock.

`common/oidc_rp.js`'s flow lifetime reads `authn.pendingTtlS` as well — the two
were "deliberately the same" as two literals, which is how two numbers come
apart. `tests/session_clocks.js` pins all of it, mutation-tested against ten.

## THE WEBAUTHN ADDRESS RULES (2026-09-12)

Two changes to what a ceremony is held to, both about the address a request
arrived at:

* **`webauthn.allowedOrigins`.** `expectedOriginFor()` answers
  `originOf(base)` when it is empty — what this module always did, and what
  `global.publicBaseUrl` already pins — and, when it is set, looks the
  clientDataJSON's claimed origin up in the list. A claim is only ever returned
  when an operator already listed it, and the verifier still checks the signed
  bytes against it; a claim off the list is answered with the list's first
  entry so the verifier refuses it in its own words.
* **`rpIdProblem()`.** `rpIdOf()`'s fallback — a configured `webauthn.rpId` that
  does not fit the host is replaced by the host, and the log says why — is a
  development convenience. The host is read off the request, so in product mode
  it is a ceremony scoped to whatever Host arrived. `rpIdProblem()` asks
  `mode.acceptsUnregisteredAddresses()` and the ceremony's POST refuses on it;
  the GET draws the sentence on the page. `rpIdOf()` itself keeps answering,
  because a page that says what it would have sent is worth more than one that
  throws.

**`/portal/keys` asks both functions**, so the two ceremonies cannot accept
different origins. `tests/webauthn_addresses.js` pins it.
