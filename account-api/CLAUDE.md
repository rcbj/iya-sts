# CLAUDE.md — `account-api/`

## THE USER PORTAL'S ONLY DOOR (#568, 2026-10-12)

`/account-api` is what the user portal draws every page from and sends every
form to, since the portal became a static application on the admin console's
pattern (#446). `rust/DESIGN.md` section 5.2 planned it under this name;
rcbj's decisions on #568 are that it is built on the Node service now, that
the portal is a PUBLIC client with DPoP (reversing #444's D9 for the portal as
#446 reversed it for the console), that the pages nobody is signed in to are
drawn the same way, and that the console-session adoption of 2026-09-30 is
dropped.

Two files:

| File | What it is |
|---|---|
| `account_api.ts` | The gate, the route wrapper, the operation table gathered from `PROVIDERS`, the cell placement, and four operations of its own: the index, the document, `GET /account-api/me` and `GET /account-api/locale`. |
| `account_api_spec.ts` | The OpenAPI 3.1 document: a pure function over the table, on `mgmt-api/admin_api_spec.ts`'s rule. |

The shapes the two halves agree on are `types/account-api.d.ts`
(`AccountOperation`, `AccountContext`, `AccountCaller`, and the browser's
`PortalPage` and `PortalRenderContext`).

## THE RULE THAT MATTERS MORE THAN THE REST: THE PERSON IS THE TOKEN'S

**No operation takes a username, an id or a DN naming whose account it acts
on.** `authenticate()` composes the caller from the verified token —
`claims.username`, or the person `helpers.nameForSubject()` reads off `sub` —
and a handler reads `caller.username` and nothing else. That is the portal's
rule (OWASP A01, `portal/CLAUDE.md`) moved to the layer every portal page now
stands on. An id a body carries (a passkey's credential id, an assessment, a
device) is looked up among the CALLER's own, as it always was.

**`link` and `public` operations are the exception and are not one**, for
`/portal/activate`'s reason: nobody is signed in, the person comes from the
link, and the single-use secret the link carries is the credential. They keep
every rate limit the pages had.

## THE GATE, IN ITS ORDER

Each step is a credential that stopped being one, answered 401 with a
`WWW-Authenticate: DPoP` challenge, or a 403 where the token is a credential
but not for this:

1. a token is presented (`STS-ACCOUNT-0001`);
2. it verifies under THIS realm's key, any generation (`0002`) — not the
   default realm's, which is the management API's choice and the opposite one:
   that API's token is a service credential, and this one is a person's in
   the realm they are in;
3. not expired (`0003`); RFC 9068 section 4: `at+jwt` (`0004`), an issuer this
   realm publishes at the address the request reached (`0005`), the audience
   this realm's `/account-api` (`0006`, 403);
4. not revoked or disowned, the person not disabled (`0007`), and the sign-on
   session it was issued on still live (`0008`) — the management API's three
   checks (#36, #446). A token the registry forgot (it is capped) answers no
   session and is honoured until it expires, for that API's reason;
5. RFC 8705's certificate binding (`0009`); RFC 9449's DPoP binding — never as
   Bearer (`0010`), the proof checked with a nonce asked for where the service
   wants one (`0011`); and `sender_constraints.js`'s rule that the portal's
   client, public, is DPoP-bound always, beside #34's two settings;
6. a PERSON's token, never a client's own (`0012`); carrying `account:manage`
   (`0013`); issued to a client that STILL declares it (`0014`, #110's rule
   asked on every call);
7. the access policy, as the portal's pages asked it: `user-portal`, `read` for
   a GET and `manage-own` otherwise, the owner the subject (`0015`).

The caller carries `session`, in the server-rendered portal's session shape,
so a handler moved from a page reads the members it read there. **Its `id` is
the SIGN-ON session's** — the session the token was issued on, from the token
registry — which is what the portal's CSRF token was bound to and what a risk
answer, a CIBA approval and a device link name.

## THE WRAPPER

`run()` checks the operation's zod `query` and `body` before its handler runs
(`0016`, `0018`), refuses a POST body that is not JSON (`0017`), and turns a
handler that throws into a 500 (`0019`). **The schemas are the documentation**:
`account_api_spec.ts` converts the very objects the wrapper checks with, so a
parameter documented and a parameter refused are one declaration.

**Since 2026-10-12, as `/authn-api`, `/gnap-api` and `/admin-api` do:**

* **A body field the operation does not declare is REFUSED** (`0018`, naming
  the field), not stripped — `AccountApi.unknownFields()` over the body
  schema's object shape; a schema that is not an object, or a `passthrough`
  one, is left to itself. The document says `additionalProperties: false` on
  every such body. The portal's own forms send nothing else:
  `tests/account_api.js` 2d checks every named control of every form a page
  draws against its operation's documented body.
* **The media type is exact** — `^application/json\s*(;|$)` — and asked of
  every body-carrying request, whether or not the operation declares a body
  (`0017`, 415). It matched `/json/i` anywhere, so a cross-site page could
  reach an operation that takes no token (activation, reset, a forgotten
  password) with a CORS-safelisted `text/plain; x=json` and no preflight.
  `tests/account_api.js` section 6.

## WHAT AN ANSWER IS

The portal's runtime (`portal/web_portal_runtime.ts`, `answered()`) draws a
POST's answer by these members, and every provider keeps to them:

| Member | Drawn as |
|---|---|
| `message` | The page asked again, with the message. In the person's language: a provider translates with `ctx.translatorFor()`. |
| `view` | The page drawn from it, in place — a secret, codes, a key, download links shown ONCE, never on a URL or in the history. A view that draws its own refusal says so (`refused`, `notOffered`, `tooMany`) and the refusal is not drawn twice. |
| `go` | Another portal page, with the message. |
| `errors` (with `ok: false`) | The page asked again, with the refusal. |
| `stepUp` | A sign-in again with `prompt=login` and the `acr_values` it names, back to the page (CIBA, GNAP). A GET's view may answer it too. |
| `location` | Another site (a Claims Provider's sign-in). |
| `files` | Each saved, `{ name, mime, base64 }`. |

## WHO CONTRIBUTES OPERATIONS

`PROVIDERS` lists the modules, in the column's order; each exports
`accountOperations(ctx)`. The table is built once, when the routes are
registered — at 8a, right after the portal (`common/protocol_stack.ts`) —
after the composition root built every provider. **A portal control has an
operation here in the same commit** (rule 7's twin, `rust/DESIGN.md` 5.2):
`mirrors` names the portal page or form, and the runtime finds a form's
operation by it.

## SERVED AT THE PERSON'S HOME (#98)

`placeRequest()` relays a request, whole and before the gate, to the home cell
of its person: the token's (its claims read only to route — the home cell
verifies it) or the person a link names. `common/cell_placement.ts` places
`/account-api` by this handler and `/portal` locally, since the portal is a
static document.

## ON A WORKER

`/account-api` is in `workers.fanout`'s default beside `/admin-api`: every
request carries its own credential, so nothing about one has to be remembered
to answer the next.

## THE DOCUMENT IN THE CONSOLE

`GET /admin-api/account-api` answers the document for the realm the console is
in, and **Service → Account API** (`/admin/account-api`,
`admin-ui/web_account_api.ts`) draws it. It CALLS NOTHING, which is the
difference from the management API's explorer: every operation here acts on
the signed-in person's own account, with their token, and a console token is
not one.

## TESTS

`tests/vendored/portal_signin.js` signs in as the portal (PKCE, DPoP) and is a
client of these operations — `page()`, `draw()`, `act()`, `api()`, and
`nobody()` for a link's.
