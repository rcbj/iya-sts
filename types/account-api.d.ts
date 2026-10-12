// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ---------------------------------------------------------------------------
// THE ACCOUNT API'S SHAPES (#568).
//
// `/account-api` is the user portal's only door since the portal became a
// static application: an operation per page view and per form, contributed
// by the module that owns the page (`portal/account_*.ts`, `portal/portal_*`)
// and served, gated and documented by `account-api/account_api.ts`. These
// are the three shapes the two halves agree on. `account-api/CLAUDE.md`
// argues them.
// ---------------------------------------------------------------------------

// WHO IS CALLING, as the gate decided it from the access token: never a
// parameter of the request (the portal's rule, OWASP A01).
export interface AccountCaller {
  // The person's username, the name this service files them under.
  username: string;
  // Their subject, `urn:uuid:<entryUUID>`.
  sub: string;
  // The realm whose authorization server issued the token, which is the
  // realm the request is in.
  realm: string;
  // The client the token was issued to: `sts-user-portal`, or another client
  // an operator let declare `account:manage`.
  clientId: string;
  scopes: string[];
  // When the token stops being accepted (seconds since the epoch).
  expiresAt: number | null;
  // The SIGN-ON session the token was issued on, '' where the token registry
  // no longer holds which (it is capped).
  sessionId: string;
  // What a portal page read off its session, in that session's shape:
  // `id` (the sign-on session's), `user` (`username`, `sub`, `name`,
  // `email`), `risk` (`assessmentId`, `level`), `expires`, and
  // `authenticated` — so a handler moved from the server-rendered portal
  // reads the same members it read there.
  session: any;
  // The sign-on session itself (`authn.sessionById()`), or null.
  signOn: any;
}

// WHAT EVERY OPERATION'S PROVIDER IS HANDED: the shared helpers, so that a
// refusal is shaped, coded and answered one way across the API.
export interface AccountContext {
  // `/account-api`.
  BASE: string;
  // `/portal`, the pages these operations are the doors of.
  PORTAL: string;
  log: { debug(message: string): void; info(message: string): void;
         error(message: string): void };
  validation: any;
  errorCodes: any;
  audit: any;
  websecurity: any;
  accessGate: any;
  config: { value(key: string): any };
  baseUrlOf(req: any): string;
  parseBody(req: any): any;
  // The portal's translator for a person (their own language first), or for
  // nobody — a page drawn for an activation link or a reset.
  translatorFor(username?: string): any;
  // Answers JSON with `Cache-Control: no-store`.
  json(res: any, status: number, body: any): unknown;
  // Marks `code` and answers `{ ok: false, errors, ...extra }`.
  refuse(res: any, status: number, code: string, errors: string | string[],
         extra?: any): unknown;
}

// ONE OPERATION, which is both a route and a row of the OpenAPI document.
export interface AccountOperation {
  method: 'GET' | 'POST';
  // The full path, `/account-api/...`. Express parameters (`:id`) allowed.
  path: string;
  operationId: string;
  // The OpenAPI tag: the portal page's name.
  tag: string;
  summary: string;
  description: string;
  // `person`: the gate's access token; `link`: nobody signed in, the request
  // spends a single-use secret it carries (an activation or reset link);
  // `public`: nobody, nothing spent (the forgot-password form, the index).
  access: 'person' | 'link' | 'public';
  // The portal page or form this operation is the door of — rule 7's twin:
  // `GET /portal/keys`, `POST /portal/keys`. The runtime sends a form to the
  // operation that mirrors it.
  mirrors?: string;
  // zod object schemas, checked before the handler runs and documented as
  // the operation's parameters and request body.
  query?: any;
  body?: any;
  // A JSON Schema that DOCUMENTS a body the handler checks itself, where no
  // zod schema can (CIBA's repeated per-right limit controls): the document
  // shows it, the wrapper checks nothing with it.
  bodyDoc?: any;
  // The JSON Schema of a successful answer, where one is declared.
  answer?: any;
  // The HTTP statuses the handler answers besides 200, with what each means.
  statuses?: Record<string, string>;
  // The access gate's action: `read` for a GET and `manage-own` otherwise,
  // unless said.
  action?: string;
  handler(req: any, res: any, caller: AccountCaller | null,
          input: { query: any; body: any }): unknown;
}

// ---------------------------------------------------------------------------
// THE BROWSER HALF: ONE PORTAL PAGE, as `portal/web_portal_pages.ts` lists it
// and the runtime draws it.
// ---------------------------------------------------------------------------

// What a renderer is handed besides its view: only what differs between two
// readers of one answer (the console's render context, #446).
export interface PortalRenderContext {
  // The translator: the person's language, from `GET /account-api/me` (or
  // `/account-api/locale` on a page drawn for nobody).
  t: any;
  // The page's own query parameters.
  query: Record<string, string>;
  // The realm's path prefix, '' in the default realm. Links are drawn
  // root-relative and the runtime puts the prefix on them.
  prefix: string;
  // This page's origin, for an address shown to be copied.
  origin: string;
  // `GET /account-api/me`'s answer, or null on a page drawn for nobody.
  me: any;
  // The language data — `negotiated`, `catalogs`, `offered` — from `me`, or
  // from `GET /account-api/locale` on a page drawn for nobody: what
  // `PortalShell.chooser()` draws the language chooser from.
  locale: any;
  // The build, `{ version, buildInfo }`.
  version: any;
  // The page's own address with the realm's prefix and its query: where a
  // language chooser on a page drawn for nobody returns to.
  here: string;
}

export interface PortalPage {
  // The path the browser shows: `/portal/sign-ins`.
  path: string;
  // The operation whose GET answers the page's view.
  operation: string;
  // `person` (the default): signed in, drawn in the frame. `link` and
  // `public`: drawn for nobody, with no column, from an operation that takes
  // no token.
  access?: 'person' | 'link' | 'public';
  // The page's body: the cards inside the frame, or for a page drawn for
  // nobody, the whole of it.
  render(view: any, ctx: PortalRenderContext): string;
  // A page for nobody's title (the frame titles a signed-in page from the
  // column's table).
  title?(view: any, ctx: PortalRenderContext): string;
}
