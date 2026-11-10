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
  // Answers JSON with `Cache-Control: no-store`. Through a handler's
  // response the answer is held to the model's at a literal 2xx status
  // (#1579, `types/api-handlers.d.ts`).
  json<R, S extends number>(res: R, status: S,
                            body: IyaApi.AnswerOf<R, S>): unknown;
  // Marks `code` and answers `{ ok: false, errors, ...extra }`.
  refuse(res: any, status: number, code: string, errors: string | string[],
         extra?: any): unknown;
  // Ends the sessions a credential the person just removed signed in
  // (#722): `{ sessionsEnded, failed, sentence }`, the sentence in their
  // language and empty when none ended.
  endFactorSessions(username: string, factor: any, what: string): any;
}

// ONE OPERATION, which is both a route and a row of the OpenAPI document.
// Every member but the operationId and the handler, which the model types.
export interface AccountOperationRow {
  /** Needs a sign-in within `account.recentAuthMinutes` (ASVS 5.0.0 7.5.1). */
  recentAuth?: boolean;
  method: 'GET' | 'POST';
  // The full path, `/account-api/...`. Express parameters (`:id`) allowed.
  path: string;
  // The OpenAPI tag: the portal page's name.
  tag?: string;
  summary?: string;
  // `person`: the gate's access token; `link`: nobody signed in, the request
  // spends a single-use secret it carries (an activation or reset link);
  // `public`: nobody, nothing spent (the forgot-password form, the index).
  access: 'person' | 'link' | 'public';
  // The portal page or form this operation is the door of — rule 7's twin:
  // `GET /portal/keys`, `POST /portal/keys`. The runtime sends a form to the
  // operation that mirrors it.
  mirrors?: string | null;
  // zod object schemas, checked before the handler runs and documented as
  // the operation's parameters and request body.
  query?: any;
  body?: any;
  // The access gate's action: `read` for a GET and `manage-own` otherwise,
  // unless said.
  action?: string;
}

// THE OPERATION THE MODEL DECLARES (#1579): the handler of the row naming
// `operationId` K is typed by `IyaApi.Account.Operations[K]` — the body and
// query it is handed (checked against the model's zod schemas before it
// runs), the request's query names, and what it may answer through
// `ctx.json()` at a literal 2xx status.
export type AccountOperationOf<K extends keyof IyaApi.Account.Operations> =
  AccountOperationRow & {
    operationId: K;
    handler(req: IyaApi.RequestTo<IyaApi.Account.Operations[K]>,
            res: IyaApi.Answering<IyaApi.Account.Operations[K]>,
            caller: AccountCaller | null,
            input: IyaApi.ValidatedInput<IyaApi.Account.Operations[K]>):
      unknown;
  };

// The response a helper a handler hands its answer to is typed by (#1579):
// the operations whose handlers call it.
export type AccountAnswering<K extends keyof IyaApi.Account.Operations> =
  IyaApi.Answering<IyaApi.Account.Operations[K]>;

// ONE OPERATION OF THE TABLE: any of the model's, discriminated by its id.
export type AccountOperation = {
  [K in keyof IyaApi.Account.Operations]: AccountOperationOf<K>
}[keyof IyaApi.Account.Operations];

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
  // WHERE THE PAGE IS DRAWN FROM THE MANAGEMENT API (#607): the
  // `/admin-api/...` path whose GET answers it for this query, read with the
  // portal's owner token, or null where the query asks for the page's own
  // `operation`. The view `render()` is then handed is
  // `{ owned: { status, answer, canWrite, query } }`.
  admin?(query: any): string | null;
}
