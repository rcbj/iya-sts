// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ---------------------------------------------------------------------------
// THE MODEL TYPES THE HANDLERS (#1579).
//
// `types/api.generated.d.ts` is generated from `models/api/*.tsp` and holds,
// for each of the five APIs, `IyaApi.<Api>.Operations`: every operation by
// its operationId (by `METHOD path` in the Reports API, whose operations carry
// none), with what it takes and what it answers. This file is what binds a
// handler to its entry there, so that the checker (`tests/typecheck.js`)
// refuses a handler that
//
//   * reads a body member, or a query name, its operation does not declare;
//   * answers a 2xx status with a member, or a value, its operation's answer
//     at that status does not allow, or answers a 2xx status the model gives
//     no JSON answer for.
//
// Declarations only: nothing here exists at runtime, and checking may not
// change behaviour.
//
// **THE ANSWER IS CHECKED WHERE THE STATUS IS A LITERAL.** A handler that
// answers `result.ok ? 200 : 400` with one value cannot say which body goes
// with which status, so that answer is left to the runtime check
// (`common/response_models.ts`), which holds every answer to the same model
// whatever the type says. `tests/model_api_handlers.js` proves the binding:
// it edits a real handler of each API in a scratch copy of the tree and
// requires the checker to refuse each edit.
// ---------------------------------------------------------------------------

declare namespace IyaApi {
  // What every entry of an `Operations` interface is.
  interface Operation {
    body: unknown;
    query: unknown;
    answers: unknown;
  }

  // The Management API and the Admin Console API are served by one route
  // table (`mgmt-api/admin_api.ts`), and no operationId is in both.
  interface AdminOperations extends IyaApi.Management.Operations,
    IyaApi.Console.Operations {}

  // THE QUERY'S NAMES ARE THE MODEL'S; ITS VALUES ARE WHAT EXPRESS PARSED. A
  // route that validates its query before the handler (the Account API's
  // zod check, which coerces) hands the handler the model's own types
  // instead, as `ValidatedInput`.
  // For a handler serving several operations, a name any of them declares.
  type RawQuery<Q> = { [K in (Q extends unknown ? keyof Q : never)]?: any };

  // A request to one operation (or to any of several, for a handler that
  // serves several): its body and query as the model declares them. Every
  // other member is the request's, untyped as it was.
  interface RequestTo<O extends Operation> {
    body: O['body'];
    query: RawQuery<O['query']>;
    [member: string]: any;
    [member: symbol]: any;
  }

  // A response to one operation: it carries, as a type only, what the
  // operation may answer, for `AnswerOf` to read. Every other member is the
  // response's, untyped as it was.
  interface Answering<O extends Operation> {
    readonly __iyaAnswers?: O['answers'];
    [member: string]: any;
    [member: symbol]: any;
  }

  // What a handler holding response `R` may send with status `S`: the
  // model's answer at a literal 2xx status, nothing at a 2xx status the model
  // gives no JSON answer, and anything at a status that is not a literal (or
  // through a response that is not typed). For a handler serving several
  // operations, any one of their answers at that status.
  type AnswerOf<R, S extends number> =
    R extends { readonly __iyaAnswers?: infer M }
      ? (number extends S ? unknown : AnswerIn<M, S>)
      : unknown;
  type AnswerIn<M, S> = M extends unknown
    ? (S extends keyof M ? M[S]
      : S extends 200 | 201 | 202 | 203 | 204 | 206 ? never : unknown)
    : never;

  // What a route that checks the request before its handler hands it: the
  // query and the body as the model declares them.
  interface ValidatedInput<O extends Operation> {
    query: O['query'];
    body: O['body'];
  }

  // WHAT A VIEW ANSWERS (#1579): the JSON answer at 200 of the operations a
  // view is the answer of, so `admin-core/admin_views.ts` builds the model's
  // shape and the checker says where it does not.
  type AnswerAt200<Ops, K extends keyof Ops> = K extends unknown
    ? (Ops[K] extends { answers: { 200: infer A } } ? A : never)
    : never;
  type AdminAnswer<K extends keyof AdminOperations> =
    AnswerAt200<AdminOperations, K>;
  // A view that answers its page's model beside it, as `json`.
  interface AdminView<K extends keyof AdminOperations> {
    json: AdminAnswer<K>;
    [member: string]: any;
  }

  // ONE ROW OF A ROUTE TABLE, discriminated by its operationId: the row's
  // `handler` is typed by the operation the same row names. `Extra` is what
  // a table hands a handler after the request and the response. Every other
  // member of a row is the table's own.
  type RowOf<Ops, Extra extends any[]> = {
    [K in keyof Ops]: {
      operationId: K;
      handler?: (req: RequestTo<Ops[K] & Operation>,
                 res: Answering<Ops[K] & Operation>,
                 ...extra: Extra) => unknown;
      [member: string]: any;
    }
  }[keyof Ops];

  // ONE ACTION OF A ROW THAT SERVES SEVERAL (`POST …/:action`).
  interface ActionOf<Ops, K extends keyof Ops = keyof Ops> {
    action: string;
    operationId: K;
    [member: string]: any;
  }

  // A ROW THAT SERVES SEVERAL OPERATIONS, one per action: its handler is
  // typed by the union of its actions' operations. `common/api_rows.ts`'s
  // `ApiRows.actions()` infers `K` from the row's own `actions`.
  type ActionRowOf<Ops, K extends keyof Ops, Extra extends any[]> = {
    operationId?: undefined;
    actions: Array<ActionOf<Ops, K>>;
    handler?: (req: RequestTo<Ops[K] & Operation>,
               res: Answering<Ops[K] & Operation>,
               ...extra: Extra) => unknown;
    [member: string]: any;
  };

  // THE MANAGEMENT AND ADMIN CONSOLE APIS' ROUTE TABLE (`mgmt-api/
  // admin_api.ts` and every module whose `ROUTES` it spreads): a row naming
  // one operation, or a row of actions.
  type AdminActionRow<K extends keyof AdminOperations = keyof AdminOperations> =
    ActionRowOf<AdminOperations, K, [any?]>;
  type AdminRow = RowOf<AdminOperations, [any?]> | AdminActionRow;
}
