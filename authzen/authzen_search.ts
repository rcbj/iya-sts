// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_search.ts
//
// ===========================================================================
// THE THREE SEARCH APIS: WHAT A SEARCH IS ASKED, WHERE ITS CANDIDATES COME
// FROM, AND HOW IT PAGES (#563, #1175).
//
// AuthZEN 1.0 section 8 defines three optional searches, and this service
// answers all three (rcbj, 2026-10-29: "Provide all search functionality as
// the spec requires"):
//
//   Subject Search    which subjects of a type may do this action on this
//                     resource (`subject.type`, no id)
//   Resource Search   which resources of a type this subject may do this
//                     action on (`resource.type`, no id)
//   Action Search     which actions this subject may do on this resource
//                     (no `action` member at all)
//
// **XACML HAS NO REVERSE QUERY**, so every search is the same three steps:
// take the CANDIDATES this service can name for the searched kind, ask the
// realm's root policy about each one exactly as `/access/v1/evaluation`
// would, and answer the ones it permitted. A result is therefore a decision
// the policy made, which is the section 8.1 SHOULD ("a result … SHOULD
// result in a" Permit) kept as a MUST. Search is not transitive (8.1's
// RECOMMENDED): a candidate is decided as named.
//
// **WHERE CANDIDATES COME FROM** (rcbj, 2026-10-30: "This service's own
// objects … focus on the application directory objects. Those define
// applications, APIs, delegation relationships between them. Let's start
// with that"):
//
//   subjects     the realm's directory people, for a `subject.type` in
//                `authzen.resolveSubjectTypes`; any other type has none
//   resources    `application`  every application entry, by identifier
//                `api`          the resource-server entries (`kinds`
//                               `oauth2-resource-server`), by identifier
//                `delegation`   every delegation relationship an entry
//                               declares (`appAllowedToDelegateTo`), as
//                               `<source>|<target>`
//                any other type has none
//   actions      every action name the root policy (and the policies it
//                references) compares action-id with, and — for a resource
//                that is an application or an API — the names of the
//                permissions that entry defines (`oauthPermission`)
//
// A type with no candidates answers an empty `results`, never a 400: the
// specification's results are "zero or more entities".
//
// **BOUNDED, AND SAID SO.** `authzen.searchMaxCandidates` caps how many
// candidates one search decides; past it the answer's `context.incomplete`
// says the result is partial rather than presenting it as complete.
//
// **PAGING (section 8.2), offset-based.** The whole permitted list is
// decided per call (it is bounded above), and a page is a slice of it. The
// `next_token` is `<offset>.<fingerprint>`: the fingerprint is a digest of
// the request without its token, so a continued request that changed any
// entity or the limit is refused, the SHOULD of section 8.2 kept as a MUST.
// An empty `next_token` ends the result set.
// ===========================================================================

import helpers = require('../common/helpers');

const { log } = helpers;

// The three searches.
const KINDS = Object.freeze(['subject', 'resource', 'action']);

// The resource types this service can name candidates of.
const RESOURCE_TYPES = Object.freeze(['application', 'api', 'delegation']);

// What stands in for the id a search does not send, so the evaluation can be
// read by the one reader; it is replaced per candidate.
const PLACEHOLDER = '__authzen_search__';

// The separator of a delegation relationship's id.
const DELEGATION_SEPARATOR = '|';

// A refusal of a search request.
interface Refusal {
  status: number;
  code: string;
  message: string;
}

// A search request, read.
interface SearchRequest {
  body?: any;
  page?: { token: string; limit: number | null; properties: any };
  fingerprint?: string;
  refusal?: Refusal;
}

// What the candidate sources read.
interface SearchDeps {
  applications: any;
  loadDirectory(): any;
  loadStore(): any;
  crypto: any;
}

/**
 * Says whether a value is a JSON object.
 *
 * @param value - the value
 * @returns true for an object that is not an array
 */
function isObject(value: unknown): boolean {
  log.debug("Entering isObject().");
  log.debug("Leaving isObject().");
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Builds a search refusal, status 400.
 *
 * @param code - the error code
 * @param message - what the caller is told
 * @returns `{ refusal }`
 */
function refused(code: string, message: string): SearchRequest {
  log.debug("Entering refused(). " + code);
  log.debug("Leaving refused().");
  return { refusal: { status: 400, code: code, message: message } };
}

/**
 * The AuthZEN searches: the request read, the candidates named, the page
 * tokens made and checked.
 */
class AuthzenSearch {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the application registry, lazy loaders of the directory
   *   and the policy store, and the crypto library
   */
  constructor(private readonly deps: SearchDeps) {
    log.debug("Entering AuthzenSearch.constructor().");
    log.debug("Leaving AuthzenSearch.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): SearchDeps {
    log.debug("Entering AuthzenSearch.defaultDeps().");
    log.debug("Leaving AuthzenSearch.defaultDeps().");
    return {
      applications: require('../common/applications'),
      loadDirectory: function (): any {
        log.debug("Entering loadDirectory().");
        log.debug("Leaving loadDirectory().");
        return require('../ldap/ldap_server');
      },
      loadStore: function (): any {
        log.debug("Entering loadStore().");
        log.debug("Leaving loadStore().");
        return require('../xacml/xacml_store');
      },
      crypto: require('../common/crypto')
    };
  }

  /**
   * Reads one search request (section 8.4–8.6): the searched kind's own
   * member carries `type` and no meaningful id (an id sent is ignored), an
   * Action Search carries no `action`, and `page` is read apart. What is
   * left is an evaluation request with a placeholder where the candidate
   * goes, for `authzen_map.ts`'s one reader.
   *
   * @param kind - subject, resource or action
   * @param given - the parsed JSON body
   * @returns `{ body, page, fingerprint }`, or `{ refusal }`
   */
  read(kind: string, given: unknown): SearchRequest {
    const self = this;
    log.debug("Entering AuthzenSearch.read(). " + kind);
    if (!isObject(given)) {
      log.debug("Leaving AuthzenSearch.read(). Not an object.");
      return refused('STS-AUTHZEN-0001', 'A search request is a JSON ' +
                     'object.');
    }
    const body: any = Object.assign({}, given);
    let page = { token: '', limit: null, properties: {} };
    if (body.page !== undefined) {
      const sent = body.page;
      const limit = isObject(sent) ? sent.limit : undefined;
      if (!isObject(sent) ||
          (sent.token !== undefined && typeof sent.token !== 'string') ||
          (limit !== undefined && (!Number.isSafeInteger(limit) ||
                                   limit < 0)) ||
          (sent.properties !== undefined && !isObject(sent.properties)) ||
          Object.keys(sent).some(function (key: string) {
            return ['token', 'limit', 'properties'].indexOf(key) < 0;
          })) {
        log.debug("Leaving AuthzenSearch.read(). A bad page.");
        return refused('STS-AUTHZEN-0042', 'page is an object with token ' +
                       '(a string from a previous next_token), limit (a ' +
                       'non-negative integer) and properties (an object), ' +
                       'each optional.');
      }
      page = { token: String(sent.token || ''),
               limit: limit === undefined ? null : limit,
               properties: sent.properties || {} };
      delete body.page;
    }
    if (kind === 'action') {
      if (body.action !== undefined) {
        log.debug("Leaving AuthzenSearch.read(). An action was sent.");
        return refused('STS-AUTHZEN-0009', 'An Action Search request ' +
                       'carries no action member (section 8.6).');
      }
      body.action = { name: PLACEHOLDER };
    } else {
      const object = body[kind];
      if (!isObject(object) || typeof object.type !== 'string' ||
          !object.type) {
        log.debug("Leaving AuthzenSearch.read(). No " + kind + ".type.");
        return refused('STS-AUTHZEN-0002', 'A ' + kind + ' search names ' +
                       'the ' + kind + '.type to search, a non-empty ' +
                       'string.');
      }
      // AN ID SENT IS IGNORED (sections 8.4 and 8.5: it "MUST be ignored").
      body[kind] = Object.assign({}, object, { id: PLACEHOLDER });
    }
    // THE FINGERPRINT IS OF EVERYTHING BUT THE TOKEN: the entities and the
    // limit a continued request must not change (section 8.2).
    const fingerprint = self.fingerprintOf(kind, given);
    log.debug("Leaving AuthzenSearch.read().");
    return { body: body, page: page, fingerprint: fingerprint };
  }

  /**
   * A digest of a search request without its page token.
   *
   * @param kind - the search
   * @param given - the request as sent
   * @returns the digest, sixteen hex digits
   */
  fingerprintOf(kind: string, given: any): string {
    log.debug("Entering AuthzenSearch.fingerprintOf().");
    const copy: any = JSON.parse(JSON.stringify(given || {}));
    if (copy.page) {
      delete copy.page.token;
    }
    // Recursive, once per member: no Entering/Leaving pair, which would
    // drown the log around a key sort.
    const canonical = function (value: any): any {
      if (Array.isArray(value)) {
        return value.map(canonical);
      }
      if (isObject(value)) {
        const out: any = {};
        Object.keys(value).sort().forEach(function (key: string) {
          out[key] = canonical(value[key]);
        });
        return out;
      }
      return value;
    };
    log.debug("Leaving AuthzenSearch.fingerprintOf().");
    return String(this.deps.crypto.sha256Hex(kind + ' ' +
      JSON.stringify(canonical(copy)))).slice(0, 16);
  }

  /**
   * Reads a page token against the request it continues.
   *
   * @param token - the token sent, or ''
   * @param fingerprint - the request's fingerprint
   * @returns the offset, or -1 when the token is not this request's
   */
  offsetOf(token: string, fingerprint: string): number {
    log.debug("Entering AuthzenSearch.offsetOf().");
    if (!token) {
      log.debug("Leaving AuthzenSearch.offsetOf(). The first page.");
      return 0;
    }
    const matched = /^(\d{1,9})\.([0-9a-f]{16})$/.exec(String(token));
    if (!matched || matched[2] !== fingerprint) {
      log.debug("Leaving AuthzenSearch.offsetOf(). Not this request's.");
      return -1;
    }
    log.debug("Leaving AuthzenSearch.offsetOf().");
    return Number(matched[1]);
  }

  /**
   * The token of the page after `offset`, or '' at the end.
   *
   * @param offset - where the next page starts
   * @param total - how many results there are
   * @param fingerprint - the request's fingerprint
   * @returns the token
   */
  static nextToken(offset: number, total: number,
                   fingerprint: string): string {
    log.debug("Entering AuthzenSearch.nextToken().");
    log.debug("Leaving AuthzenSearch.nextToken().");
    return offset < total ? String(offset) + '.' + fingerprint : '';
  }

  /**
   * The candidates of one search, in a stable order, at most `most`.
   *
   * @param kind - subject, resource or action
   * @param evaluation - the evaluation read (its subject and resource)
   * @param resolves - whether the subject type names directory people
   * @param most - the most candidates to name
   * @returns `{ values, truncated }`: ids, or action names
   */
  candidates(kind: string, evaluation: any, resolves: boolean,
             most: number): { values: string[]; truncated: boolean } {
    const self = this;
    log.debug("Entering AuthzenSearch.candidates(). " + kind);
    let values: string[] = [];
    if (kind === 'subject') {
      values = resolves ? self.people(most + 1) : [];
    } else if (kind === 'resource') {
      values = self.resources(String(evaluation.resource.type));
    } else {
      values = self.actions(evaluation.resource);
    }
    const unique = values.filter(function (one: string, i: number) {
      return !!one && values.indexOf(one) === i;
    });
    log.debug("Leaving AuthzenSearch.candidates(). " + unique.length);
    return { values: unique.slice(0, most), truncated: unique.length > most };
  }

  // The realm's people, by username, bounded.
  private people(most: number): string[] {
    log.debug("Entering AuthzenSearch.people().");
    let out: string[] = [];
    try {
      const directory = this.deps.loadDirectory();
      out = (typeof directory.personNamesUpTo === 'function'
        ? directory.personNamesUpTo(most)
        : directory.personNames().slice(0, most)).map(String);
    } catch (e) {
      // No directory: no people to name.
      log.debug("Caught in AuthzenSearch.people(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving AuthzenSearch.people(). " + out.length);
    return out;
  }

  /**
   * The resources of a type this service can name, from the application
   * directory.
   *
   * @param type - application, api or delegation
   * @returns their ids
   */
  resources(type: string): string[] {
    log.debug("Entering AuthzenSearch.resources(). " + type);
    if (RESOURCE_TYPES.indexOf(type) < 0) {
      log.debug("Leaving AuthzenSearch.resources(). Not ours.");
      return [];
    }
    const rows = this.deps.applications.list() || [];
    let out: string[] = [];
    if (type === 'application') {
      out = rows.map(function (row: any) {
        return String(row.identifier);
      });
    } else if (type === 'api') {
      out = rows.filter(function (row: any) {
        return (row.kinds || []).indexOf('oauth2-resource-server') >= 0;
      }).map(function (row: any) {
        return String(row.identifier);
      });
    } else {
      rows.forEach(function (row: any) {
        [].concat(((row.fields || {}).appAllowedToDelegateTo) || [])
          .forEach(function (target: unknown) {
            out.push(String(row.identifier) + DELEGATION_SEPARATOR +
                     String(target));
          });
      });
    }
    out.sort();
    log.debug("Leaving AuthzenSearch.resources(). " + out.length);
    return out;
  }

  /**
   * The actions this service can name for a resource: every action name
   * the root policy compares action-id with, and an application's or an
   * API's own permission names.
   *
   * @param resource - the evaluation's resource
   * @returns the action names
   */
  actions(resource: any): string[] {
    const self = this;
    log.debug("Entering AuthzenSearch.actions().");
    const out: string[] = self.policyActions();
    const type = String((resource || {}).type || '');
    if (type === 'application' || type === 'api') {
      const entry = self.deps.applications.get(String(resource.id || ''));
      const defined = entry && entry.fields
        ? [].concat(entry.fields.oauthPermission || []) : [];
      defined.forEach(function (one: unknown) {
        const name = String(one).split(/\s/)[0];
        if (name) {
          out.push(name);
        }
      });
    }
    out.sort();
    log.debug("Leaving AuthzenSearch.actions(). " + out.length);
    return out;
  }

  /**
   * Every action name the realm's root policy, and the policies its
   * repository holds, compare action-id with — a target's match or a
   * condition's comparison with a literal.
   *
   * @returns the names
   */
  policyActions(): string[] {
    log.debug("Entering AuthzenSearch.policyActions().");
    const ACTION_ID = 'urn:oasis:names:tc:xacml:1.0:action:action-id';
    const found: string[] = [];
    // Recursive, once per node of every policy: no Entering/Leaving pair,
    // which would drown the log around a property read.
    const walk = function (node: any, depth: number): void {
      if (!node || typeof node !== 'object' || depth > 64) {
        return;
      }
      if (Array.isArray(node)) {
        node.forEach(function (one: any) {
          walk(one, depth + 1);
        });
        return;
      }
      // A target's match: a designator beside a literal.
      if (node.reference && node.reference.attributeId === ACTION_ID &&
          node.value && node.value.kind === 'value') {
        found.push(String(node.value.lexical));
      }
      // A condition's comparison: a designator among a call's arguments.
      if (Array.isArray(node.args) && node.args.some(function (arg: any) {
        return arg && arg.kind === 'designator' &&
               arg.attributeId === ACTION_ID;
      })) {
        node.args.forEach(function (arg: any) {
          if (arg && arg.kind === 'value') {
            found.push(String(arg.lexical));
          }
        });
      }
      Object.keys(node).forEach(function (key: string) {
        walk(node[key], depth + 1);
      });
    };
    try {
      const store = this.deps.loadStore();
      const repository = store.repository() || {};
      Object.keys(repository).forEach(function (key: string) {
        walk(repository[key], 0);
      });
      const root = store.root();
      if (root) {
        walk(store.parseDocument(root.document), 0);
      }
    } catch (e) {
      // A repository that will not read names no actions; the search then
      // answers none rather than failing.
      log.debug("Caught in AuthzenSearch.policyActions(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving AuthzenSearch.policyActions(). " + found.length);
    return found.filter(function (one: string, i: number) {
      return found.indexOf(one) === i;
    });
  }
}

/**
 * The AuthZEN searches (#1175): reading, candidates and paging.
 * @namespace
 */
export = {
  AuthzenSearch: AuthzenSearch,
  KINDS: KINDS,
  RESOURCE_TYPES: RESOURCE_TYPES,
  PLACEHOLDER: PLACEHOLDER,
  DELEGATION_SEPARATOR: DELEGATION_SEPARATOR,
  nextToken: AuthzenSearch.nextToken
};
