// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_external_pdp.ts
//
// ===========================================================================
// THE AUTHZEN BINDING FOR OAUTH 2.0 TOKEN EXCHANGE, DIRECTION B: THIS
// AUTHORIZATION SERVER ASKS AN EXTERNAL PDP (#1200).
//
// Direction A (`authzen_exchange.ts`, #1181) is the other way round: this
// service IS the PDP another authorization server asks. This file is the
// ask. The token endpoint, once the local issuance policy has allowed an
// RFC 8693 exchange and the local scope narrowing has run, and only when
// the token it is about to mint is an OAuth access token, sends the
// binding's batch to the PDP an administrator configured and honours the
// answer.
//
// **IT SITS BESIDE THE ISSUANCE GATE. IT DOES NOT REPLACE IT.** The local
// decision has already been made, by `delegation_policy.ts` and the
// issuance policy, the same way an exchange is decided with this switch
// off. A refusal that policy enforces is not sent on. What comes back may
// only NARROW: a false scope tuple drops that scope, `granted_scope` is
// intersected with the scopes the local endpoint would already issue, and
// `token_lifetime` is a ceiling on the access token (`lifetimeCapS`, which
// only shortens). Nothing here writes `sub`, `aud`, `act`, `may_act` or a
// claim, and a wider scope or a longer life is ignored. The refresh token,
// when one is also issued, keeps its own lifetime.
//
// **A KERBEROS `requested_token_type` IS OUTSIDE THE BINDING.** The tuples
// name a registered OAuth token type, and the branch that mints a Kerberos
// token does not call here. The local policy is the whole of that decision.
//
// **FAIL CLOSED, IN EVERY MODE.** Development softens the LOCAL issuance
// policy. It does not soften this. No URL, a URL this file will not dial,
// a client certificate or key that cannot be read, `federation.outbound`
// off, a timeout, a non-2xx, a body that is not the batch's answer: no
// token. A `decision: false` on a subject or requesting-party gate is a
// refusal of the whole exchange. The client is told neither which gate nor
// the code, and the PDP's address is not in that sentence.
//
// **THE URL IS AN ADMINISTRATOR'S.** `authzen.externalPdpUrl`, never a
// request. Absolute https only — plain http is refused even when
// `federation.outboundAllowHttp` is on, because the body carries token
// claims and the call carries a client certificate — and no userinfo,
// query or fragment, so a configured base cannot be given parameters.
// Mutual TLS is the only mode: the PEM paths are read at the dial, held to
// `security.fileRoots` in product (`common/outbound_tls.ts`), and the key's
// bytes are never a configuration value. The dial is
// `federation_http.requestConfigured` (no redirect, the timeout, the body
// cap). An empty audience is still asked, with a resource id of '' — the
// binding's resource id is required to be non-empty by this service's own
// model, so a PDP that refuses that shape refuses the token, which is the
// same fail-closed rule.
//
// The batch is the one direction A accepts (`TOKEN_TYPES`, `GATE_RESOURCE`,
// `SCOPE_RESOURCE`, and the context types `readContext` holds), so a realm
// of this service can be the PDP the tests use. A member that would not
// type-check is left out rather than sent: a 400 from the PDP means our
// request was refused as malformed, and that is no answer, not a local
// bug to paper over.
// ===========================================================================

import helpers = require('../common/helpers');
import exchange = require('./authzen_exchange');
import OutboundTls = require('../common/outbound_tls');

const { log } = helpers;

type Json = any;

// The gate this branch asks. The token endpoint's non-Kerberos arm always
// mints an access token, whatever `requested_token_type` was.
const GATE_ACTION = 'issue:access_token:token_exchange';

const ACCESS_TOKEN_TYPE = exchange.TOKEN_TYPES.access_token;

// How deep an `act` chain may be before it is left out. Deeper, direction A
// refuses the whole request (400), which this side would read as no answer.
const MAX_ACT_DEPTH = 32;

const CLIENT_SENTENCE_REFUSED = 'The authorization server\'s policy refused ' +
  'this token exchange.';
const CLIENT_SENTENCE_FAULT = 'The authorization server could not complete ' +
  'this token exchange. Try again shortly.';

interface DialOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  ca?: string;
  timeoutMs?: number;
  cert?: string;
  key?: string;
}

interface DialReply {
  ok: boolean;
  status: number;
  body: Buffer | string;
  kind: string;
  why: string;
}

interface ExternalPdpDeps {
  log: typeof log;
  config: { value(key: string): Json };
  errorCodes: { tag(code: string): string };
  namedFileAllowed(file: string): boolean;
  readFile(file: string): string;
  request(url: string, options: DialOptions): Promise<DialReply>;
}

interface BatchItem {
  kind: string;
  scope: string;
  audience: string;
  // Whether the exchange named this audience or resource, rather than the
  // authorization server standing in for none (#1200's review).
  named: boolean;
}

/**
 * Direction B: the batch this authorization server sends before it issues
 * an RFC 8693 access token, and what of the answer it honours.
 */
class AuthzenExternalPdp {
  /**
   * Builds the ask over its dependencies.
   *
   * @param deps - the logger, settings, error codes, the file-root check,
   *   the file read and the dial
   */
  constructor(private readonly deps: ExternalPdpDeps) {
    deps.log.debug("Entering AuthzenExternalPdp.constructor().");
    deps.log.debug("Leaving AuthzenExternalPdp.constructor().");
  }

  /**
   * The dependencies built from the real modules. The dial is the outbound
   * request an administrator's URL is made with; the file check is the one
   * every named PEM goes through.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ExternalPdpDeps {
    log.debug("Entering AuthzenExternalPdp.defaultDeps().");
    const deps: ExternalPdpDeps = {
      log: log,
      config: require('../common/config'),
      errorCodes: require('../common/error_codes'),
      namedFileAllowed: function (file: string): boolean {
        log.debug("Entering namedFileAllowed().");
        const allowed = require('../common/outbound_tls')
          .namedFileAllowed(file);
        log.debug("Leaving namedFileAllowed().");
        return allowed;
      },
      readFile: function (file: string): string {
        log.debug("Entering readFile().");
        try {
          const text = require('fs').readFileSync(file, 'utf8');
          log.debug("Leaving readFile().");
          return text;
        } catch (e) {
          const err = e as { code?: string; message?: string };
          // err.message names the path. The code does not.
          log.debug("Caught in readFile(): " + (err && err.code ||
                                                'unreadable'));
          log.debug("Leaving readFile().");
          throw e;
        }
      },
      request: function (url: string, options: DialOptions):
          Promise<DialReply> {
        log.debug("Entering request().");
        const pending = require('../federation/federation_http')
          .requestConfigured(url, options);
        log.debug("Leaving request().");
        return pending;
      }
    };
    log.debug("Leaving AuthzenExternalPdp.defaultDeps().");
    return deps;
  }

  /**
   * Whether this realm asks (`authzen.externalPdp`).
   *
   * @returns true while the switch is on
   */
  enabled(): boolean {
    const { log: logger, config } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.enabled().");
    const on = config.value('authzen.externalPdp') === true;
    logger.debug("Leaving AuthzenExternalPdp.enabled().");
    return on;
  }

  /**
   * Asks the configured PDP, or reports that the local decision stands
   * unchanged. Never throws: a fault is a result, and the token endpoint
   * refuses from it.
   *
   * @param input - the exchange the token endpoint is about to issue
   * @returns `{ ok, code, status, error, description, scope, lifetimeCapS }`.
   *   `scope` null means the local scope stands; `''` means issue none.
   *   `lifetimeCapS` null means no ceiling.
   */
  async consult(input: Json): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.consult().");
    let out: Json;
    try {
      out = await this.asked(input);
    } catch (e) {
      const err = e as { message?: string };
      logger.debug("Caught in AuthzenExternalPdp.consult(): " +
                   ((err && err.message) || e));
      // A throw is the same as no answer. The token is not issued.
      logger.error(this.deps.errorCodes.tag('STS-AUTHZEN-0124') +
                   'the external AuthZEN PDP was not asked.');
      out = AuthzenExternalPdp.fault('STS-AUTHZEN-0124');
    }
    logger.debug("Leaving AuthzenExternalPdp.consult().");
    return out;
  }

  /**
   * The ask itself: nothing while the switch is off, then the URL, then
   * the certificate, then the dial, then the answer.
   *
   * @param input - the exchange
   * @returns the result `consult` returns
   */
  private async asked(input: Json): Promise<Json> {
    const self = this;
    const { log: logger, config } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.asked().");
    if (!self.enabled()) {
      logger.debug("Leaving AuthzenExternalPdp.asked(). Off.");
      return AuthzenExternalPdp.unchanged();
    }
    const url = String(config.value('authzen.externalPdpUrl') || '');
    const urlProblem = AuthzenExternalPdp.urlProblem(url);
    if (urlProblem) {
      logger.error(self.deps.errorCodes.tag('STS-AUTHZEN-0123') +
                   'authzen.externalPdpUrl cannot be dialled (' +
                   urlProblem + ').');
      logger.debug("Leaving AuthzenExternalPdp.asked(). " + urlProblem);
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0123');
    }
    const cert = self.readPem('authzen.externalPdpClientCertFile',
                              'CERTIFICATE');
    if (cert.code) {
      logger.debug("Leaving AuthzenExternalPdp.asked(). No certificate.");
      return AuthzenExternalPdp.fault(cert.code);
    }
    const key = self.readPem('authzen.externalPdpClientKeyFile',
                             'PRIVATE KEY');
    if (key.code) {
      logger.debug("Leaving AuthzenExternalPdp.asked(). No key.");
      return AuthzenExternalPdp.fault(key.code);
    }
    const caFile = String(config.value('authzen.externalPdpCaFile') || '');
    let ca = '';
    // `outbound-authzen-pdp`'s truststores where it is assigned (#2118);
    // unassigned, the CA file exactly as before.
    const assigned = OutboundTls.assignedCa('outbound-authzen-pdp');
    if (assigned && assigned.problem) {
      logger.error(self.deps.errorCodes.tag('STS-AUTHZEN-0127') +
                   assigned.problem.why);
      logger.debug("Leaving AuthzenExternalPdp.asked(). No CA.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0127');
    } else if (assigned) {
      ca = assigned.ca || '';
    } else if (caFile) {
      const read = self.readPem('authzen.externalPdpCaFile', 'CERTIFICATE');
      if (read.code) {
        logger.debug("Leaving AuthzenExternalPdp.asked(). No CA.");
        return AuthzenExternalPdp.fault(read.code);
      }
      ca = read.pem;
    }
    const built = AuthzenExternalPdp.batchOf(input || {});
    const timeout = Number(config.value('authzen.externalPdpTimeoutMs'));
    const timeoutMs = Number.isFinite(timeout) && timeout > 0 ? timeout
                                                              : 5000;
    const options: DialOptions = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(built.body),
      timeoutMs: timeoutMs,
      cert: cert.pem,
      key: key.pem
    };
    if (ca) {
      options.ca = ca;
    }
    let reply: DialReply;
    try {
      reply = await self.deps.request(url, options);
    } catch (e) {
      const err = e as { code?: string; message?: string };
      logger.debug("Caught in AuthzenExternalPdp.asked(): " +
                   (err && err.code || err && err.message || e));
      // The dial promises not to reject. A throw is still no answer.
      logger.error(self.deps.errorCodes.tag('STS-AUTHZEN-0124') +
                   'the external AuthZEN PDP was not reached.');
      logger.debug("Leaving AuthzenExternalPdp.asked(). Threw.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0124');
    }
    const out = self.outcomeOf(reply, built.items);
    logger.debug("Leaving AuthzenExternalPdp.asked().");
    return out;
  }

  /**
   * Why a configured address cannot be dialled, or '' when it can. Stricter
   * than the dialer's own verdict: https only, and no userinfo, query or
   * fragment.
   *
   * @param raw - the configured URL
   * @returns `unparseable`, `not-https`, `userinfo`, `query`, `fragment`
   *   or ''
   */
  static urlProblem(raw: string): string {
    log.debug("Entering AuthzenExternalPdp.urlProblem().");
    let target: URL;
    try {
      target = new URL(String(raw || ''));
    } catch (e) {
      const err = e as { message?: string };
      log.debug("Caught in AuthzenExternalPdp.urlProblem(): " +
                ((err && err.message) || e));
      log.debug("Leaving AuthzenExternalPdp.urlProblem(). Unparseable.");
      return 'unparseable';
    }
    let problem = '';
    if (target.protocol !== 'https:') {
      problem = 'not-https';
    } else if (target.username || target.password) {
      problem = 'userinfo';
    } else if (target.search) {
      problem = 'query';
    } else if (target.hash) {
      problem = 'fragment';
    }
    log.debug("Leaving AuthzenExternalPdp.urlProblem(). " +
              (problem || 'Usable.'));
    return problem;
  }

  /**
   * Reads one named PEM, or the code for why it cannot be used. The path
   * and the bytes stay out of the log.
   *
   * @param setting - the setting that names the file
   * @param marker - the PEM label the file must carry (`CERTIFICATE`, or
   *   `PRIVATE KEY` which also matches an RSA or EC label)
   * @returns `{ pem }` or `{ code }`
   */
  private readPem(setting: string, marker: string): Json {
    const { log: logger, config, namedFileAllowed, readFile,
            errorCodes } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.readPem().");
    const file = String(config.value(setting) || '');
    const refuse = function (why: string): Json {
      logger.debug("Entering refuse().");
      logger.error(errorCodes.tag('STS-AUTHZEN-0127') + setting + ' ' +
                   why);
      logger.debug("Leaving refuse().");
      logger.debug("Leaving AuthzenExternalPdp.readPem(). Refused.");
      return { code: 'STS-AUTHZEN-0127' };
    };
    if (!file) {
      return refuse('is empty while authzen.externalPdp is on.');
    }
    if (!namedFileAllowed(file)) {
      return refuse('is not a file this process may read.');
    }
    let text = '';
    try {
      text = readFile(file);
    } catch (e) {
      const err = e as { code?: string };
      // The message names the path, so the log keeps the errno only.
      logger.debug("Caught in AuthzenExternalPdp.readPem(): " +
                   (err && err.code || 'unreadable'));
      return refuse('could not be read (' + (err && err.code || 'error') +
                    ').');
    }
    const label = marker === 'PRIVATE KEY' ? 'PRIVATE KEY-----'
                                           : 'CERTIFICATE-----';
    if (String(text || '').indexOf(label) < 0) {
      return refuse('does not hold a PEM ' + marker.toLowerCase() + '.');
    }
    logger.debug("Leaving AuthzenExternalPdp.readPem().");
    return { pem: text };
  }

  /**
   * The batch, and the parallel list the answer is read against. A party
   * the caller passes that is the subject is not sent. An exchange that
   * names no audience or resource is asked about `defaultTarget`, this
   * authorization server's issuer (#1200's review): a gate whose resource
   * id was empty was an item error at a PDP, this service's own included,
   * so such an exchange failed closed.
   *
   * @param input - the exchange
   * @returns `{ body, items }`
   */
  static batchOf(input: Json): { body: Json; items: BatchItem[] } {
    log.debug("Entering AuthzenExternalPdp.batchOf().");
    const given = input && typeof input === 'object' ? input : {};
    const subject = AuthzenExternalPdp.partyOf(given.subject, 'user');
    const party = given.party
      ? AuthzenExternalPdp.partyOf(given.party, 'user') : null;
    const sendParty = !!party && (party.type !== subject.type ||
                                  party.id !== subject.id);
    const named = Array.isArray(given.audiences) &&
      given.audiences.length > 0;
    const audiences = named
      ? given.audiences.map(function (one: Json) {
        return String(one);
      })
      : [String(given.defaultTarget || '')];
    const scopes = (Array.isArray(given.scopes) ? given.scopes : [])
      .map(function (one: Json) {
        return String(one);
      })
      .filter(function (one: string) {
        return !!one;
      });
    const items: BatchItem[] = [];
    const evaluations: Json[] = [];
    audiences.forEach(function (audience: string, index: number) {
      const gate = function (who: Json, kind: string): void {
        log.debug("Entering gate().");
        const item: Json = {
          subject: { type: who.type, id: who.id },
          action: { name: GATE_ACTION }
        };
        if (index > 0) {
          item.resource = { type: exchange.GATE_RESOURCE, id: audience };
        }
        evaluations.push(item);
        items.push({ kind: kind, scope: '', audience: audience,
                     named: named });
        log.debug("Leaving gate().");
      };
      gate(subject, 'subject');
      if (sendParty && party) {
        gate(party, 'party');
      }
      scopes.forEach(function (scope: string) {
        evaluations.push({
          subject: { type: subject.type, id: subject.id },
          action: { name: scope },
          resource: { type: exchange.SCOPE_RESOURCE, id: audience }
        });
        items.push({ kind: 'scope', scope: scope, audience: audience,
                     named: named });
      });
    });
    const body: Json = {
      resource: { type: exchange.GATE_RESOURCE, id: audiences[0] },
      context: AuthzenExternalPdp.contextOf(given),
      evaluations: evaluations,
      options: { evaluations_semantic: 'execute_all' }
    };
    log.debug("Leaving AuthzenExternalPdp.batchOf(). " + items.length +
              " item(s).");
    return { body: body, items: items };
  }

  /**
   * The context members direction A reads, each only when it type-checks.
   * A member that would make the PDP refuse the request as malformed is
   * left out.
   *
   * @param input - the exchange
   * @returns the context object
   */
  static contextOf(input: Json): Json {
    log.debug("Entering AuthzenExternalPdp.contextOf().");
    const claims = input.subjectClaims &&
      typeof input.subjectClaims === 'object' ? input.subjectClaims : {};
    const context: Json = {};
    const put = function (key: string, type: string, value: Json): void {
      log.debug("Entering put().");
      if (value !== undefined && value !== null &&
          AuthzenExternalPdp.fits(type, value) &&
          !(type === 'string' && !value) &&
          !(type === 'strings' && !value.length)) {
        context[key] = value;
      }
      log.debug("Leaving put().");
    };
    put('client_id', 'string', input.clientId);
    put('subject_token_type', 'string', input.subjectTokenType);
    put('actor_token_type', 'string', input.actorTokenType);
    const token: Json = {};
    const claim = function (key: string, type: string): void {
      log.debug("Entering claim().");
      const value = claims[key];
      if (value !== undefined && AuthzenExternalPdp.fits(type, value) &&
          !((type === 'string' || type === 'string-or-strings') &&
            value === '')) {
        token[key] = value;
      }
      log.debug("Leaving claim().");
    };
    claim('aud', 'string-or-strings');
    claim('client_id', 'string');
    claim('azp', 'string');
    claim('scope', 'string');
    claim('exp', 'integer');
    if (Object.keys(token).length) {
      context.subject_token = token;
    }
    if (AuthzenExternalPdp.actSendable(input.act)) {
      context.act = input.act;
    }
    if (input.mayAct && typeof input.mayAct === 'object' &&
        !Array.isArray(input.mayAct) &&
        typeof input.mayAct.sub === 'string') {
      context.may_act = input.mayAct;
    }
    put('acr', 'string', claims.acr);
    put('amr', 'strings', claims.amr);
    put('auth_time', 'integer', claims.auth_time);
    put('cnf', 'object', claims.cnf);
    put('jti', 'string', claims.jti);
    log.debug("Leaving AuthzenExternalPdp.contextOf().");
    return context;
  }

  /**
   * Whether an `act` chain is short enough to send. A deeper one is omitted
   * whole, not truncated: a shorter chain would be a different history.
   *
   * @param act - the subject token's `act`
   * @returns whether it may be sent
   */
  static actSendable(act: Json): boolean {
    log.debug("Entering AuthzenExternalPdp.actSendable().");
    if (!act || typeof act !== 'object' || Array.isArray(act)) {
      log.debug("Leaving AuthzenExternalPdp.actSendable(). No.");
      return false;
    }
    let depth = 0;
    let link: Json = act;
    while (link && typeof link === 'object' && !Array.isArray(link)) {
      depth += 1;
      if (depth > MAX_ACT_DEPTH) {
        log.debug("Leaving AuthzenExternalPdp.actSendable(). Too deep.");
        return false;
      }
      link = link.act;
    }
    log.debug("Leaving AuthzenExternalPdp.actSendable(). Yes.");
    return true;
  }

  /**
   * The dial's result as the token endpoint's result. A 2xx is read; every
   * other outcome is no answer.
   *
   * @param reply - what the dial returned
   * @param items - the batch, in order
   * @returns the result
   */
  private outcomeOf(reply: DialReply, items: BatchItem[]): Json {
    const { log: logger, errorCodes } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.outcomeOf().");
    const given = reply && typeof reply === 'object' ? reply
      : { ok: false, status: 0, body: '', kind: '', why: '' };
    if (given.kind === 'url') {
      logger.error(errorCodes.tag('STS-AUTHZEN-0123') +
                   'the external AuthZEN PDP was not dialled (' +
                   (given.why || 'url') + ').');
      logger.debug("Leaving AuthzenExternalPdp.outcomeOf(). URL.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0123');
    }
    const status = Number(given.status) || 0;
    const answered = status >= 200 && status < 300;
    if (!answered) {
      logger.error(errorCodes.tag('STS-AUTHZEN-0124') +
                   'the external AuthZEN PDP did not answer (' +
                   (given.kind || status || 'no-status') + ').');
      logger.debug("Leaving AuthzenExternalPdp.outcomeOf(). No answer.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0124');
    }
    let text = '';
    try {
      text = Buffer.isBuffer(given.body) ? given.body.toString('utf8')
                                         : String(given.body || '');
    } catch (e) {
      const err = e as { message?: string };
      logger.debug("Caught in AuthzenExternalPdp.outcomeOf(): " +
                   ((err && err.message) || e));
      text = '';
    }
    let json: Json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      const err = e as { message?: string };
      logger.debug("Caught in AuthzenExternalPdp.outcomeOf(): " +
                   ((err && err.message) || e));
      // A 2xx that is not JSON is not a decision.
      json = null;
    }
    if (!json || typeof json !== 'object') {
      logger.error(errorCodes.tag('STS-AUTHZEN-0126') +
                   'the external AuthZEN PDP\'s answer was not JSON.');
      logger.debug("Leaving AuthzenExternalPdp.outcomeOf(). Not JSON.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0126');
    }
    const out = this.answerOf(items, json.evaluations);
    logger.debug("Leaving AuthzenExternalPdp.outcomeOf().");
    return out;
  }

  /**
   * What the batch's answer changes. A false subject or party gate refuses
   * the exchange. A false scope drops that scope for every audience. An
   * item the PDP reports as its own error is not a decision.
   *
   * @param items - the batch, in order
   * @param evaluations - the answer's `evaluations`
   * @returns the result
   */
  private answerOf(items: BatchItem[], evaluations: Json): Json {
    const { log: logger, errorCodes } = this.deps;
    logger.debug("Entering AuthzenExternalPdp.answerOf().");
    if (!Array.isArray(evaluations) || evaluations.length !== items.length) {
      logger.error(errorCodes.tag('STS-AUTHZEN-0126') +
                   'the external AuthZEN PDP answered ' +
                   (Array.isArray(evaluations) ? evaluations.length : 'no') +
                   ' evaluation(s) for ' + items.length + ' asked.');
      logger.debug("Leaving AuthzenExternalPdp.answerOf(). Shape.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0126');
    }
    let refused = false;
    let refusedTarget = false;
    const dropped = new Set<string>();
    const grants: string[][] = [];
    let lifetime: number | null = null;
    for (let i = 0; i < items.length; i += 1) {
      const item = evaluations[i];
      if (!item || typeof item !== 'object' || Array.isArray(item) ||
          typeof item.decision !== 'boolean') {
        logger.error(errorCodes.tag('STS-AUTHZEN-0126') +
                     'an external AuthZEN evaluation was not a decision.');
        logger.debug("Leaving AuthzenExternalPdp.answerOf(). Item.");
        return AuthzenExternalPdp.fault('STS-AUTHZEN-0126');
      }
      const erred = item.context && typeof item.context === 'object' &&
        !Array.isArray(item.context) && item.context.error &&
        typeof item.context.error === 'object';
      if (erred) {
        logger.error(errorCodes.tag('STS-AUTHZEN-0126') +
                     'the external AuthZEN PDP did not decide an item.');
        logger.debug("Leaving AuthzenExternalPdp.answerOf(). Item error.");
        return AuthzenExternalPdp.fault('STS-AUTHZEN-0126');
      }
      if (items[i].kind === 'scope') {
        if (item.decision === false) {
          dropped.add(items[i].scope);
        }
        continue;
      }
      if (item.decision === false) {
        refused = true;
        if (items[i].named) {
          refusedTarget = true;
        }
      }
      if (items[i].kind !== 'subject') {
        continue;
      }
      const issuance = AuthzenExternalPdp.issuanceOf(item);
      if (!issuance) {
        continue;
      }
      const life = issuance.token_lifetime;
      if (typeof life === 'number' && Number.isSafeInteger(life) &&
          life > 0) {
        lifetime = lifetime === null ? life : Math.min(lifetime, life);
      }
      const grant = AuthzenExternalPdp.grantOf(issuance.granted_scope);
      // An empty list is a narrowing to nothing. null means the member
      // was absent or not a list of names, and is ignored.
      if (grant !== null) {
        grants.push(grant);
      }
    }
    if (refused) {
      logger.info('authzen: the external PDP refused a token exchange.');
      logger.debug("Leaving AuthzenExternalPdp.answerOf(). Refused.");
      return AuthzenExternalPdp.fault('STS-AUTHZEN-0125',
        refusedTarget ? 'invalid_target' : 'invalid_grant');
    }
    const sent: string[] = [];
    items.forEach(function (one: BatchItem) {
      if (one.kind === 'scope' && sent.indexOf(one.scope) < 0) {
        sent.push(one.scope);
      }
    });
    let narrowed = sent.filter(function (scope: string) {
      return !dropped.has(scope);
    });
    if (grants.length) {
      narrowed = narrowed.filter(function (scope: string) {
        return grants.every(function (grant: string[]) {
          return grant.indexOf(scope) >= 0;
        });
      });
    }
    let scope: string | null = null;
    if (narrowed.length !== sent.length ||
        narrowed.some(function (scopeName: string, index: number) {
          return scopeName !== sent[index];
        })) {
      scope = narrowed.join(' ');
      const lost = sent.filter(function (scopeName: string) {
        return narrowed.indexOf(scopeName) < 0;
      });
      logger.info('authzen: the external PDP dropped ' +
                  (lost.join(' ') || 'nothing') +
                  ' from a token exchange.');
    }
    if (lifetime !== null) {
      logger.info('authzen: the external PDP capped a token exchange\'s ' +
                  'access-token lifetime at ' + lifetime + ' seconds.');
    }
    logger.debug("Leaving AuthzenExternalPdp.answerOf().");
    return {
      ok: true, code: '', status: 0, error: '', description: '',
      scope: scope, lifetimeCapS: lifetime
    };
  }

  /**
   * A result that issues the local decision unchanged.
   *
   * @returns the result
   */
  static unchanged(): Json {
    log.debug("Entering AuthzenExternalPdp.unchanged().");
    log.debug("Leaving AuthzenExternalPdp.unchanged().");
    return { ok: true, code: '', status: 0, error: '', description: '',
             scope: null, lifetimeCapS: null };
  }

  /**
   * A result that issues nothing. The sentence carries neither the code,
   * the gate, nor the PDP's address. A refusal is RFC 8693 section 2.2.2's
   * error for what was refused (#1200's review): `invalid_target` when a
   * gate for an audience or resource the exchange named was false,
   * `invalid_grant` when the gate refused the subject token itself, for
   * an exchange that named no target.
   *
   * @param code - the recorded code
   * @param error - the OAuth error of a refusal; `invalid_grant` by default
   * @returns the result
   */
  static fault(code: string, error?: string): Json {
    log.debug("Entering AuthzenExternalPdp.fault().");
    const refused = code === 'STS-AUTHZEN-0125';
    log.debug("Leaving AuthzenExternalPdp.fault(). " + code);
    return {
      ok: false,
      code: code,
      status: refused ? 400 : 503,
      error: refused ? (error === 'invalid_target' ? 'invalid_target'
                                                   : 'invalid_grant')
                     : 'temporarily_unavailable',
      description: refused ? CLIENT_SENTENCE_REFUSED : CLIENT_SENTENCE_FAULT,
      scope: null,
      lifetimeCapS: null
    };
  }

  /**
   * A party as `{ type, id }`, with a type when the caller sent none.
   *
   * @param party - the caller's party
   * @param fallback - the type when none was sent
   * @returns the party
   */
  static partyOf(party: Json, fallback: string):
      { type: string; id: string } {
    log.debug("Entering AuthzenExternalPdp.partyOf().");
    const given = party && typeof party === 'object' ? party : {};
    const type = typeof given.type === 'string' && given.type
      ? given.type : fallback;
    log.debug("Leaving AuthzenExternalPdp.partyOf().");
    return { type: type, id: String(given.id || '') };
  }

  /**
   * Whether a value is the one JSON type direction A's `readContext`
   * accepts for that context member.
   *
   * @param type - `string`, `strings`, `string-or-strings`, `integer` or
   *   `object`
   * @param value - the value
   * @returns whether it type-checks
   */
  static fits(type: string, value: Json): boolean {
    log.debug("Entering AuthzenExternalPdp.fits().");
    let ok = false;
    if (type === 'string') {
      ok = typeof value === 'string' && value.length <= 2048;
    } else if (type === 'strings') {
      ok = Array.isArray(value) && value.length <= 64 &&
        value.every(function (one: Json) {
          return typeof one === 'string' && one.length <= 256;
        });
    } else if (type === 'string-or-strings') {
      ok = AuthzenExternalPdp.fits('string', value) ||
        AuthzenExternalPdp.fits('strings', value);
    } else if (type === 'integer') {
      ok = typeof value === 'number' && Number.isSafeInteger(value);
    } else {
      ok = !!value && typeof value === 'object' && !Array.isArray(value);
    }
    log.debug("Leaving AuthzenExternalPdp.fits().");
    return ok;
  }

  /**
   * The subject gate's `context.issuance`, or null when the item carries
   * nothing this side reads. A value that is not a plain object is ignored,
   * not treated as a fault.
   *
   * @param item - one evaluation answer
   * @returns the issuance object, or null
   */
  static issuanceOf(item: Json): Json {
    log.debug("Entering AuthzenExternalPdp.issuanceOf().");
    const context = item && item.context;
    let issuance: Json = null;
    if (context && typeof context === 'object' && !Array.isArray(context)) {
      const named = context.issuance;
      if (named && typeof named === 'object' && !Array.isArray(named)) {
        issuance = named;
      }
    }
    log.debug("Leaving AuthzenExternalPdp.issuanceOf()." +
              (issuance ? '' : ' None.'));
    return issuance;
  }

  /**
   * `granted_scope` as a list of scope names, or null when the value is
   * not a string or an array of strings and is therefore ignored. An empty
   * string or an empty array is an empty list: grant nothing.
   *
   * @param value - the issuance member
   * @returns the names, or null
   */
  static grantOf(value: Json): string[] | null {
    log.debug("Entering AuthzenExternalPdp.grantOf().");
    let names: string[] | null = null;
    if (typeof value === 'string') {
      names = value.split(/\s+/).filter(Boolean);
    } else if (Array.isArray(value)) {
      const parts: string[] = [];
      let strings = true;
      value.forEach(function (one: Json) {
        if (typeof one !== 'string') {
          strings = false;
        } else {
          one.split(/\s+/).filter(Boolean).forEach(function (part: string) {
            parts.push(part);
          });
        }
      });
      if (strings) {
        names = parts;
      }
    }
    log.debug("Leaving AuthzenExternalPdp.grantOf().");
    return names;
  }
}

const externalPdp = new AuthzenExternalPdp(AuthzenExternalPdp.defaultDeps());

/**
 * Direction B of the AuthZEN binding for OAuth 2.0 Token Exchange (#1200).
 * @namespace
 */
export = {
  AuthzenExternalPdp: AuthzenExternalPdp,
  /**
   * Forwards to the process's `AuthzenExternalPdp.consult()`.
   *
   * @param input - the exchange the token endpoint is about to issue
   * @returns the consult result
   */
  consult: function (input: Json): Promise<Json> {
    log.debug("Entering consult().");
    const pending = externalPdp.consult(input);
    log.debug("Leaving consult().");
    return pending;
  },
  ACCESS_TOKEN_TYPE: ACCESS_TOKEN_TYPE
};
