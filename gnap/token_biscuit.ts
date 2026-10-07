// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_biscuit.ts
//
// ===========================================================================
// THE `biscuit` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2), BISCUIT V3 ON
// `@biscuit-auth/biscuit-wasm` (2026-09-12).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js`, `common/crypto.js` and `gnap/gnap_access.ts`. The
// WASM library is loaded LAZILY, once, by the first mint or verify, and never
// at require time — requiring this file costs nothing a process that never
// sees a biscuit pays.
//
// **IT NEVER HOLDS THE WASM LIBRARY (#453, rcbj's decision of 2026-10-05).**
// `common/crypto.js` loads it (the loader below is described there), turns
// the realm's Ed25519 KeyObject into the library's key object, and runs it:
// `biscuitMint()`, `biscuitAuthorize()` and `biscuitAttenuate()`. What stays
// here is the Datalog — the authority block's facts and checks, the
// authorizer's facts, the queries the model is read back with — handed over
// as source, parameters and rule text, and the reading of what comes back.
// The Ed25519 block signatures are still made inside the WebAssembly engine,
// which has no hook for an external signer.
//
// ---------------------------------------------------------------------------
// WHAT A BISCUIT IS, AND WHY IT IS THE MACAROON'S OPPOSITE IN ONE RESPECT.
//
// A biscuit is a chain of BLOCKS, each carrying Datalog facts, rules and
// checks, signed with Ed25519: the authority block by the AS's root key, each
// later block by an ephemeral key the previous block committed to. Like a
// macaroon, anybody holding one can append a block (RFC 9767 section 2.2's
// "derive sub-tokens") and nobody can remove one. UNLIKE a macaroon it is
// verified with a PUBLIC key, so a resource server can verify and attenuate
// without the AS sharing a secret with it — that is what the format costs a
// Datalog engine for.
//
// ---------------------------------------------------------------------------
// THE LOADER, AND WHY IT IS NOT `require()`, is `common/crypto.js`'s since
// #453 (its group A, "BISCUITS"): the package is built for a bundler, so it
// is compiled and instantiated by hand, and found by walking `module.paths`
// because its exports map hides `package.json`.
//
// ---------------------------------------------------------------------------
// THREE THINGS ABOUT THIS LIBRARY VERSION THAT COST TIME AND ARE WORTH KNOWING.
//
//   * `authorize()` WITH DEFAULT LIMITS ANSWERS `RunLimit: Timeout`. Its
//     default time budget reads the clock in a way this build cannot, so every
//     call is `authorizeWithLimits()` / `queryWithLimits()` with `LIMITS`
//     below. A timeout is a REFUSAL (STS-GNAP-0325), never a pass. **AND THE
//     FIRST RULE-APPLYING EVALUATION AFTER LOAD CAN BE REFUSED ON ITS RUN
//     LIMITS WHATEVER THE BUDGET** (#432), so the load primes it with a
//     throwaway evaluation (`crypto.js`'s `biscuitPrime()`).
//   * A PARAMETER THAT IS NOT A DATALOG TERM PANICS THE WASM MODULE. A JS
//     `Date` handed to `addCodeWithParameters()` aborts inside Rust with
//     `unreachable`; the term must be `{ date: <ISO string> }`, which is what
//     the package's own `prepareTerm()` does and what `dateTerm()` here does.
//     The panic is caught and the instance kept working in every probe, but a
//     panic is not a control-flow mechanism, so values are prepared rather
//     than trusted.
//   * A BUILDER THAT HAS THROWN IS CONSUMED. `addCode()` with a parse error
//     moves the builder's contents out, and the NEXT call on it panics with
//     "empty BiscuitBuilder". Every attempt here builds a fresh builder.
//
// And one that makes the design possible: `getBlockSource()` prints strings
// UNESCAPED (`"a"b"`), so the printed source cannot be parsed back. The model
// is read with Datalog QUERIES instead, which return typed terms.
//
// ---------------------------------------------------------------------------
// THE FACT VOCABULARY OF THE AUTHORITY BLOCK.
//
//   gnap_token(jti)                 issuer(iss)
//   issued_at(date)                 expires(date)          not_before(date)?
//   subject(sub)?                   audience(id)*          client_instance(id)
//   audience_at(i, id)*             the audience's order, i = 0..
//   access(i, json)                 one per right, i = 0.., json = the right
//   access_ref(string)              for a reference-string right
//   access_type(i, type)  access_action(i, a)  access_location(i, l)
//   access_datatype(i, d) access_privilege(i, p) access_identifier(i, id)
//   flag(f)*                        label(l)?
//   cnf_jkt(tp) | cnf_x5t(tp) | cnf_kid(ref) | bearer(true)
//   actor(i, sub)*                  the actor chain, i = 0 the most recent
//   grant(id)?                      the grant limits are counted against
//   access_limit_amount(i, v, cur)  a right's limits (#432 phase 5), each
//   access_limit_count(i, n)        member with a meaning decomposed:
//   access_limit_receiver(i, r)*    the amount as a decimal STRING (Datalog
//   access_limit_interval(i, text)  has no decimal and a float is not an
//   access_limit_not_before(i, d)   amount), the count an integer, the
//   access_limit_not_after(i, d)    window's ends dates
//
// The limits facts exist for a resource server's OWN attenuation block —
// `check if access_limit_count($i, $n), $n <= 10` — and are authority facts
// for `actor`'s reason below; the model's limits are read back from the
// right's JSON in `access(i, json)`, as every other member is. `grant(id)`
// is the grant a resource server keeps the running totals against (rcbj's
// decision 2 on #432).
//
// `actor(i, sub)` (#432) is RFC 8693 section 4.1's `act` as Datalog: the
// resource server that DERIVED this token (RFC 9767 section 4) at 0, each
// earlier deriver after it — so a resource server's own attenuation block
// can reason about who acted (`check if actor(0, "rs-a")`). It is an
// AUTHORITY fact for the reason every fact the model is read from is: a
// block anybody holding the token may append is a block anybody may write
// an actor into, and an authorizer query sees only the authority block and
// its own facts (see readModel()).
//
// and its checks — so that the token carries its own rules and ANY biscuit
// verifier enforces them, not only this one:
//
//   check if time($t), $t < <exp>;
//   check if time($t), $t >= <nbf>;                           when nbf is set
//   check if presented_key("jkt", $k), cnf_jkt($k);           or x5t / kid
//   check if rs($r), audience($r);                            when aud non-empty
//
// `presented_key` takes the KIND as well as the value — `presented_key("jkt",
// tp)` rather than `presented_key(tp)` — so a key reference that happens to
// equal some thumbprint's text cannot satisfy a check written for the other.
//
// The model is read back from `access(i, json)` rather than reassembled from
// the decomposed facts: the decomposition exists so a Datalog attenuation can
// reason about a right (`check if access_action($i, "read")`), and the JSON is
// what makes the round trip exact, API-specific members included.
//
// ---------------------------------------------------------------------------
// THE AUTHORIZER, AND WHAT AN ATTENUATION BLOCK CAN SEE.
//
// The authorizer supplies `time(now)`, `rs(audience)` when an audience is
// given — and, when it is not, the rule `rs($a) <- audience($a)`, which is the
// Datalog for "this verifier is not an RS and restricts nothing", the same
// reading `gnap_access.checkAudience()` gives a null audience — and
// `presented_key(kind, value)` for each member of the presented key.
//
// It also states the REQUEST: `request_ref(s)` for a required reference string
// and `request_type(i, t)`, `request_action(i, a)`, `request_location(i, l)`,
// `request_datatype(i, d)`, `request_privilege(i, p)`,
// `request_identifier(i, id)` for a required object. That is how an attenuation
// block narrows ACCESS: `reject if request_action($i, $a), $a != "read";` is a
// read-only sub-token. A block cannot hand facts to the authorizer — Biscuit
// scopes a block's facts to that block's own rules — so a narrowing has to be
// a check over the request, not a second access list. **A `reject if` over
// request facts passes vacuously when the RS states no requirement**; a
// resource server relying on an attenuation of that kind must state one, and
// a block that must fail closed uses `check if request_…` instead.
//
// ORDER OF VERIFICATION: signature (parse with the root public key), model
// (queries over the authority block), the shared checks
// (`gnap_access.checkPresentation()`, so time, audience and binding refuse with
// the same codes as every other format), then the authorizer — which runs the
// authority block's own checks again and every attenuation block's. A failure
// that survives the shared checks is therefore an attenuation, and is refused
// with STS-GNAP-0324 naming the check that failed.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `TokenBiscuit` takes the logger, the clock, the error-code table, the
// access model (`gnap_access`) and `common/crypto.js` (which loads and holds
// the WASM library, #453) through its constructor. The module still exports
// its old names as FACADES forwarding to
// the instance the composition root builds (#50, R2), for the unconverted
// modules and the tests that require it. A process that loads this module
// without the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import gnapAccess = require('./gnap_access');
// The limits vocabulary (#432 phase 5), for a right's limit facts.
import AccessLimits = require('../common/access_limits');

interface TokenBiscuitDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  nowSec(): number;
  errorCodes: { tag(code: string): string };
  // `gnap_access`: the model, its refusals and its presentation checks.
  access: any;
  // `common/crypto.js`: the only holder of the biscuit library (#453).
  stsCrypto: {
    biscuitReady(): Promise<void>;
    biscuitMint(privateKey: any, prepare: () => any): Promise<any>;
    biscuitAuthorize(value: string, publicKey: any, run: any): Promise<any>;
    biscuitAttenuate(value: string, publicKey: any,
                     prepare: () => any): Promise<any>;
  };
}

// A Datalog source and its parameters, built together.
interface Program {
  add(template: string, values?: unknown[]): void;
  source(): string;
  params: Record<string, unknown>;
}

const FORMAT = 'biscuit';
// The package's name, for `describe()`; `common/crypto.js` loads it.
const PACKAGE = '@biscuit-auth/biscuit-wasm';

// Generous against this service's own tokens (a model of fifty rights with
// every dimension populated is a few hundred facts, evaluated in well under a
// millisecond) and still a bound on a hostile attenuation block.
const LIMITS = { max_facts: 10000, max_iterations: 100,
                 max_time_micro: 250000 };

const VALUE_RE = /^[A-Za-z0-9_-]+={0,2}$/;

// The queries the model is read back with, IN THE ORDER `readModel()` reads
// them: `common/crypto.js` runs them in this order and stops at the first
// that throws, and `query()` rethrows that error where `readModel()` reaches
// the query that threw — so the answer is the one a query-by-query read
// gave before #453.
const MODEL_QUERIES = [
  'data($v) <- gnap_token($v)',
  'data($v) <- issuer($v)',
  'data($v) <- issued_at($v)',
  'data($v) <- expires($v)',
  'data($v) <- not_before($v)',
  'data($v) <- subject($v)',
  'data($v) <- client_instance($v)',
  'data($v) <- label($v)',
  'data($v) <- grant($v)',
  'data($v) <- audience($v)',
  'data($i, $v) <- audience_at($i, $v)',
  'data($v) <- flag($v)',
  'data($i, $j) <- access($i, $j)',
  'data($i, $s) <- actor($i, $s)',
  'data($v) <- cnf_jkt($v)',
  'data($v) <- cnf_x5t($v)',
  'data($v) <- cnf_kid($v)',
  'data($v) <- bearer($v)'
];

/**
 * The `biscuit` GNAP token format (RFC 9767 section 5.3.2): Biscuit v3 on
 * `@biscuit-auth/biscuit-wasm`, loaded lazily on the first mint or verify.
 *
 * A route-free library; a biscuit is verified with a public key, so a resource
 * server can verify and attenuate one without a shared secret.
 */
class TokenBiscuit {
  /**
   * The format's name, `biscuit`.
   */
  static readonly FORMAT = FORMAT;
  /**
   * The Datalog run limits every authorization is bounded by (facts, iterations
   * and time).
   */
  static readonly LIMITS = LIMITS;

  /**
   * Builds the format from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: TokenBiscuitDeps) {
    deps.log.debug("Entering TokenBiscuit.constructor().");
    deps.log.debug("Leaving TokenBiscuit.constructor().");
  }

  private refusal(code: string, why: string): any {
    const { log, access } = this.deps;
    log.debug("Entering TokenBiscuit.refusal().");
    log.debug("Leaving TokenBiscuit.refusal().");
    return access.refusal(code, why);
  }

  // -------------------------------------------------------------------------
  // The library, loaded by `common/crypto.js` (once, lazily; a failure is
  // retried by the next call). A load failure is this format's refusal.
  // -------------------------------------------------------------------------
  private loadRefusal(e: any): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering TokenBiscuit.loadRefusal().");
    log.error(errorCodes.tag('STS-GNAP-0321') + 'the biscuit WASM ' +
              'library could not be loaded: ' +
              e.message);
    log.debug("Leaving TokenBiscuit.loadRefusal().");
    return this.refusal('STS-GNAP-0321',
                        'the biscuit library could not be loaded: ' +
                        e.message);
  }

  private async library(): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering TokenBiscuit.library().");
    try {
      await stsCrypto.biscuitReady();
      log.debug("Leaving TokenBiscuit.library().");
      return { ok: true };
    } catch (e) {
      log.debug("Caught in TokenBiscuit.library(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenBiscuit.library().");
      return this.loadRefusal(e);
    }
  }

  // The library's errors are plain objects (`{ Format: { Signature: … } }`);
  // render one for a `why` without trusting its shape.
  private errorText(e: unknown): string {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.errorText().");
    if (e instanceof Error) {
      log.debug("Leaving TokenBiscuit.errorText().");
      return e.message;
    }
    try {
      log.debug("Leaving TokenBiscuit.errorText().");
      return JSON.stringify(e);
    } catch (err) {
      log.debug("Caught in TokenBiscuit.errorText(): " +
                ((err && err.message) || err));
      log.debug("Leaving TokenBiscuit.errorText().");
      // A cyclic or exotic value: String() is the best available
      // description.
      return String(e);
    }
  }

  private dateTerm(seconds: number): { date: string } {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.dateTerm().");
    log.debug("Leaving TokenBiscuit.dateTerm().");
    return { date: new Date(seconds * 1000).toISOString() };
  }

  // Datalog source plus parameters, built together so a parameter name can
  // never be out of step with its placeholder.
  private program(): Program {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.program().");
    const lines = [];
    const params = {};
    let n = 0;
    log.debug("Leaving TokenBiscuit.program().");
    return {
      add: function (template, values) {
        log.debug("Entering add().");
        let line = template;
        (values || []).forEach(function (v) {
          const name = 'p' + (n++);
          params[name] = v;
          line = line.replace('?', '{' + name + '}');
        });
        lines.push(line);
        log.debug("Leaving add().");
      },
      source: function () {
        log.debug("Entering source().");
        log.debug("Leaving source().");
        return lines.join('\n');
      },
      params: params
    };
  }

  // The facts and checks of the authority block (see the header).
  // A right's limits as authority facts (#432 phase 5; the header). Only
  // the members `common/access_limits.ts` gives a meaning, read as it reads
  // them; another member is in the right's JSON and nowhere else.
  private addLimitFacts(p: Program, i: number, limits: any): void {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.addLimitFacts().");
    if (!limits || typeof limits !== 'object') {
      log.debug("Leaving TokenBiscuit.addLimitFacts(). None.");
      return;
    }
    if (limits.amount !== undefined) {
      p.add('access_limit_amount(?, ?, ?);',
            [i, String(limits.amount), String(limits.currency || '')]);
    }
    if (Number.isSafeInteger(limits.count)) {
      p.add('access_limit_count(?, ?);', [i, limits.count]);
    }
    (AccessLimits.receiversOf(limits) || []).forEach(function (r: string) {
      p.add('access_limit_receiver(?, ?);', [i, r]);
    });
    if (typeof limits.interval === 'string') {
      p.add('access_limit_interval(?, ?);', [i, limits.interval]);
    }
    const window = limits.window || {};
    const nb = AccessLimits.timeOf(window.notBefore);
    const na = AccessLimits.timeOf(window.notAfter);
    if (nb !== null) {
      p.add('access_limit_not_before(?, ?);', [i, this.dateTerm(nb)]);
    }
    if (na !== null) {
      p.add('access_limit_not_after(?, ?);', [i, this.dateTerm(na)]);
    }
    log.debug("Leaving TokenBiscuit.addLimitFacts().");
  }

  private authorityProgram(model: any): Program {
    const { log, access } = this.deps;
    const self = this;
    log.debug("Entering TokenBiscuit.authorityProgram().");
    const p = this.program();
    p.add('gnap_token(?);', [model.jti]);
    p.add('issuer(?);', [model.iss]);
    p.add('issued_at(?);', [this.dateTerm(model.iat)]);
    p.add('expires(?);', [this.dateTerm(model.exp)]);
    if (model.nbf !== null) {
      p.add('not_before(?);', [this.dateTerm(model.nbf)]);
    }
    if (model.sub !== null) {
      p.add('subject(?);', [model.sub]);
    }
    model.aud.forEach(function (a, i) {
      p.add('audience(?);', [a]);
      // The ORDER, which a set of facts does not keep (#432: adding the
      // actor facts reshuffled what the queries answered, and the round
      // trip of a two-audience model failed). `audience(id)` stays what the
      // checks and an attenuation block test; this is only how the model
      // is read back in the order it was written.
      p.add('audience_at(?, ?);', [i, a]);
    });
    p.add('client_instance(?);', [model.instanceId]);
    model.access.forEach(function (right, i) {
      p.add('access(?, ?);', [i, JSON.stringify(right)]);
      if (typeof right === 'string') {
        p.add('access_ref(?);', [right]);
        return;
      }
      p.add('access_type(?, ?);', [i, right.type]);
      [['actions', 'access_action'], ['locations', 'access_location'],
       ['datatypes', 'access_datatype'],
       ['privileges', 'access_privilege']].forEach(function (pair) {
        (right[pair[0]] ||
         []).forEach(function (v) {
          p.add(pair[1] + '(?, ?);', [i, v]);
        });
      });
      if (right.identifier !== undefined) {
        p.add('access_identifier(?, ?);', [i, right.identifier]);
      }
      self.addLimitFacts(p, i, right.limits);
    });
    model.flags.forEach(function (f) {
      p.add('flag(?);', [f]);
    });
    if (model.label !== null) {
      p.add('label(?);', [model.label]);
    }
    (access.actorChain(model.act) || []).forEach(function (sub, i) {
      p.add('actor(?, ?);', [i, sub]);
    });
    if (model.grant) {
      p.add('grant(?);', [model.grant]);
    }
    if (!model.cnf) {
      p.add('bearer(true);');
    } else if (model.cnf.jkt) {
      p.add('cnf_jkt(?);', [model.cnf.jkt]);
      p.add('check if presented_key("jkt", $k), cnf_jkt($k);');
    } else if (model.cnf['x5t#S256']) {
      p.add('cnf_x5t(?);', [model.cnf['x5t#S256']]);
      p.add('check if presented_key("x5t#S256", $k), cnf_x5t($k);');
    } else {
      p.add('cnf_kid(?);', [model.cnf.kid]);
      p.add('check if presented_key("kid", $k), cnf_kid($k);');
    }
    p.add('check if time($t), $t < ?;', [this.dateTerm(model.exp)]);
    if (model.nbf !== null) {
      p.add('check if time($t), $t >= ?;', [this.dateTerm(model.nbf)]);
    }
    if (model.aud.length) {
      p.add('check if rs($r), audience($r);');
    }
    log.debug("Leaving TokenBiscuit.authorityProgram().");
    return p;
  }

  // -------------------------------------------------------------------------
  // mint(model, keys): keys = { privateKey: node KeyObject, Ed25519 }.
  // -------------------------------------------------------------------------
  /**
   * Mints a biscuit carrying an access model, its authority block signed with
   * the AS's Ed25519 root key.
   *
   * @param model - the token model `gnap_access` validates
   * @param keys - `{ privateKey }`, an Ed25519 node KeyObject
   * @returns `{ value, format, jti }`, or a refusal
   */
  async mint(model: any, keys: any): Promise<any> {
    const { log, errorCodes, access, stsCrypto } = this.deps;
    log.debug("Entering TokenBiscuit.mint().");
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenBiscuit.mint(). Model invalid.");
      return valid;
    }
    // THE REVOCATION IDENTIFIERS (#432): one per block, hex, each the
    // signature that block was sealed with — the authority block's first.
    // Read at mint (by `crypto.biscuitMint()`) because this is the only
    // moment the AS holds the token's value (the store keeps its digest),
    // and published by `/gnap/biscuit/revocations` once the token is
    // revoked. A derivative a resource server attenuates offline keeps the
    // authority block, so the authority id revokes it too.
    const minted = await stsCrypto.biscuitMint(
        keys && keys.privateKey, () => {
          const p = this.authorityProgram(valid.model);
          return { source: p.source(), params: p.params };
        });
    if (!minted.ok && minted.stage === 'key') {
      log.debug("Leaving TokenBiscuit.mint(). Private key unusable.");
      return this.refusal('STS-GNAP-0320', 'a biscuit is minted with an ' +
                          'Ed25519 private KeyObject.');
    }
    if (!minted.ok && minted.stage === 'load') {
      log.debug("Leaving TokenBiscuit.mint(). Library unavailable.");
      return this.loadRefusal(minted.error);
    }
    if (!minted.ok) {
      const e = minted.error;
      log.warn(errorCodes.tag('STS-GNAP-0320') + 'biscuit minting failed ' +
               'in the library: ' + this.errorText(e));
      log.debug("Leaving TokenBiscuit.mint(). Library failure.");
      return this.refusal('STS-GNAP-0320',
                          'the biscuit library refused to mint: ' +
                          this.errorText(e));
    }
    const value = minted.value;
    const revocationIds: string[] = minted.revocationIds;
    if (!VALUE_RE.test(value)) {
      // token68 (RFC 9110 section 11.2) allows `=` only at the end. The
      // library emits URL-safe base64; this is the check that it still does.
      log.warn(errorCodes.tag('STS-GNAP-0320') + 'the biscuit library ' +
               'emitted a value that is not token68.');
      log.debug("Leaving TokenBiscuit.mint(). Not token68.");
      return this.refusal('STS-GNAP-0320', 'the biscuit library emitted a ' +
                          'value that is not token68.');
    }
    if (!revocationIds.length ||
        !revocationIds.every(function (one) {
          return /^[0-9a-f]+$/.test(one);
        })) {
      // A biscuit this AS could never publish as revoked would be one a
      // resource server checking it offline must accept until it expires;
      // it is not minted.
      log.warn(errorCodes.tag('STS-GNAP-0750') + 'the biscuit library gave ' +
               'no usable revocation identifiers for a minted token.');
      log.debug("Leaving TokenBiscuit.mint(). No revocation identifiers.");
      return this.refusal('STS-GNAP-0750', 'the biscuit\'s revocation ' +
                          'identifiers could not be read.');
    }
    log.debug("Leaving TokenBiscuit.mint(). jti=" + valid.model.jti);
    return { value: value, format: FORMAT, jti: valid.model.jti,
             revocationIds: revocationIds };
  }

  // The value's own shape, checked before `crypto.js` is handed it.
  private valueRefusal(value: unknown): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.valueRefusal().");
    if (typeof value !== 'string' || !VALUE_RE.test(value)) {
      log.debug("Leaving TokenBiscuit.valueRefusal(). Not base64url.");
      return this.refusal('STS-GNAP-0322', 'the token value is not ' +
                          'URL-safe base64.');
    }
    log.debug("Leaving TokenBiscuit.valueRefusal().");
    return null;
  }

  // A `crypto.js` answer that stopped at the key or the parse, as this
  // format's refusal; null for any other stage.
  private parseRefusal(answer: any): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.parseRefusal().");
    if (answer.stage === 'key') {
      log.debug("Leaving TokenBiscuit.parseRefusal(). Public key unusable.");
      return this.refusal('STS-GNAP-0320', 'a biscuit is verified with an ' +
                          'Ed25519 public KeyObject.');
    }
    if (answer.stage === 'parse') {
      log.debug("Leaving TokenBiscuit.parseRefusal(). " +
                this.errorText(answer.error));
      return this.refusal('STS-GNAP-0322', 'the biscuit did not parse, or ' +
                          'its signature chain does not verify under this ' +
                          'authorization server\'s public key: ' +
                          this.errorText(answer.error));
    }
    if (answer.stage === 'load') {
      log.debug("Leaving TokenBiscuit.parseRefusal(). Library unavailable.");
      return this.loadRefusal(answer.error);
    }
    log.debug("Leaving TokenBiscuit.parseRefusal().");
    return null;
  }

  // The request facts an attenuation block may reason about (see the
  // header).
  private requestProgram(p: Program, requiredAccess: any[]): void {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.requestProgram().");
    (requiredAccess || []).forEach(function (right, i) {
      if (typeof right === 'string') {
        p.add('request_ref(?);', [right]);
        return;
      }
      if (!right || typeof right !== 'object' ||
          typeof right.type !== 'string') {
        return;
      }
      p.add('request_type(?, ?);', [i, right.type]);
      [['actions', 'request_action'], ['locations', 'request_location'],
       ['datatypes', 'request_datatype'],
       ['privileges', 'request_privilege']].forEach(function (pair) {
        (Array.isArray(right[pair[0]]) ? right[pair[0]] : []).forEach(
            function (v) {
          if (typeof v === 'string') {
            p.add(pair[1] + '(?, ?);', [i, v]);
          }
        });
      });
      if (typeof right.identifier === 'string') {
        p.add('request_identifier(?, ?);', [i, right.identifier]);
      }
    });
    log.debug("Leaving TokenBiscuit.requestProgram().");
  }

  // The authorizer's facts and its one policy (see the header), as
  // `{ source, params }` for `crypto.biscuitAuthorize()`.
  private authorizerProgram(context: any, now: number): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.authorizerProgram().");
    const ctx = context || {};
    const p = this.program();
    p.add('time(?);', [this.dateTerm(now)]);
    if (typeof ctx.audience === 'string') {
      p.add('rs(?);', [ctx.audience]);
    } else {
      p.add('rs($a) <- audience($a);');
    }
    const presented = ctx.presentedKey || {};
    ['jkt', 'x5t#S256', 'kid'].forEach(function (member) {
      if (typeof presented[member] === 'string') {
        p.add('presented_key(?, ?);', [member, presented[member]]);
      }
    });
    if (Array.isArray(ctx.requiredAccess)) {
      this.requestProgram(p, ctx.requiredAccess);
    }
    p.add('allow if true;');
    log.debug("Leaving TokenBiscuit.authorizerProgram().");
    return { source: p.source(), params: p.params };
  }

  // One model query's answer (`MODEL_QUERIES`): its rows when it ran, and
  // the error `crypto.js` stopped at when it did not.
  private query(answers: any, rule: string): any[][] {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.query().");
    const i = MODEL_QUERIES.indexOf(rule);
    if (i < 0 || i >= answers.rows.length) {
      log.debug("Leaving TokenBiscuit.query(). Not answered.");
      throw answers.queryError ||
            new Error('the biscuit query "' + rule + '" was not run');
    }
    log.debug("Leaving TokenBiscuit.query().");
    return answers.rows[i];
  }

  private seconds(term: unknown): number | undefined {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.seconds().");
    log.debug("Leaving TokenBiscuit.seconds().");
    return term instanceof Date ? Math.floor(term.getTime() / 1000) :
      undefined;
  }

  // -------------------------------------------------------------------------
  // The authority block's facts back into a model. Authorizer queries see the
  // authority block and the authorizer's own facts, never an attenuation
  // block's, so nothing a later block says can reach the model.
  // -------------------------------------------------------------------------
  private readModel(answers: any): any {
    const { log, access } = this.deps;
    const self = this;
    log.debug("Entering TokenBiscuit.readModel().");
    function one(rule: string) {
      log.debug("Entering one().");
      const rows = self.query(answers, rule);
      log.debug("Leaving one().");
      return rows.length === 1 ? rows[0][0] :
             (rows.length === 0 ? null : undefined);
    }
    const jti = one('data($v) <- gnap_token($v)');
    const iss = one('data($v) <- issuer($v)');
    const iat = one('data($v) <- issued_at($v)');
    const exp = one('data($v) <- expires($v)');
    const nbf = one('data($v) <- not_before($v)');
    const sub = one('data($v) <- subject($v)');
    const client = one('data($v) <- client_instance($v)');
    const label = one('data($v) <- label($v)');
    const grant = one('data($v) <- grant($v)');
    const audSet = this.query(answers, 'data($v) <- audience($v)')
      .map(function (r) {
        return r[0];
      });
    const audRows = this.query(answers,
                               'data($i, $v) <- audience_at($i, $v)')
      .sort(function (a, b) {
        return a[0] - b[0];
      });
    const aud = audRows.map(function (r) {
      return r[1];
    });
    if (audRows.some(function (r, i) { return r[0] !== i; }) ||
        aud.length !== audSet.length ||
        audSet.some(function (one) { return aud.indexOf(one) < 0; })) {
      log.debug("Leaving TokenBiscuit.readModel(). The audience facts " +
                "disagree.");
      return this.refusal('STS-GNAP-0323', 'the biscuit\'s audience_at ' +
                          'facts are not 0..n-1 over exactly its audience ' +
                          'facts.');
    }
    const flags = this.query(answers, 'data($v) <- flag($v)').map(
        function (r) {
          return r[0];
        });
    const rows = this.query(answers,
                            'data($i, $j) <- access($i, $j)')
      .sort(function (a, b) {
        return a[0] - b[0];
      });
    const rights = [];
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] !== i || typeof rows[i][1] !== 'string') {
        log.debug("Leaving TokenBiscuit.readModel(). access indices are not " +
                  "0..n-1.");
        return this.refusal('STS-GNAP-0323', 'the biscuit\'s access facts ' +
                            'are not numbered 0..n-1.');
      }
      try {
        rights.push(JSON.parse(rows[i][1]));
      } catch (e) {
        log.debug("Caught in TokenBiscuit.readModel(): " +
                  ((e && e.message) || e));
        log.debug("Leaving TokenBiscuit.readModel(). access " + i +
                  " is not JSON.");
        return this.refusal('STS-GNAP-0323', 'the biscuit\'s access fact ' +
                            i + ' ' + 'is not JSON.');
      }
    }
    const actorRows = this.query(answers,
                                 'data($i, $s) <- actor($i, $s)')
      .sort(function (a, b) {
        return a[0] - b[0];
      });
    const actors: string[] = [];
    for (let i = 0; i < actorRows.length; i++) {
      if (actorRows[i][0] !== i || typeof actorRows[i][1] !== 'string') {
        log.debug("Leaving TokenBiscuit.readModel(). actor indices are not " +
                  "0..n-1.");
        return this.refusal('STS-GNAP-0323', 'the biscuit\'s actor facts ' +
                            'are not numbered 0..n-1 with one actor each.');
      }
      actors.push(actorRows[i][1]);
    }
    const jkt = one('data($v) <- cnf_jkt($v)');
    const x5t = one('data($v) <- cnf_x5t($v)');
    const kid = one('data($v) <- cnf_kid($v)');
    const bearer = this.query(answers,
                              'data($v) <- bearer($v)').length;
    const bindings = [jkt, x5t, kid].filter(function (v) {
      return v !== null;
    });
    if ([jti, iss, iat, exp, nbf, sub, client, label, grant, jkt, x5t,
         kid].some(
        function (v) {
          return v === undefined;
        }) ||
        bindings.length + bearer !== 1) {
      log.debug("Leaving TokenBiscuit.readModel(). A singular fact is " +
                "repeated, or the binding is not exactly one.");
      return this.refusal('STS-GNAP-0323', 'the biscuit\'s authority block ' +
                          'repeats a fact that must be singular, or does ' +
                          'not carry exactly one key binding.');
    }
    let cnf = null;
    if (jkt !== null) {
      cnf = { jkt: jkt };
    } else if (x5t !== null) {
      cnf = { 'x5t#S256': x5t };
    } else if (kid !== null) {
      cnf = { kid: kid };
    }
    const model = {
      jti: jti, iss: iss, sub: sub, aud: aud, instanceId: client,
      access: rights,
      flags: flags,
      cnf: cnf, iat: this.seconds(iat),
      nbf: nbf === null ? null : this.seconds(nbf),
      exp: this.seconds(exp),
      label: label,
      act: access.nestActors(actors),
      grant: grant
    };
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenBiscuit.readModel(). Not a valid model.");
      return this.refusal('STS-GNAP-0323', 'the biscuit\'s authority block ' +
                          'is not a GNAP token model: ' +
                          valid.why);
    }
    log.debug("Leaving TokenBiscuit.readModel(). Read.");
    return valid;
  }

  private authorizationRefusal(e: any): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.authorizationRefusal().");
    const failed = e && e.FailedLogic && e.FailedLogic.Unauthorized &&
                   e.FailedLogic.Unauthorized.checks;
    if (e && e.RunLimit) {
      log.debug("Leaving TokenBiscuit.authorizationRefusal(). Run limit.");
      return this.refusal('STS-GNAP-0325', 'biscuit authorization exceeded ' +
                          'its run limits (' +
                          this.errorText(e.RunLimit) + '), which is a ' +
                          'refusal and never a pass.');
    }
    const rules = (Array.isArray(failed) ? failed : []).map(function (c) {
      const where = c.Block || c.Authorizer || {};
      return (c.Block ? 'block ' + where.block_id + ': ' :
              'authorizer: ') + where.rule;
    });
    log.debug("Leaving TokenBiscuit.authorizationRefusal(). " +
              rules.length + " failed " + "check(s).");
    return this.refusal('STS-GNAP-0324', 'a biscuit check failed' +
                        (rules.length ? ' — ' + rules.join('; ') :
                         ': ' + this.errorText(e)) + '.');
  }

  // -------------------------------------------------------------------------
  // verify(value, keys, context) -> { ok:true, model, attenuated } | refusal.
  // keys = { publicKey: node KeyObject, Ed25519 }.
  // -------------------------------------------------------------------------
  /**
   * Verifies a biscuit against the AS's public key and checks it against the
   * presentation context.
   *
   * @param value - the presented token value
   * @param keys - `{ publicKey }`, an Ed25519 node KeyObject
   * @param context - the presentation to check the token against
   * @returns `{ ok: true, model, attenuated }`, or a refusal
   */
  async verify(value: unknown, keys: any, context?: any): Promise<any> {
    const { log, access, nowSec, stsCrypto } = this.deps;
    log.debug("Entering TokenBiscuit.verify().");
    const lib = await this.library();
    if (!lib.ok) {
      log.debug("Leaving TokenBiscuit.verify(). Library unavailable.");
      return lib;
    }
    const badValue = this.valueRefusal(value);
    if (badValue) {
      log.debug("Leaving TokenBiscuit.verify(). Parse refused.");
      return badValue;
    }
    const ctx = context || {};
    const now = Number.isSafeInteger(ctx.now) ? ctx.now : nowSec();
    // The token is verified, the authorizer built, the model queries and
    // the authorization run, all in `crypto.js` and in that order; what
    // each answered is read here in the order it always was.
    const answers = await stsCrypto.biscuitAuthorize(value as string,
                                                     keys && keys.publicKey, {
      authorizer: () => this.authorizerProgram(ctx, now),
      queries: MODEL_QUERIES,
      limits: LIMITS
    });
    if (!answers.ok) {
      const refused = this.parseRefusal(answers);
      if (refused) {
        log.debug("Leaving TokenBiscuit.verify(). Parse refused.");
        return refused;
      }
      log.debug("Leaving TokenBiscuit.verify(). Authorizer could not be " +
                "built: " + this.errorText(answers.error));
      return this.refusal('STS-GNAP-0324', 'the biscuit authorizer could ' +
                          'not be built for this presentation: ' +
                          this.errorText(answers.error));
    }
    let read;
    try {
      read = this.readModel(answers);
    } catch (e) {
      log.debug("Caught in TokenBiscuit.verify(): " + this.errorText(e));
      log.debug("Leaving TokenBiscuit.verify(). Model query failed: " +
                this.errorText(e));
      return e && e.RunLimit ? this.authorizationRefusal(e)
        : this.refusal('STS-GNAP-0323', 'the biscuit\'s authority block ' +
                       'could not be read: ' + this.errorText(e));
    }
    if (!read.ok) {
      log.debug("Leaving TokenBiscuit.verify(). Model refused.");
      return read;
    }
    const failed = access.checkPresentation(read.model,
                                            Object.assign({}, ctx,
                                                          { now: now }));
    if (failed) {
      log.debug("Leaving TokenBiscuit.verify(). Presentation refused.");
      return failed;
    }
    if (answers.authorizeError) {
      log.debug("Leaving TokenBiscuit.verify(). Authorization refused: " +
                this.errorText(answers.authorizeError));
      return this.authorizationRefusal(answers.authorizeError);
    }
    const blocks = answers.blocks;
    log.debug("Leaving TokenBiscuit.verify(). Verified jti=" +
              read.model.jti + " blocks=" + blocks);
    return { ok: true, model: read.model, attenuated: blocks > 1 };
  }

  // -------------------------------------------------------------------------
  // attenuate(value, datalogSource, keys[, parameters]): append a block of
  // checks — what a resource server does to derive a narrower token without
  // calling the AS (RFC 9767 section 2.2). `keys.publicKey` is needed because
  // this library will not open a token without verifying it, which is the
  // right default; a block cannot hold a policy (`allow if`) and the library
  // refuses one. Returns `{ ok:true, value, format }` or a refusal.
  // -------------------------------------------------------------------------
  /**
   * Appends a block of checks to a biscuit, deriving a narrower token without
   * calling the AS (RFC 9767 section 2.2).
   *
   * The token is verified first; a block holding a policy (`allow if`) is
   * refused by the library.
   *
   * @param value - the biscuit to attenuate
   * @param datalogSource - the Datalog checks of the new block
   * @param keys - `{ publicKey }` the biscuit verifies against
   * @param parameters - values for the block's parameters
   * @returns `{ ok: true, value, format }`, or a refusal
   */
  async attenuate(value: unknown, datalogSource: unknown, keys: any,
                  parameters?: Record<string, unknown>): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering TokenBiscuit.attenuate().");
    if (typeof datalogSource !== 'string' || !datalogSource.trim()) {
      log.debug("Leaving TokenBiscuit.attenuate(). No source.");
      return this.refusal('STS-GNAP-0326', 'an attenuation is a non-empty ' +
                          'block of Datalog.');
    }
    const lib = await this.library();
    if (!lib.ok) {
      log.debug("Leaving TokenBiscuit.attenuate(). Library unavailable.");
      return lib;
    }
    const badValue = this.valueRefusal(value);
    if (badValue) {
      log.debug("Leaving TokenBiscuit.attenuate(). Parse refused.");
      return badValue;
    }
    // The block's parameters are checked once the token has parsed, as
    // they always were: `crypto.js` calls this after the parse.
    const prepare = () => {
      const params = {};
      const given = parameters || {};
      const names = Object.keys(given);
      for (let i = 0; i < names.length; i++) {
        const v = given[names[i]];
        if (typeof v === 'string' || typeof v === 'boolean' ||
            Number.isSafeInteger(v)) {
          params[names[i]] = v;
        } else if (v instanceof Date) {
          params[names[i]] = { date: v.toISOString() };
        } else {
          log.debug("Parameter " + names[i] + " is not a term.");
          return { refusal: this.refusal('STS-GNAP-0326',
                                         'attenuation parameter "' +
                                         names[i] + '" must be a string, ' +
                                         'boolean, integer or Date.') };
        }
      }
      return { source: datalogSource, params: params };
    };
    const appended = await stsCrypto.biscuitAttenuate(
        value as string, keys && keys.publicKey, prepare);
    if (!appended.ok) {
      const refused = appended.stage === 'prepare' ? appended.refusal
        : this.parseRefusal(appended);
      if (refused) {
        log.debug("Leaving TokenBiscuit.attenuate(). Refused at " +
                  appended.stage + ".");
        return refused;
      }
      log.debug("Leaving TokenBiscuit.attenuate(). Library refused: " +
                this.errorText(appended.error));
      return this.refusal('STS-GNAP-0326',
                          'the attenuation block was refused: ' +
                          this.errorText(appended.error));
    }
    const out = appended.value;
    log.debug("Leaving TokenBiscuit.attenuate(). Appended.");
    return { ok: true, value: out, format: FORMAT };
  }

  /**
   * Describes the format for the console: its library, algorithms and the
   * fields it carries.
   *
   * @returns the format's description
   */
  describe() {
    const { log, access } = this.deps;
    log.debug("Entering TokenBiscuit.describe().");
    const out = {
      name: FORMAT,
      libraries: [access.libraryInfo(PACKAGE)],
      algorithms: [
        ['Root signature', ['Ed25519']],
        ['Block chaining', ['Ed25519, an ephemeral key per block']],
        ['Serialisation', ['Protobuf, URL-safe base64']],
        ['Authorization logic', ['Datalog (Biscuit v3), bounded by run ' +
                                 'limits']]
      ],
      carries: ['jti', 'iss', 'sub', 'aud', 'instanceId', 'access', 'flags',
                'cnf',
                'iat', 'nbf', 'exp', 'label', 'act', 'grant'],
      cannot: []
    };
    log.debug("Leaving TokenBiscuit.describe().");
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): TokenBiscuitDeps {
    helpers.log.debug("Entering TokenBiscuit.defaultDeps().");
    helpers.log.debug("Leaving TokenBiscuit.defaultDeps().");
    return {
      log: helpers.log,
      nowSec: function () {
        return helpers.nowSec();
      },
      errorCodes: errorCodes,
      access: gnapAccess,
      stsCrypto: stsCrypto
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<TokenBiscuit>(
  'gnap/token_biscuit',
  () => new TokenBiscuit(TokenBiscuit.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The `biscuit` GNAP token format (RFC 9767 section 5.3.2).
 *
 * A route-free library: mint, verify, attenuate and describe.
 *
 * @namespace
 */
export = {
  TokenBiscuit: TokenBiscuit,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: TokenBiscuit): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  FORMAT: TokenBiscuit.FORMAT,
  LIMITS: TokenBiscuit.LIMITS,
  mint: slot.forward('mint'),
  verify: slot.forward('verify'),
  attenuate: slot.forward('attenuate'),
  describe: slot.forward('describe')
};
