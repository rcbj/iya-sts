'use strict';
//
// File: token_biscuit.ts
//
// ===========================================================================
// THE `biscuit` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2), BISCUIT V3 ON
// `@biscuit-auth/biscuit-wasm` (2026-09-12).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js` and `gnap/gnap_access.ts`. The WASM library is
// loaded LAZILY, once, by the first mint or verify, and never at require time —
// requiring this file costs nothing a process that never sees a biscuit pays.
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
// THE LOADER, AND WHY IT IS NOT `require()`.
//
// The package is built with wasm-pack's `bundler` target: its entry point is
// `import * as wasm from "./biscuit_bg.wasm"`, which only a bundler resolves,
// and its exports map has an `import` condition and nothing else. So
// `require()` and `import()` of the package both fail in node. `loadBiscuit()`
// does what a bundler would: compile `module/biscuit_bg.wasm`, build the import
// object by importing every module `WebAssembly.Module.imports()` names
// (relative to `module/`), instantiate, hand the instance to the glue with
// `__wbg_set_wasm()` and call `__wbindgen_start()`. The package directory is
// found by `gnap_access.packageDir()`, because the exports map hides
// `package.json` from `require.resolve` as well.
//
// `__wbindgen_start()` prints "biscuit-wasm loading" through `console.log`.
// It is synchronous, so `console.log` is replaced for exactly that call and put
// back in a `finally`; the line goes to the debug log instead of stdout.
//
// ---------------------------------------------------------------------------
// THREE THINGS ABOUT THIS LIBRARY VERSION THAT COST TIME AND ARE WORTH KNOWING.
//
//   * `authorize()` WITH DEFAULT LIMITS ANSWERS `RunLimit: Timeout`. Its
//     default time budget reads the clock in a way this build cannot, so every
//     call is `authorizeWithLimits()` / `queryWithLimits()` with `LIMITS`
//     below. A timeout is a REFUSAL (STS-GNAP-0325), never a pass.
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
//   access(i, json)                 one per right, i = 0.., json = the right
//   access_ref(string)              for a reference-string right
//   access_type(i, type)  access_action(i, a)  access_location(i, l)
//   access_datatype(i, d) access_privilege(i, p) access_identifier(i, id)
//   flag(f)*                        label(l)?
//   cnf_jkt(tp) | cnf_x5t(tp) | cnf_kid(ref) | bearer(true)
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
// access model (`gnap_access`), `fs`, `path` and `url` through its
// constructor. The lazy load is the instance's: the WASM library is still
// loaded once, by the first mint or verify, and its glue modules still by a
// real dynamic `import()` (module `nodenext` keeps it one in the compiled
// CommonJS). The module still exports its old names as FACADES forwarding to
// the instance the composition root builds (#50, R2), for the unconverted
// modules and the tests that require it. A process that loads this module
// without the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import fs = require('fs');
import path = require('path');
import url = require('url');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import gnapAccess = require('./gnap_access');

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
  fs: { readFileSync(p: string): Buffer };
  path: { join(...parts: string[]): string };
  url: { pathToFileURL(p: string): URL };
}

// A Datalog source and its parameters, built together.
interface Program {
  add(template: string, values?: unknown[]): void;
  source(): string;
  params: Record<string, unknown>;
}

const FORMAT = 'biscuit';
const PACKAGE = '@biscuit-auth/biscuit-wasm';

// Generous against this service's own tokens (a model of fifty rights with
// every dimension populated is a few hundred facts, evaluated in well under a
// millisecond) and still a bound on a hostile attenuation block.
const LIMITS = { max_facts: 10000, max_iterations: 100,
                 max_time_micro: 250000 };

const VALUE_RE = /^[A-Za-z0-9_-]+={0,2}$/;

class TokenBiscuit {
  static readonly FORMAT = FORMAT;
  static readonly LIMITS = LIMITS;

  // The one load of the WASM library, shared by every call.
  private loading: Promise<any> | null = null;

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
  // The one lazy load. A failure is remembered as a rejected promise would
  // be, but a NEW attempt is allowed next time: a transient failure (a file
  // briefly unreadable during a deploy) should not disable the format for the
  // life of the process.
  // -------------------------------------------------------------------------
  loadBiscuit(): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.loadBiscuit().");
    if (!this.loading) {
      this.loading = this.instantiate().catch((e) => {
        log.debug("Caught in TokenBiscuit.loadBiscuit(): " +
                  ((e && e.message) || e));
        this.loading = null;
        throw e;
      });
    }
    log.debug("Leaving TokenBiscuit.loadBiscuit().");
    return this.loading;
  }

  private async instantiate(): Promise<any> {
    const { log, access, fs, path, url } = this.deps;
    log.debug("Entering TokenBiscuit.instantiate().");
    const dir = access.packageDir(PACKAGE);
    if (!dir) {
      log.debug("Leaving TokenBiscuit.instantiate(). Package not installed.");
      throw new Error(PACKAGE + ' is not installed');
    }
    const moduleDir = path.join(dir, 'module');
    const wasmBytes: any = fs.readFileSync(
        path.join(moduleDir, 'biscuit_bg.wasm'));
    const compiled = await WebAssembly.compile(wasmBytes);
    const imports = {};
    const wanted = WebAssembly.Module.imports(compiled);
    for (let i = 0; i < wanted.length; i++) {
      const name = wanted[i].module;
      if (!imports[name]) {
        imports[name] = await import(url.pathToFileURL(
            path.join(moduleDir, name)).href);
      }
    }
    const bg = imports['./biscuit_bg.js'];
    if (!bg || typeof bg.__wbg_set_wasm !== 'function') {
      log.debug("Leaving TokenBiscuit.instantiate(). Glue module not found.");
      throw new Error('the biscuit glue module ./biscuit_bg.js was not ' +
                      'among the WASM imports');
    }
    const instance = await WebAssembly.instantiate(compiled, imports);
    const exported: any = instance.exports;
    bg.__wbg_set_wasm(exported);
    if (typeof exported.__wbindgen_start === 'function') {
      const original = console.log;
      console.log = function () {
        log.debug('biscuit-wasm: ' +
                  Array.prototype.join.call(arguments, ' '));
      };
      try {
        exported.__wbindgen_start();
      } finally {
        console.log = original;
      }
    }
    log.debug("Leaving TokenBiscuit.instantiate(). Loaded.");
    return bg;
  }

  private async library(): Promise<any> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering TokenBiscuit.library().");
    try {
      log.debug("Leaving TokenBiscuit.library().");
      return { ok: true, bg: await this.loadBiscuit() };
    } catch (e) {
      log.debug("Caught in TokenBiscuit.library(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-GNAP-0321') + 'the biscuit WASM ' +
                'library could not be loaded: ' +
                e.message);
      log.debug("Leaving TokenBiscuit.library().");
      return this.refusal('STS-GNAP-0321',
                          'the biscuit library could not be loaded: ' +
                          e.message);
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

  private rawKey(keyObject: any, member: string): Buffer | null {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.rawKey().");
    if (!keyObject || typeof keyObject.export !== 'function' ||
        keyObject.asymmetricKeyType !== 'ed25519') {
      log.debug("Leaving TokenBiscuit.rawKey().");
      return null;
    }
    const jwk = keyObject.export({ format: 'jwk' });
    log.debug("Leaving TokenBiscuit.rawKey().");
    return jwk[member] ? Buffer.from(jwk[member], 'base64url') : null;
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
  private authorityProgram(model: any): Program {
    const { log } = this.deps;
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
    model.aud.forEach(function (a) {
      p.add('audience(?);', [a]);
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
    });
    model.flags.forEach(function (f) {
      p.add('flag(?);', [f]);
    });
    if (model.label !== null) {
      p.add('label(?);', [model.label]);
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
  async mint(model: any, keys: any): Promise<any> {
    const { log, errorCodes, access } = this.deps;
    log.debug("Entering TokenBiscuit.mint().");
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenBiscuit.mint(). Model invalid.");
      return valid;
    }
    const d = this.rawKey(keys && keys.privateKey, 'd');
    if (!d) {
      log.debug("Leaving TokenBiscuit.mint(). Private key unusable.");
      return this.refusal('STS-GNAP-0320', 'a biscuit is minted with an ' +
                          'Ed25519 private KeyObject.');
    }
    const lib = await this.library();
    if (!lib.ok) {
      log.debug("Leaving TokenBiscuit.mint(). Library unavailable.");
      return lib;
    }
    const bg = lib.bg;
    let value;
    try {
      const root = bg.PrivateKey.fromBytes(new Uint8Array(d),
                                           bg.SignatureAlgorithm.Ed25519);
      const p = this.authorityProgram(valid.model);
      const builder = bg.Biscuit.builder();
      builder.addCodeWithParameters(p.source(), p.params, {});
      const token = builder.build(root);
      value = token.toBase64();
      token.free();
    } catch (e) {
      log.debug("Caught in TokenBiscuit.mint(): " + this.errorText(e));
      log.warn(errorCodes.tag('STS-GNAP-0320') + 'biscuit minting failed ' +
               'in the library: ' + this.errorText(e));
      log.debug("Leaving TokenBiscuit.mint(). Library failure.");
      return this.refusal('STS-GNAP-0320',
                          'the biscuit library refused to mint: ' +
                          this.errorText(e));
    }
    if (!VALUE_RE.test(value)) {
      // token68 (RFC 9110 section 11.2) allows `=` only at the end. The
      // library emits URL-safe base64; this is the check that it still does.
      log.warn(errorCodes.tag('STS-GNAP-0320') + 'the biscuit library ' +
               'emitted a value that is not token68.');
      log.debug("Leaving TokenBiscuit.mint(). Not token68.");
      return this.refusal('STS-GNAP-0320', 'the biscuit library emitted a ' +
                          'value that is not token68.');
    }
    log.debug("Leaving TokenBiscuit.mint(). jti=" + valid.model.jti);
    return { value: value, format: FORMAT, jti: valid.model.jti };
  }

  private parseToken(bg: any, value: unknown, keys: any): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.parseToken().");
    if (typeof value !== 'string' || !VALUE_RE.test(value)) {
      log.debug("Leaving TokenBiscuit.parseToken(). Not base64url.");
      return this.refusal('STS-GNAP-0322', 'the token value is not ' +
                          'URL-safe base64.');
    }
    const x = this.rawKey(keys && keys.publicKey, 'x');
    if (!x) {
      log.debug("Leaving TokenBiscuit.parseToken(). Public key unusable.");
      return this.refusal('STS-GNAP-0320', 'a biscuit is verified with an ' +
                          'Ed25519 public KeyObject.');
    }
    try {
      const root = bg.PublicKey.fromBytes(new Uint8Array(x),
                                          bg.SignatureAlgorithm.Ed25519);
      const token = bg.Biscuit.fromBase64(value, root);
      log.debug("Leaving TokenBiscuit.parseToken(). Parsed.");
      return { ok: true, token: token };
    } catch (e) {
      log.debug("Caught in TokenBiscuit.parseToken(): " + this.errorText(e));
      log.debug("Leaving TokenBiscuit.parseToken(). " + this.errorText(e));
      return this.refusal('STS-GNAP-0322', 'the biscuit did not parse, or ' +
                          'its signature chain does not verify under this ' +
                          'authorization server\'s public key: ' +
                          this.errorText(e));
    }
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

  private buildAuthorizer(bg: any, token: any, context: any,
                          now: number): any {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.buildAuthorizer().");
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
    const builder = new bg.AuthorizerBuilder();
    builder.addCodeWithParameters(p.source(), p.params, {});
    const authorizer = builder.buildAuthenticated(token);
    log.debug("Leaving TokenBiscuit.buildAuthorizer().");
    return authorizer;
  }

  private query(bg: any, authorizer: any, rule: string): any[][] {
    const { log } = this.deps;
    log.debug("Entering TokenBiscuit.query().");
    log.debug("Leaving TokenBiscuit.query().");
    return authorizer.queryWithLimits(bg.Rule.fromString(rule), LIMITS)
                     .map(function (f) {
      return f.terms();
    });
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
  private readModel(bg: any, authorizer: any): any {
    const { log, access } = this.deps;
    const self = this;
    log.debug("Entering TokenBiscuit.readModel().");
    function one(rule: string) {
      log.debug("Entering one().");
      const rows = self.query(bg, authorizer, rule);
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
    const aud = this.query(bg, authorizer, 'data($v) <- audience($v)').map(
        function (r) {
          return r[0];
        });
    const flags = this.query(bg, authorizer, 'data($v) <- flag($v)').map(
        function (r) {
          return r[0];
        });
    const rows = this.query(bg, authorizer,
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
    const jkt = one('data($v) <- cnf_jkt($v)');
    const x5t = one('data($v) <- cnf_x5t($v)');
    const kid = one('data($v) <- cnf_kid($v)');
    const bearer = this.query(bg, authorizer,
                              'data($v) <- bearer($v)').length;
    const bindings = [jkt, x5t, kid].filter(function (v) {
      return v !== null;
    });
    if ([jti, iss, iat, exp, nbf, sub, client, label, jkt, x5t, kid].some(
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
      label: label
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
  async verify(value: unknown, keys: any, context?: any): Promise<any> {
    const { log, access, nowSec } = this.deps;
    log.debug("Entering TokenBiscuit.verify().");
    const lib = await this.library();
    if (!lib.ok) {
      log.debug("Leaving TokenBiscuit.verify(). Library unavailable.");
      return lib;
    }
    const bg = lib.bg;
    const parsed = this.parseToken(bg, value, keys);
    if (!parsed.ok) {
      log.debug("Leaving TokenBiscuit.verify(). Parse refused.");
      return parsed;
    }
    const token = parsed.token;
    const ctx = context || {};
    const now = Number.isSafeInteger(ctx.now) ? ctx.now : nowSec();
    let authorizer = null;
    try {
      try {
        authorizer = this.buildAuthorizer(bg, token, ctx, now);
      } catch (e) {
        log.debug("Caught in TokenBiscuit.verify(): " + this.errorText(e));
        log.debug("Leaving TokenBiscuit.verify(). Authorizer could not be " +
                  "built: " + this.errorText(e));
        return this.refusal('STS-GNAP-0324', 'the biscuit authorizer could ' +
                            'not be built for this presentation: ' +
                            this.errorText(e));
      }
      let read;
      try {
        read = this.readModel(bg, authorizer);
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
      try {
        authorizer.authorizeWithLimits(LIMITS);
      } catch (e) {
        log.debug("Caught in TokenBiscuit.verify(): " + this.errorText(e));
        log.debug("Leaving TokenBiscuit.verify(). Authorization refused: " +
                  this.errorText(e));
        return this.authorizationRefusal(e);
      }
      const blocks = token.countBlocks();
      log.debug("Leaving TokenBiscuit.verify(). Verified jti=" +
                read.model.jti + " blocks=" + blocks);
      return { ok: true, model: read.model, attenuated: blocks > 1 };
    } finally {
      if (authorizer) {
        authorizer.free();
      }
      token.free();
    }
  }

  // -------------------------------------------------------------------------
  // attenuate(value, datalogSource, keys[, parameters]): append a block of
  // checks — what a resource server does to derive a narrower token without
  // calling the AS (RFC 9767 section 2.2). `keys.publicKey` is needed because
  // this library will not open a token without verifying it, which is the
  // right default; a block cannot hold a policy (`allow if`) and the library
  // refuses one. Returns `{ ok:true, value, format }` or a refusal.
  // -------------------------------------------------------------------------
  async attenuate(value: unknown, datalogSource: unknown, keys: any,
                  parameters?: Record<string, unknown>): Promise<any> {
    const { log } = this.deps;
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
    const bg = lib.bg;
    const parsed = this.parseToken(bg, value, keys);
    if (!parsed.ok) {
      log.debug("Leaving TokenBiscuit.attenuate(). Parse refused.");
      return parsed;
    }
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
        parsed.token.free();
        log.debug("Leaving TokenBiscuit.attenuate(). Parameter " + names[i] +
                  " is not a term.");
        return this.refusal('STS-GNAP-0326',
                            'attenuation parameter "' + names[i] + '" ' +
                            'must be a string, boolean, integer or Date.');
      }
    }
    let out;
    try {
      const block = bg.Biscuit.block_builder();
      block.addCodeWithParameters(datalogSource, params, {});
      const next = parsed.token.appendBlock(block);
      out = next.toBase64();
      next.free();
    } catch (e) {
      log.debug("Caught in TokenBiscuit.attenuate(): " + this.errorText(e));
      log.debug("Leaving TokenBiscuit.attenuate(). Library refused: " +
                this.errorText(e));
      return this.refusal('STS-GNAP-0326',
                          'the attenuation block was refused: ' +
                          this.errorText(e));
    } finally {
      parsed.token.free();
    }
    log.debug("Leaving TokenBiscuit.attenuate(). Appended.");
    return { ok: true, value: out, format: FORMAT };
  }

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
                'iat', 'nbf', 'exp', 'label'],
      cannot: []
    };
    log.debug("Leaving TokenBiscuit.describe().");
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
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
      fs: fs,
      path: path,
      url: url
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

export = {
  TokenBiscuit: TokenBiscuit,
  installInstance: (instance: TokenBiscuit): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FORMAT: TokenBiscuit.FORMAT,
  LIMITS: TokenBiscuit.LIMITS,
  mint: slot.forward('mint'),
  verify: slot.forward('verify'),
  attenuate: slot.forward('attenuate'),
  describe: slot.forward('describe'),
  loadBiscuit: slot.forward('loadBiscuit')
};
