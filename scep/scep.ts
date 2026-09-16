'use strict';
//
// File: scep.ts
//
// ===========================================================================
// THE SIMPLE CERTIFICATE ENROLMENT PROTOCOL (RFC 8894), PER TRUST REALM
// (2026-09-13).
//
//   GET|POST /enroll/scep[/pkiclient.exe]?operation=…
//   GET|POST /enroll/scep/{profile}[/pkiclient.exe]?operation=…
//
// Four operations: GetCACaps (what this server can do), GetCACert (the RA and
// the CA chain), GetNextCACert (not implemented — see below) and PKIOperation,
// which carries a signed and encrypted pkiMessage and is answered with a
// signed CertRep. The messages the last one takes are PKCSReq, RenewalReq,
// CertPoll (GetCertInitial), GetCert and GetCRL.
//
// **WHAT THIS FILE DECIDES IS WHICH SCEP MESSAGE IT IS LOOKING AT AND WHAT A
// CertRep SAYS BACK. IT DECIDES NOTHING ABOUT WHO GETS A CERTIFICATE.** That is
// `common/cert_enrollment.ts`'s, which every issuance here goes through; the
// CMS bytes are `scep_cms.ts`'s; the RA key is `scep_ra.ts`'s.
//
// ---------------------------------------------------------------------------
// THE AUTHORIZATION IS THE CHALLENGE, AND THE PRINCIPAL IS THE ENTRY IT NAMES.
//
// rcbj's decision 2 (the contract): a SCEP challenge password is issued for ONE
// directory entry and ONE profile — by the person on the portal, or by an
// administrator on the console or `/admin-api` for any entry in the realm. So
// whoever redeems it acts AS that entry: the principal handed to the core is
// `{ kind, id, admin: false }` for the entry the challenge names, and the
// core's identity rule then refuses a request whose subjectAltName names
// anybody else (`STS-ENROLL-0021`). An administrator creating a challenge FOR
// somebody is the administrator's authority, exercised when they created it;
// the device redeeming it is not an administrator.
//
// A challenge is VERIFIED IN BOTH MODES (the TOTP argument: a permissive
// verifier is a broken verifier), is single-use, and is SPENT by the first
// request that proves it — before the certificate authority rules on the
// request, so two transactions racing one challenge cannot both be issued.
// A request refused after that has used it up, and the page that made it says
// so.
//
// ---------------------------------------------------------------------------
// WHY SCEP ANSWERS OVER PLAIN HTTP, IN PRODUCT MODE AS WELL.
//
// ACME and EST ask `core.transportRefusal()` and are refused over plain HTTP in
// product mode, because their security IS the TLS channel. SCEP's is not: RFC
// 8894 section 2.1 runs it over HTTP on purpose and protects every message at
// the CMS layer — the request is signed by the requester and encrypted to the
// RA, the reply is signed by the RA and its certificate encrypted to the
// requester, and the challenge travels inside the encryption. A transport
// refusal here would refuse every device that implements the specification and
// protect nothing the envelope does not already protect.
//
// ---------------------------------------------------------------------------
// TWO ANSWERS, AND WHICH ONE A REFUSAL GETS.
//
// An HTTP error (400, 405, 413, 415, 429, 501, 503) is for a request too
// malformed, too large or too early to NAME: without a readable SignedData, a
// transactionID and a senderNonce there is nothing a CertRep could echo. Once
// those are read, every refusal is a CertRep FAILURE — HTTP 200, signed by the
// RA, with a failInfo — which is what RFC 8894 section 3.3.2.2 says a client is
// told. **The STS code is recorded on the response mark, the audit row and the
// monitor, and is never in the CertRep**: a failInfo is the protocol's word.
//
// ---------------------------------------------------------------------------
// DOCUMENTED EXCEPTIONS (scep/CLAUDE.md has the full list):
//
//   * GetNextCACert is not implemented (HTTP 501) and not advertised: this
//     service has no pre-announced CA rollover to hand out.
//   * PENDING is never answered: nothing here is approved by hand, so a request
//     is issued or refused in the same exchange, and CertPoll returns what a
//     completed transaction produced.
//   * A requester key must be RSA: the CertRep is encrypted to the requester
//     with RSA key transport, so an ECDSA, EdDSA or post-quantum key cannot be
//     enrolled over SCEP (`STS-SCEP-0025`, `STS-SCEP-0033`, badAlg).
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Scep` takes the modules it uses through its constructor
// (`ScepDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `Scep` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the
// transitional code calls at load where the first route used to be
// registered, so rule 1's order is unchanged.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log } = helpers;
import audit = require('../common/audit');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import validation = require('../common/validation');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
// The atomic "once" the transaction guard and nothing else here is held to
// across nodes. A LIBRARY that reaches `persistence.js` lazily.
import claims = require('../cluster/cluster_claims');
import cms = require('./scep_cms');
import ra = require('./scep_ra');

const vz = validation.z;
const vt = validation.types;

const OPERATIONS = ['GetCACaps', 'GetCACert', 'GetNextCACert',
                    'PKIOperation'];

// RFC 8894 section 3.5.2. `SCEPStandard` asserts AES, POSTPKIOperation and
// SHA-256; each is still named, because older clients read the list rather
// than the umbrella. `GetNextCACert` is deliberately absent — see the header.
const CAPABILITIES = ['POSTPKIOperation', 'SHA-256', 'SHA-512', 'AES',
                      'SCEPStandard', 'Renewal'];

const PROFILE_SEGMENT = /^[a-z][a-z0-9-]{0,63}$/;

// The GET binding's base64 is at most a third larger than the largest message
// `scep.maxRequestBytes` allows at its maximum; the precise bound is checked
// against the setting once the length is known.
const MESSAGE_PARAMETER_CAP = Math.ceil(4194304 / 3) * 4 + 4;

const QUERY = vz.object({
  operation: vt.oneOf(OPERATIONS),
  message: vt.opt(vz.string().max(MESSAGE_PARAMETER_CAP))
});

// How long a completed transaction's result is kept for CertPoll and for a
// retried request, and how many a realm keeps. A result is a public
// certificate, so the bound is about the store's size rather than a secret's
// lifetime; a day covers any client that retries after losing a reply.
const TRANSACTION_TTL_MS = 24 * 3600 * 1000;
const MAX_TRANSACTIONS = 1000;

const transactions = realms.map({ persist: 'scep.transactions' });

// One transaction at a time per (realm, transactionID) in this process, so a
// client that retries before the first reply arrives meets the stored result
// rather than a second redemption of its challenge.
const inflight = new Map();

// ---------------------------------------------------------------------------
// AND ONE AT A TIME ACROSS THE CLUSTER (2026-09-14, #46 section 2).
//
// `inflight` is a Map in this process, so a client that retried its PKCSReq
// at a SECOND node while the first was still answering it met no guard at
// all: the second node found no stored result, redeemed nothing (the
// challenge is claimed — `redeemScepChallengeOnce()`) and answered FAILURE,
// and the client discarded the certificate the first node was issuing it. The
// guard is therefore also a CLAIM on the transaction, held while one node
// answers it:
//
//   * a node that finds it claimed WAITS (polling every
//     `TRANSACTION_POLL_MS`, for at most `TRANSACTION_WAIT_MS`) rather than
//     refusing, because the ordinary cause is a client's own retry and what
//     it deserves is the stored result;
//   * the node that holds it gives it back only after its writes have
//     COMMITTED, and the waiter catches up with the store before it runs the
//     handler — without both, the waiter would take the claim, not yet see
//     the stored transaction, and refuse the retry it waited for;
//   * a wait that runs out answers FAILURE (`STS-SCEP-0064`), and a store
//     that cannot be asked answers FAILURE (`STS-SCEP-0065`): a transaction
//     this node cannot prove nobody else is answering is not one it answers.
//
// The claim lives `TRANSACTION_CLAIM_TTL_MS`, far beyond any issuance, so a
// node that died holding it blocks that one transactionID for two minutes and
// nothing else.
// ---------------------------------------------------------------------------
const TRANSACTION_CLAIM_TTL_MS = 2 * 60 * 1000;
const TRANSACTION_WAIT_MS = 20 * 1000;
const TRANSACTION_POLL_MS = 250;

// What `Scep` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepDeps {
  nodeCrypto: typeof nodeCrypto;
  log: typeof log;
  audit: typeof audit;
  config: typeof config;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  validation: typeof validation;
  core: typeof core;
  monitor: typeof monitor;
  claims: typeof claims;
  cms: typeof cms;
  ra: typeof ra;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadPersistence(): typeof import('../persistence/persistence');
  loadPkiRevocation(): typeof import('../common/pki_revocation');
}

type RouteApp = typeof app;

class Scep {
  constructor(private readonly deps: ScepDeps) {
    deps.log.debug("Entering Scep.constructor().");
    deps.log.debug("Leaving Scep.constructor().");
  }

  persistenceModule() {
    const { log, loadPersistence } = this.deps;
    log.debug("Entering Scep.persistenceModule().");
    log.debug("Leaving Scep.persistenceModule().");
    // LAZY: this module is required at 23e–g and the store module's own
    // position (#4a) is not this file's to assume.
    return loadPersistence();
  }

  pause(ms) {
    const { log } = this.deps;
    log.debug("Entering Scep.pause().");
    log.debug("Leaving Scep.pause().");
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  async acrossNodes(key, fn) {
    const { log, claims, errorCodes, cms } = this.deps;
    log.debug("Entering Scep.acrossNodes().");
    const began = Date.now();
    const ask = function () {
      log.debug("Entering ask().");
      log.debug("Leaving ask().");
      return claims.claim({ scope: 'scep.transaction', value: key,
                            ttlMs: TRANSACTION_CLAIM_TTL_MS });
    };
    let claimed = await ask();
    let waited = false;
    while (!claimed.ok && claimed.reason === 'used' &&
           Date.now() - began < TRANSACTION_WAIT_MS) {
      waited = true;
      await this.pause(TRANSACTION_POLL_MS);
      claimed = await ask();
    }
    if (!claimed.ok && claimed.reason === 'used') {
      log.warn(errorCodes.tag('STS-SCEP-0064') + 'scep: a transaction was ' +
               'still being answered by another request after ' +
               TRANSACTION_WAIT_MS + 'ms; this copy of it is refused.');
      log.debug("Leaving Scep.acrossNodes(). Held elsewhere.");
      return this.failed('STS-SCEP-0064',
                         'Another request with this transactionID is still ' +
                         'being answered. Retry, or poll with CertPoll.',
                         cms.FAIL_INFO.badRequest);
    }
    if (!claimed.ok) {
      log.error(errorCodes.tag('STS-SCEP-0065') + 'scep: a transaction could ' +
                'not be claimed (' + claimed.why + '); it is refused.');
      log.debug("Leaving Scep.acrossNodes(). The store.");
      return this.failed('STS-SCEP-0065',
                         'This server could not check whether ' +
                         'the transaction is already being answered.',
                         cms.FAIL_INFO.badRequest);
    }
    const store = this.persistenceModule();
    const shared = !!store.clusterStore();
    try {
      if (waited && shared && typeof store.syncNow === 'function') {
        try {
          await store.syncNow();
        } catch (e) {
          log.debug("Caught in Scep.acrossNodes(): " + ((e && e.message) || e));
        }
      }
      log.debug("Leaving Scep.acrossNodes(). Answering.");
      return await fn();
    } finally {
      if (shared) {
        try {
          await Promise.all([store.flush(), store.flushMinted()]);
        } catch (e) {
          log.debug("Caught in Scep.acrossNodes(): " + ((e && e.message) || e));
        }
      }
      claims.release(claimed.handle);
    }
  }

  // ---------------------------------------------------------------------------
  // THE HTTP ERROR, for a request that cannot be answered with a CertRep.
  // ---------------------------------------------------------------------------
  // error-code: none — the definition of this helper, not a call to it
  scepError(res, status, code, text, headers?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Scep.scepError(). status=" + status + " code=" + code);
    errorCodes.mark(res, code);
    res.status(status)
       .type('text/plain')
       .set('Cache-Control', 'no-store');
    Object.keys(headers || {}).forEach(function (name) {
      res.set(name, headers[name]);
    });
    res.send(String(text) + '\n');
    log.debug("Leaving Scep.scepError().");
  }

  enabled() {
    const { log, config } = this.deps;
    log.debug("Entering Scep.enabled().");
    log.debug("Leaving Scep.enabled().");
    return config.value('scep.enabled') !== false;
  }

  maxBytes() {
    const { log, config } = this.deps;
    log.debug("Entering Scep.maxBytes().");
    log.debug("Leaving Scep.maxBytes().");
    return Number(config.value('scep.maxRequestBytes'));
  }

  record(detail) {
    const { log, monitor } = this.deps;
    log.debug("Entering Scep.record().");
    monitor.record('scep', detail);
    log.debug("Leaving Scep.record().");
  }

  // ---------------------------------------------------------------------------
  // THE TRANSACTION STORE.
  // ---------------------------------------------------------------------------
  prune() {
    const { log } = this.deps;
    log.debug("Entering Scep.prune().");
    const nowMs = Date.now();
    const expired = [];
    transactions.forEach(function (value, key) {
      if (!value || value.expiresAtMs <= nowMs) {
        expired.push(key);
      }
    });
    expired.forEach(function (key) {
      transactions.delete(key);
    });
    while (transactions.size > MAX_TRANSACTIONS) {
      transactions.delete(transactions.keys().next().value);
    }
    log.debug("Leaving Scep.prune().");
  }

  transactionOf(id) {
    const { log } = this.deps;
    log.debug("Entering Scep.transactionOf().");
    this.prune();
    const held = transactions.has(id) ? transactions.get(id) : null;
    log.debug("Leaving Scep.transactionOf(). " + (held ? "held" : "none"));
    return held;
  }

  remember(id, result) {
    const { log } = this.deps;
    log.debug("Entering Scep.remember().");
    const nowMs = Date.now();
    transactions.set(id, Object.assign({}, result, {
      transactionID: id,
      createdAt: new Date(nowMs).toISOString(),
      expiresAtMs: nowMs + TRANSACTION_TTL_MS
    }));
    this.prune();
    log.debug("Leaving Scep.remember().");
  }

  serialized(key, fn) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scep.serialized().");
    const before = inflight.get(key) || Promise.resolve();
    const guarded = function () {
      log.debug("Entering guarded().");
      log.debug("Leaving guarded().");
      return self.acrossNodes(key, fn);
    };
    const run = before.then(guarded, guarded);
    const settled = run.then(function () {
      return undefined;
    }, function () {
      return undefined;
    });
    inflight.set(key, settled);
    settled.then(function () {
      if (inflight.get(key) === settled) {
        inflight.delete(key);
      }
    });
    log.debug("Leaving Scep.serialized().");
    return run;
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL, AS A CertRep FAILURE WILL CARRY IT.
  // ---------------------------------------------------------------------------
  failed(code, why, failInfo, extra?) {
    const { log, cms } = this.deps;
    log.debug("Entering Scep.failed(). code=" + code);
    log.debug("Leaving Scep.failed().");
    return Object.assign({ ok: false, code: code, why: String(why || ''),
                           failInfo: failInfo || cms.FAIL_INFO.badRequest },
                         extra || {});
  }

  // Every core refusal, as the failInfo a client is told. The table beside each
  // code in common/error_codes.js says the same thing in its `spec` column.
  failInfoForCore(code) {
    const { log, cms } = this.deps;
    log.debug("Entering Scep.failInfoForCore(). code=" + code);
    const byCode = {
      'STS-ENROLL-0031': 'badAlg',
      'STS-ENROLL-0032': 'badAlg',
      'STS-ENROLL-0033': 'badMessageCheck',
      'STS-ENROLL-0018': 'badMessageCheck',
      'STS-ENROLL-0019': 'badMessageCheck'
    };
    log.debug("Leaving Scep.failInfoForCore().");
    return cms.FAIL_INFO[byCode[code] || 'badRequest'];
  }

  fromCore(refusal, extra?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Scep.fromCore().");
    const code = errorCodes.codeOf(refusal) || 'STS-SCEP-0045';
    log.debug("Leaving Scep.fromCore(). " + code);
    return this.failed(code, (refusal.errors || [])[0] || refusal.why,
                       this.failInfoForCore(code), extra);
  }

  spkiSha256(publicKeyPem) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering Scep.spkiSha256().");
    const der = nodeCrypto.createPublicKey(publicKeyPem)
      .export({ type: 'spki', format: 'der' });
    log.debug("Leaving Scep.spkiSha256().");
    return nodeCrypto.createHash('sha256').update(der).digest('hex');
  }

  // ---------------------------------------------------------------------------
  // THE MESSAGE TYPES.
  // ---------------------------------------------------------------------------
  async readRequest(message, raKeys) {
    const { log, cms, core, nodeCrypto } = this.deps;
    log.debug("Entering Scep.readRequest().");
    const opened = cms.openEnvelope(message.content, raKeys.certificatePem,
                                    raKeys.privateKeyPem);
    if (!opened.ok) {
      log.debug("Leaving Scep.readRequest(). The envelope.");
      return { refusal: this.failed(opened.code, opened.why, opened.failInfo) };
    }
    const csr = await core.parseCsr(opened.content);
    if (!csr.ok) {
      log.debug("Leaving Scep.readRequest(). The PKCS#10.");
      return { refusal: this.fromCore(csr), cipher: opened.cipher };
    }
    if (csr.keyKind !== 'rsa') {
      log.debug("Leaving Scep.readRequest(). Not an RSA key.");
      return { refusal: this.failed('STS-SCEP-0033', 'The request carries a ' +
        csr.keyAlg +
        ' key. SCEP encrypts its reply to the requester with RSA ' +
        'key transport, so only an RSA key can be enrolled over SCEP; use ' +
        'ACME or EST for an ECDSA, EdDSA or post-quantum key.',
        cms.FAIL_INFO.badAlg), cipher: opened.cipher };
    }
    log.debug("Leaving Scep.readRequest().");
    return { csr: csr, cipher: opened.cipher,
             csrSha256: nodeCrypto.createHash('sha256').update(opened.content)
               .digest('hex') };
  }

  // The stored result of a transactionID, when this request is a retry of it.
  replayed(message, read) {
    const { log, cms } = this.deps;
    log.debug("Entering Scep.replayed().");
    const held = this.transactionOf(message.transactionID);
    if (!held) {
      log.debug("Leaving Scep.replayed(). A new transaction.");
      return null;
    }
    if (held.signerKey !== message.signer.spkiSha256) {
      log.debug("Leaving Scep.replayed(). A different signer.");
      return this.failed('STS-SCEP-0039',
                         'That transactionID completed for a ' +
                         'request signed with a different key.',
                         cms.FAIL_INFO.badCertId);
    }
    if (held.csrSha256 !== read.csrSha256) {
      log.debug("Leaving Scep.replayed(). A different request.");
      return this.failed('STS-SCEP-0037',
                         'That transactionID already completed ' +
                         'for a different certificate ' +
                         'request. A new request needs ' +
                         'a new transactionID.', cms.FAIL_INFO.badRequest);
    }
    log.debug("Leaving Scep.replayed(). The stored result.");
    return { ok: true, replay: true, certificatePem: held.certificatePem,
             profile: held.profile, target: held.target,
             principal: held.principal, serialHex: held.serialHex };
  }

  async pkcsReq(ctx) {
    const { log, cms, core, realms } = this.deps;
    log.debug("Entering Scep.pkcsReq().");
    const message = ctx.message;
    const read = await this.readRequest(message, ctx.ra);
    if (read.refusal) {
      log.debug("Leaving Scep.pkcsReq(). Unreadable.");
      return read.refusal;
    }
    if (this.spkiSha256(read.csr.publicKeyPem) !== message.signer.spkiSha256) {
      log.debug("Leaving Scep.pkcsReq(). Two keys.");
      return this.failed('STS-SCEP-0034',
                         'The request is signed by a certificate ' +
                         'whose key is not the key in the PKCS#10 request. ' +
                         'RFC 8894 section 2.3 has a PKCSReq signed by a ' +
                         'self-signed certificate for the requested key.',
                         cms.FAIL_INFO.badMessageCheck);
    }
    const retry = this.replayed(message, read);
    if (retry) {
      log.debug("Leaving Scep.pkcsReq(). A retry.");
      return Object.assign(retry, { cipher: read.cipher });
    }
    const password = read.csr.challengePassword;
    if (!password) {
      log.debug("Leaving Scep.pkcsReq(). No challenge.");
      return this.failed('STS-SCEP-0035',
                         'The request carries no challengePassword ' +
                         'attribute. A SCEP enrollment in this service is ' +
                         'authorized by a single-use ' +
                         'challenge issued for one ' +
                         'entry and one profile.', cms.FAIL_INFO.badRequest);
    }
    const identity = password.slice(0, Math.max(0, password.lastIndexOf('.')))
      .slice(0, 400);
    const blocked = await core.throttledShared('scep', ctx.req, identity);
    if (blocked) {
      log.debug("Leaving Scep.pkcsReq(). Throttled.");
      return { ok: false, http: blocked, identity: identity };
    }
    const peek = core.redeemScepChallenge(password, { peek: true });
    if (!peek.ok) {
      log.debug("Leaving Scep.pkcsReq(). The challenge.");
      return this.fromCore(peek, { identity: identity });
    }
    const entryUri = core.entryUri(peek.entry);
    if (ctx.urlProfile && ctx.urlProfile !== peek.profile) {
      log.debug("Leaving Scep.pkcsReq(). The URL names another profile.");
      return this.failed('STS-SCEP-0036',
                         'The URL names the "' + ctx.urlProfile +
                         '" profile and the challenge was issued for "' +
                         peek.profile + '".', cms.FAIL_INFO.badRequest,
                         { identity: identity, profile: peek.profile,
                           principal: entryUri });
    }
    // SPENT ONCE ACROSS THE CLUSTER (2026-09-14, #46): claimed in the store
    // between the look above and the write, so one challenge in two PKCSReqs
    // with two transactionIDs at two nodes issues once. See
    // `common/cert_enrollment.ts`'s `redeemScepChallengeOnce()`.
    const spent = await core.redeemScepChallengeOnce(password);
    if (!spent.ok) {
      log.debug("Leaving Scep.pkcsReq(). Spent between the two looks.");
      return this.fromCore(spent, { identity: identity });
    }
    const principal = { kind: spent.entry.kind, id: spent.entry.id,
                        admin: false, hasEntry: true, via: 'scep',
                        realm: realms.currentId() };
    const extra = { identity: identity, profile: spent.profile,
                    principal: entryUri, audited: true };
    const target = core.targetFromRequest(read.csr.requested,
                                          read.csr.commonName, principal);
    if (!target.ok) {
      log.debug("Leaving Scep.pkcsReq(). No target.");
      return this.fromCore(target,
                           Object.assign({}, extra, { audited: false }));
    }
    const issued = await core.issue({
      family: 'scep', profile: spent.profile, principal: principal,
      target: target.target, publicKeyPem: read.csr.publicKeyPem,
      requested: read.csr.requested, keySource: 'client',
      keyAlg: read.csr.keyAlg, via: 'scep'
    });
    if (!issued.ok) {
      log.debug("Leaving Scep.pkcsReq(). The core refused.");
      return this.fromCore(issued, extra);
    }
    const done = {
      certificatePem: issued.record.certificatePem, profile: spent.profile,
      target: core.entryUri(issued.target), principal: entryUri,
      serialHex: issued.record.serialHex
    };
    this.remember(message.transactionID, Object.assign({
      messageType: 'PKCSReq', signerKey: message.signer.spkiSha256,
      csrSha256: read.csrSha256 }, done));
    log.debug("Leaving Scep.pkcsReq(). Issued " + issued.record.serialHex);
    return Object.assign({ ok: true, issued: true, cipher: read.cipher,
                           identity: identity }, done);
  }

  // The entry a signing certificate belongs to — RenewalReq, GetCert, GetCRL.
  async signerEntry(message) {
    const { log, core, cms } = this.deps;
    log.debug("Entering Scep.signerEntry().");
    const answer = await core.authenticatePresentedCertificate(
      message.signer.pem, 'scep', { clientAuth: false });
    if (!answer.ok) {
      log.debug("Leaving Scep.signerEntry(). Refused.");
      return this.failed('STS-SCEP-0040', 'The message is not signed by a ' +
                         'certificate this realm issued to an entry that ' +
                         'still holds it: ' + ((answer.errors || [])[0] || ''),
                         cms.FAIL_INFO.badMessageCheck,
                         { identity: core.normalSerial(
                             message.signer.x509.serialNumber) });
    }
    log.debug("Leaving Scep.signerEntry(). " + answer.principal.id);
    return answer;
  }

  async renewalReq(ctx) {
    const { log, core, cms } = this.deps;
    log.debug("Entering Scep.renewalReq().");
    const message = ctx.message;
    const auth = await this.signerEntry(message);
    if (!auth.ok) {
      log.debug("Leaving Scep.renewalReq(). The signer.");
      return auth;
    }
    const principal = auth.principal;
    const entryUri = core.entryUri(principal);
    const identity = principal.certificateSerial;
    const blocked = await core.throttledShared('scep', ctx.req, identity);
    if (blocked) {
      log.debug("Leaving Scep.renewalReq(). Throttled.");
      return { ok: false, http: blocked, identity: identity };
    }
    const read = await this.readRequest(message, ctx.ra);
    if (read.refusal) {
      log.debug("Leaving Scep.renewalReq(). Unreadable.");
      return Object.assign(read.refusal, { identity: identity,
                                           principal: entryUri });
    }
    const retry = this.replayed(message, read);
    if (retry) {
      log.debug("Leaving Scep.renewalReq(). A retry.");
      return Object.assign(retry, { cipher: read.cipher });
    }
    const renewed = core.enrolledOf(principal).filter(function (one) {
      return core.normalSerial(one.serialHex) === principal.certificateSerial;
    })[0];
    const profile = renewed ? renewed.profile : '';
    if (ctx.urlProfile && ctx.urlProfile !== profile) {
      log.debug("Leaving Scep.renewalReq(). The URL names another profile.");
      return this.failed('STS-SCEP-0036',
                         'The URL names the "' + ctx.urlProfile +
                         '" profile and the certificate being renewed is "' +
                         profile + '".', cms.FAIL_INFO.badRequest,
                         { identity: identity, principal: entryUri,
                           profile: profile });
    }
    const extra = { identity: identity, profile: profile, principal: entryUri,
                    audited: true };
    const target = core.targetFromRequest(read.csr.requested,
                                          read.csr.commonName, principal);
    if (!target.ok) {
      log.debug("Leaving Scep.renewalReq(). No target.");
      return this.fromCore(target,
                           Object.assign({}, extra, { audited: false }));
    }
    const issued = await core.issue({
      family: 'scep', profile: profile, principal: principal,
      target: target.target, publicKeyPem: read.csr.publicKeyPem,
      requested: read.csr.requested, keySource: 'client',
      keyAlg: read.csr.keyAlg, via: 'scep',
      replaces: principal.certificateSerial
    });
    if (!issued.ok) {
      log.debug("Leaving Scep.renewalReq(). The core refused.");
      return this.fromCore(issued, extra);
    }
    const done = {
      certificatePem: issued.record.certificatePem, profile: profile,
      target: core.entryUri(issued.target), principal: entryUri,
      serialHex: issued.record.serialHex
    };
    this.remember(message.transactionID, Object.assign({
      messageType: 'RenewalReq', signerKey: message.signer.spkiSha256,
      csrSha256: read.csrSha256 }, done));
    log.debug("Leaving Scep.renewalReq(). Issued " + issued.record.serialHex);
    return Object.assign({ ok: true, issued: true, cipher: read.cipher,
                           identity: identity, replaced: identity }, done);
  }

  async certPoll(ctx) {
    const { log, cms } = this.deps;
    log.debug("Entering Scep.certPoll().");
    const message = ctx.message;
    const opened = cms.openEnvelope(message.content, ctx.ra.certificatePem,
                                    ctx.ra.privateKeyPem);
    if (!opened.ok) {
      log.debug("Leaving Scep.certPoll(). The envelope.");
      return this.failed(opened.code, opened.why, opened.failInfo);
    }
    if (!cms.readIssuerAndSubject(opened.content)) {
      log.debug("Leaving Scep.certPoll(). Not an IssuerAndSubject.");
      return this.failed('STS-SCEP-0032', 'A CertPoll envelope holds an ' +
                         'IssuerAndSubject (RFC 8894 section 3.3.3).',
                         cms.FAIL_INFO.badRequest);
    }
    const held = this.transactionOf(message.transactionID);
    if (!held) {
      log.debug("Leaving Scep.certPoll(). Unknown transaction.");
      return this.failed('STS-SCEP-0038',
                         'This realm holds no result for that ' +
                         'transactionID. Nothing here is PENDING: a request ' +
                         'is issued or refused when it is made.',
                         cms.FAIL_INFO.badCertId,
                         { identity: message.transactionID });
    }
    if (held.signerKey !== message.signer.spkiSha256) {
      log.debug("Leaving Scep.certPoll(). A different signer.");
      return this.failed('STS-SCEP-0039',
                         'That transaction was completed for a ' +
                         'request signed with a different key.',
                         cms.FAIL_INFO.badCertId,
                         { identity: message.transactionID });
    }
    log.debug("Leaving Scep.certPoll().");
    return { ok: true, certificatePem: held.certificatePem,
             cipher: opened.cipher, profile: held.profile,
             target: held.target, principal: held.principal,
             serialHex: held.serialHex, identity: message.transactionID };
  }

  async getCert(ctx) {
    const { log, cms, core } = this.deps;
    log.debug("Entering Scep.getCert().");
    const message = ctx.message;
    const auth = await this.signerEntry(message);
    if (!auth.ok) {
      log.debug("Leaving Scep.getCert(). The signer.");
      return auth;
    }
    const opened = cms.openEnvelope(message.content, ctx.ra.certificatePem,
                                    ctx.ra.privateKeyPem);
    if (!opened.ok) {
      log.debug("Leaving Scep.getCert(). The envelope.");
      return this.failed(opened.code, opened.why, opened.failInfo);
    }
    const wanted = cms.readIssuerAndSerial(opened.content);
    if (!wanted) {
      log.debug("Leaving Scep.getCert(). Not an IssuerAndSerialNumber.");
      return this.failed('STS-SCEP-0032', 'A GetCert envelope holds an ' +
                         'IssuerAndSerialNumber (RFC 8894 section 3.3.4).',
                         cms.FAIL_INFO.badRequest);
    }
    const entryUri = core.entryUri(auth.principal);
    const hit = core.enrolledOf(auth.principal).filter(function (one) {
      return core.normalSerial(one.serialHex) ===
             core.normalSerial(wanted.serialHex);
    })[0];
    if (!hit) {
      log.debug("Leaving Scep.getCert(). Not the signer's.");
      return this.failed('STS-SCEP-0041', 'The ' + entryUri + ' holds no ' +
                         'certificate with that serial.',
                         cms.FAIL_INFO.badCertId,
                         { principal: entryUri,
                           identity: auth.principal.certificateSerial });
    }
    log.debug("Leaving Scep.getCert().");
    return { ok: true, certificatePem: hit.certificatePem,
             cipher: opened.cipher, profile: hit.profile, target: entryUri,
             principal: entryUri, serialHex: hit.serialHex,
             identity: auth.principal.certificateSerial };
  }

  async getCrl(ctx) {
    const { log, cms, core, loadPkiRevocation, realms, errorCodes } = this.deps;
    log.debug("Entering Scep.getCrl().");
    const message = ctx.message;
    const auth = await this.signerEntry(message);
    if (!auth.ok) {
      log.debug("Leaving Scep.getCrl(). The signer.");
      return auth;
    }
    const opened = cms.openEnvelope(message.content, ctx.ra.certificatePem,
                                    ctx.ra.privateKeyPem);
    if (!opened.ok) {
      log.debug("Leaving Scep.getCrl(). The envelope.");
      return this.failed(opened.code, opened.why, opened.failInfo);
    }
    const wanted = cms.readIssuerAndSerial(opened.content);
    if (!wanted) {
      log.debug("Leaving Scep.getCrl(). Not an IssuerAndSerialNumber.");
      return this.failed('STS-SCEP-0032', 'A GetCRL envelope holds an ' +
                         'IssuerAndSerialNumber (RFC 8894 section 3.3.4).',
                         cms.FAIL_INFO.badRequest);
    }
    const chain = core.caChainOf('scep');
    const issuing = chain.ok
      ? cms.describeCertificate(cms.pemToDer(chain.issuingPem)) : null;
    const entryUri = core.entryUri(auth.principal);
    if (!issuing || !issuing.subjectRaw.equals(wanted.issuerRaw)) {
      log.debug("Leaving Scep.getCrl(). Another issuer.");
      return this.failed('STS-SCEP-0042',
                         'GetCRL answers for this realm\'s SCEP ' +
                         'Issuing CA, and the request names another issuer.',
                         cms.FAIL_INFO.badCertId,
                         { principal: entryUri,
                           identity: auth.principal.certificateSerial });
    }
    let made = null;
    try {
      made = await loadPkiRevocation()
        .buildCrl(realms.currentId(), 'scep');
    } catch (e) {
      log.debug("Caught in Scep.getCrl(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SCEP-0043') + 'scep: the SCEP Issuing ' +
                'CA\'s CRL could not be built: ' + ((e && e.message) || e));
      made = null;
    }
    if (!made || !made.ok) {
      log.debug("Leaving Scep.getCrl(). No CRL.");
      return this.failed('STS-SCEP-0043',
                         'The SCEP Issuing CA\'s CRL could not be ' +
                         'built.', cms.FAIL_INFO.badRequest,
                         { principal: entryUri });
    }
    log.debug("Leaving Scep.getCrl(). " + made.count + " entries.");
    return { ok: true, crlDer: made.der, cipher: opened.cipher,
             principal: entryUri, identity: auth.principal.certificateSerial };
  }

  async answerMessage(ctx) {
    const { log, cms, realms } = this.deps;
    log.debug("Entering Scep.answerMessage().");
    const message = ctx.message;
    const verified = cms.verifySigner(message);
    if (!verified.ok) {
      log.debug("Leaving Scep.answerMessage(). The signature.");
      return this.failed(verified.code, verified.why, verified.failInfo);
    }
    if (message.signer.keyType !== 'rsa') {
      log.debug("Leaving Scep.answerMessage(). Not an RSA signer.");
      return this.failed('STS-SCEP-0025', 'The message is signed with a ' +
                         message.signer.keyType +
                         ' key. A CertRep is encrypted to ' +
                         'the signer\'s certificate with ' +
                         'RSA key transport, so SCEP ' +
                         'in this service takes an RSA requester key only.',
                         cms.FAIL_INFO.badAlg);
    }
    const handler = HANDLERS[message.messageType];
    if (!handler) {
      log.debug("Leaving Scep.answerMessage(). Unknown messageType.");
      return this.failed('STS-SCEP-0031', 'The messageType "' +
                         message.messageTypeText + '" is not one this server ' +
                         'answers. It answers PKCSReq (19), RenewalReq (17), ' +
                         'CertPoll (20), GetCert (21) and GetCRL (22).',
                         cms.FAIL_INFO.badRequest);
    }
    const key = realms.currentId() + '|' + message.transactionID;
    const result = await this.serialized(key, function () {
      return handler(ctx);
    });
    log.debug("Leaving Scep.answerMessage(). ok=" + result.ok);
    return result;
  }

  // ---------------------------------------------------------------------------
  // THE FOUR OPERATIONS.
  // ---------------------------------------------------------------------------
  getCaCaps(req, res, operation) {
    const { log } = this.deps;
    log.debug("Entering Scep.getCaCaps().");
    res.status(200)
       .type('text/plain')
       .set('Cache-Control', 'no-store')
       .send(CAPABILITIES.join('\n') + '\n');
    this.record({ operation: operation, outcome: 'answered', status: 200 });
    log.debug("Leaving Scep.getCaCaps().");
  }

  async getCaCert(req, res, operation) {
    const { log, ra, realms, core, errorCodes, cms } = this.deps;
    log.debug("Entering Scep.getCaCert().");
    const keys = await ra.ensure(realms.currentId());
    const chain = core.caChainOf('scep');
    if (!keys.ok || !chain.ok) {
      const code = errorCodes.codeOf(keys) || 'STS-SCEP-0005';
      this.record({ operation: operation, outcome: 'refused', status: 503,
                    errorCode: code });
      this.scepError(res, 503, code, (keys.errors || [])[0] ||
                     'This realm has no SCEP Issuing CA.');
      log.debug("Leaving Scep.getCaCert(). No authority.");
      return;
    }
    const body = cms.certsOnly([keys.certificatePem, chain.issuingPem,
                               chain.intermediatePem, chain.rootPem]
      .filter(function (one) { return !!one; }));
    res.status(200)
       .type('application/x-x509-ca-ra-cert')
       .set('Cache-Control', 'no-store')
       .send(body);
    this.record({ operation: operation, outcome: 'answered', status: 200 });
    log.debug("Leaving Scep.getCaCert().");
  }

  messageBytes(req, res, operation) {
    const { log } = this.deps;
    log.debug("Entering Scep.messageBytes().");
    const limit = this.maxBytes();
    if (req.method === 'POST') {
      const type = String(req.headers['content-type'] || '').split(';')[0]
        .trim().toLowerCase();
      if (type !== 'application/x-pki-message' || !Buffer.isBuffer(req.body)) {
        this.record({ operation: operation, outcome: 'refused', status: 415,
                      errorCode: 'STS-SCEP-0007' });
        this.scepError(res, 415, 'STS-SCEP-0007',
                       'A PKIOperation POST carries Content-Type: ' +
                       'application/x-pki-message (RFC 8894 section 4.3).');
        log.debug("Leaving Scep.messageBytes(). Content type.");
        return null;
      }
      if (req.body.length > limit) {
        this.record({ operation: operation, outcome: 'refused', status: 413,
                      errorCode: 'STS-SCEP-0008' });
        this.scepError(res, 413, 'STS-SCEP-0008', 'The message is ' +
                       req.body.length + ' bytes and scep.maxRequestBytes is ' +
                       limit + '.');
        log.debug("Leaving Scep.messageBytes(). Too large.");
        return null;
      }
      log.debug("Leaving Scep.messageBytes(). POST.");
      return req.body;
    }
    const text = String(req.query.message || '');
    if (text.length > Math.ceil(limit / 3) * 4 + 4) {
      this.record({ operation: operation, outcome: 'refused', status: 413,
                    errorCode: 'STS-SCEP-0008' });
      this.scepError(res, 413, 'STS-SCEP-0008',
                     'The message parameter is longer ' +
                     'than scep.maxRequestBytes (' + limit + ') allows.');
      log.debug("Leaving Scep.messageBytes(). Too large.");
      return null;
    }
    if (!text || text.length % 4 !== 0 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
      this.record({ operation: operation, outcome: 'refused', status: 400,
                    errorCode: 'STS-SCEP-0009' });
      this.scepError(res, 400, 'STS-SCEP-0009',
                     'A GET PKIOperation carries the ' +
                     'pkiMessage in the message parameter as base64 (RFC ' +
                     '8894 section 4.3), with no whitespace.');
      log.debug("Leaving Scep.messageBytes(). Not base64.");
      return null;
    }
    const bytes = Buffer.from(text, 'base64');
    if (bytes.length > limit) {
      this.record({ operation: operation, outcome: 'refused', status: 413,
                    errorCode: 'STS-SCEP-0008' });
      this.scepError(res, 413, 'STS-SCEP-0008',
                     'The message is ' + bytes.length +
                     ' bytes and scep.maxRequestBytes is ' + limit + '.');
      log.debug("Leaving Scep.messageBytes(). Too large.");
      return null;
    }
    log.debug("Leaving Scep.messageBytes(). GET.");
    return bytes;
  }

  async pkiOperation(req, res, operation, urlProfile) {
    const { log, core, errorCodes, cms, audit, ra, realms } = this.deps;
    log.debug("Entering Scep.pkiOperation().");
    const early = await core.throttledShared('scep', req, '');
    if (early) {
      this.record({ operation: operation, outcome: 'refused', status: 429,
                    errorCode: errorCodes.codeOf(early) });
      this.scepError(res, 429, errorCodes.codeOf(early) || 'STS-ENROLL-0061',
                     early.why,
                     { 'Retry-After': String(core.retryAfterOf(early)) });
      log.debug("Leaving Scep.pkiOperation(). Throttled.");
      return;
    }
    const bytes = this.messageBytes(req, res, operation);
    if (!bytes) {
      core.countFailure('scep', req, '');
      log.debug("Leaving Scep.pkiOperation(). The bytes.");
      return;
    }
    const message = cms.parsePkiMessage(bytes);
    if (!message.ok) {
      core.countFailure('scep', req, '');
      this.record({ operation: operation, outcome: 'refused', status: 400,
                    errorCode: message.code });
      audit.failure(message.code, { protocol: 'SCEP',
        summary: 'a SCEP pkiMessage was refused before it could be named: ' +
                 message.why });
      // The parser's own code: STS-SCEP-0010, STS-SCEP-0011 or STS-SCEP-0012.
      this.scepError(res, 400, message.code, message.why);
      log.debug("Leaving Scep.pkiOperation(). Unreadable.");
      return;
    }
    const typeName = cms.MESSAGE_TYPES[message.messageType] ||
                     ('messageType ' + message.messageTypeText);
    const opName = operation + ':' + typeName;
    const keys = await ra.ensure(realms.currentId());
    if (!keys.ok) {
      const code = errorCodes.codeOf(keys) || 'STS-SCEP-0005';
      this.record({ operation: opName, outcome: 'refused', status: 503,
                    errorCode: code });
      this.scepError(res, 503, code, (keys.errors || [])[0]);
      log.debug("Leaving Scep.pkiOperation(). No RA.");
      return;
    }
    const result = await this.answerMessage({ req: req, message: message,
                                              ra: keys,
                                              urlProfile: urlProfile });
    if (result.http) {
      this.record({ operation: opName, outcome: 'refused', status: 429,
                    errorCode: errorCodes.codeOf(result.http),
                    principal: result.identity });
      this.scepError(res, 429,
                     errorCodes.codeOf(result.http) || 'STS-ENROLL-0061',
                     result.http.why,
                     { 'Retry-After': String(core.retryAfterOf(result.http)) });
      log.debug("Leaving Scep.pkiOperation(). Throttled.");
      return;
    }
    const digest = (cms.DIGESTS[message.digestAlg] || {}).id || 'sha256';
    let body = null;
    try {
      if (result.ok) {
        const inner = result.crlDer
          ? cms.certsOnly([], [result.crlDer])
          : cms.certsOnly([result.certificatePem]);
        body = cms.certRep({
          raCertificatePem: keys.certificatePem,
          raPrivateKeyPem: keys.privateKeyPem,
          transactionID: message.transactionID,
          recipientNonce: message.senderNonce,
          pkiStatus: cms.PKI_STATUS.SUCCESS,
          content: cms.envelope(inner, message.signer.pem, result.cipher),
          digest: digest
        });
      } else {
        body = cms.certRep({
          raCertificatePem: keys.certificatePem,
          raPrivateKeyPem: keys.privateKeyPem,
          transactionID: message.transactionID,
          recipientNonce: message.senderNonce,
          pkiStatus: cms.PKI_STATUS.FAILURE,
          failInfo: result.failInfo,
          digest: digest
        });
      }
    } catch (e) {
      log.debug("Caught in Scep.pkiOperation(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SCEP-0044') + 'scep: a CertRep could not ' +
                'be built for transaction ' + message.transactionID + ': ' +
                ((e && e.stack) || e));
      body = null;
    }
    if (!body) {
      this.record({ operation: opName, outcome: 'refused', status: 500,
                    errorCode: 'STS-SCEP-0044' });
      this.scepError(res, 500, 'STS-SCEP-0044',
                     'The reply could not be built.');
      log.debug("Leaving Scep.pkiOperation(). No CertRep.");
      return;
    }
    if (!result.ok && core.sharesThrottle()) {
      // WHERE THE THROTTLE IS SHARED THE COUNT DECIDES THE ANSWER (2026-09-14):
      // a FAILURE whose count took the caller past the limit is answered with
      // the throttle's 429 rather than a CertRep naming what the challenge
      // password got wrong — `core.countFailureShared()` argues it.
      const overLimit = await core.countFailureShared('scep', req,
                                                      result.identity || '');
      if (overLimit) {
        this.record({ operation: opName, outcome: 'refused', status: 429,
                      errorCode: 'STS-ENROLL-0061',
                      principal: result.identity });
        this.scepError(res, 429, 'STS-ENROLL-0061', overLimit.why,
                       { 'Retry-After': String(core.retryAfterOf(overLimit)) });
        log.debug("Leaving Scep.pkiOperation(). Past the shared throttle.");
        return;
      }
    } else if (!result.ok) {
      core.countFailure('scep', req, result.identity || '');
    }
    if (!result.ok) {
      if (!result.audited) {
        audit.failure(result.code, { protocol: 'SCEP',
          actor: result.principal || '', target: result.principal || '',
          summary: 'a SCEP ' + typeName + ' was answered FAILURE ' +
                   (FAIL_NAMES[result.failInfo] || '') + ': ' +
                   String(result.why).slice(0, 300),
          detail: { transactionID: message.transactionID,
                    failInfo: FAIL_NAMES[result.failInfo] || '' } });
      }
      errorCodes.mark(res, result.code);
    }
    res.status(200)
       .type('application/x-pki-message')
       .set('Cache-Control', 'no-store')
       .send(body);
    this.record({
      operation: opName,
      outcome: result.ok ? (result.issued && !result.replay ? 'issued'
                                                             : 'answered')
                              : 'refused',
      status: 200,
      profile: result.profile || null,
      principal: result.principal || result.identity || null,
      target: result.target || null,
      errorCode: result.ok ? null : result.code,
      serialHex: result.serialHex || null,
      failInfo: result.ok ? null : (FAIL_NAMES[result.failInfo] || null)
    });
    log.debug("Leaving Scep.pkiOperation(). ok=" + result.ok);
  }

  // ---------------------------------------------------------------------------
  // ONE HANDLER FOR THE EIGHT ROUTES.
  // ---------------------------------------------------------------------------
  async handle(req, res) {
    const { log, validation } = this.deps;
    log.debug("Entering Scep.handle(). " + req.method + " " + req.path);
    const urlProfile = req.params && req.params.profile
      ? String(req.params.profile) : '';
    if (urlProfile && !PROFILE_SEGMENT.test(urlProfile)) {
      this.record({ operation: 'invalid', outcome: 'refused', status: 400,
                    errorCode: 'STS-SCEP-0013' });
      this.scepError(res, 400, 'STS-SCEP-0013', 'The path segment after ' +
                     '/enroll/scep/ names a certificate profile.');
      log.debug("Leaving Scep.handle(). Malformed profile.");
      return;
    }
    if (!this.enabled()) {
      this.record({ operation: 'disabled', outcome: 'refused', status: 503,
                    errorCode: 'STS-SCEP-0001' });
      this.scepError(res, 503, 'STS-SCEP-0001',
                     'SCEP is turned off in this realm ' +
                     '(scep.enabled).');
      log.debug("Leaving Scep.handle(). Disabled.");
      return;
    }
    const query = validation.check(req, 'query', QUERY);
    if (!query.ok) {
      this.record({ operation: 'invalid', outcome: 'refused', status: 400,
                    errorCode: 'STS-SCEP-0002' });
      this.scepError(res, 400, 'STS-SCEP-0002',
                     'SCEP: ' + query.detail + ' The ' +
                     'operations are ' + OPERATIONS.join(', ') + '.');
      log.debug("Leaving Scep.handle(). Bad query.");
      return;
    }
    const operation = query.value.operation;
    if (req.method === 'POST' && operation !== 'PKIOperation') {
      this.record({ operation: operation, outcome: 'refused', status: 405,
                    errorCode: 'STS-SCEP-0003' });
      this.scepError(res, 405, 'STS-SCEP-0003',
                     operation + ' is a GET (RFC 8894 ' +
                     'section 4); only PKIOperation may be POSTed.',
                     { Allow: 'GET' });
      log.debug("Leaving Scep.handle(). POST of a GET operation.");
      return;
    }
    if (operation === 'GetCACaps') {
      this.getCaCaps(req, res, operation);
    } else if (operation === 'GetCACert') {
      await this.getCaCert(req, res, operation);
    } else if (operation === 'GetNextCACert') {
      this.record({ operation: operation, outcome: 'refused', status: 501,
                    errorCode: 'STS-SCEP-0004' });
      this.scepError(res, 501, 'STS-SCEP-0004',
                     'GetNextCACert is not implemented: ' +
                     'this service does not pre-announce a CA rollover, and ' +
                     'GetCACaps does not advertise it.');
    } else {
      await this.pkiOperation(req, res, operation, urlProfile);
    }
    log.debug("Leaving Scep.handle().");
  }

  route(req, res) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Scep.route().");
    this.handle(req, res).catch(function (e) {
      log.error(errorCodes.tag('STS-SCEP-0044') + 'scep: a request failed: ' +
                ((e && e.stack) || e));
      if (!res.headersSent) {
        self.scepError(res, 500, 'STS-SCEP-0044',
                       'The SCEP request could not be answered.');
      }
    });
    log.debug("Leaving Scep.route().");
  }

  // THE ROUTES, registered where they always were: the transitional
  // code below calls this at load, at the point the first of them
  // used to be registered, so the route order is unchanged (rule 1).
  registerRoutes(app: RouteApp): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Scep.registerRoutes().");
    PATHS.forEach(function (path) {
      app.get(path, self.route.bind(self));
      app.post(path, self.route.bind(self));
    });
    log.debug("Leaving Scep.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const scep = new Scep({
  nodeCrypto: nodeCrypto,
  log: log,
  audit: audit,
  config: config,
  errorCodes: errorCodes,
  realms: realms,
  validation: validation,
  core: core,
  monitor: monitor,
  claims: claims,
  cms: cms,
  ra: ra,
  loadPersistence: function () {
    return require('../persistence/persistence');
  },
  loadPkiRevocation: function () {
    return require('../common/pki_revocation');
  }
});

const FAIL_NAMES = {};
Object.keys(cms.FAIL_INFO).forEach(function (name) {
  FAIL_NAMES[cms.FAIL_INFO[name]] = name;
});

const HANDLERS = { 19: scep.pkcsReq.bind(scep), 17: scep.renewalReq.bind(scep),
                   20: scep.certPoll.bind(scep), 21: scep.getCert.bind(scep),
                   22: scep.getCrl.bind(scep) };

// `pkiclient.exe` BEFORE `:profile`, so the literal CGI name every SCEP client
// appends is never read as a profile called "pkiclient.exe".
const PATHS = ['/enroll/scep', '/enroll/scep/pkiclient.exe',
               '/enroll/scep/:profile/pkiclient.exe',
               '/enroll/scep/:profile'];

scep.registerRoutes(app);

// The console pages and their management API operations are this family's
// own, required here so the family is one line in common/protocol_stack.js.
//
// **THIS USED TO COME AFTER THE EXPORTS WERE ASSIGNED**, so that a console
// model reading this module's tables at load could not be handed an empty
// object. As TypeScript (#50) it cannot: `export =` is emitted as the LAST
// statement of the compiled file wherever it stands here, so this require runs
// before the exports are assigned — and is written above them to say so. That
// is safe because nothing on its path reads this module at load:
// `scep_console.ts` requires it lazily, when a page is drawn. A new reader at
// load would be handed an empty object, which is the hazard this note is for.
require('./scep_admin');

export = {
  Scep: Scep,
  OPERATIONS: OPERATIONS,
  CAPABILITIES: CAPABILITIES,
  PATHS: PATHS,
  TRANSACTION_TTL_MS: TRANSACTION_TTL_MS,
  MAX_TRANSACTIONS: MAX_TRANSACTIONS,
  failInfoForCore: scep.failInfoForCore.bind(scep) as Scep['failInfoForCore']
};
