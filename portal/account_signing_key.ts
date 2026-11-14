// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_signing_key.ts
//
// ---------------------------------------------------------------------------
// `/portal/signing-key`'s TWO OPERATIONS (#568): the page's view and the one
// door its forms post to. Moved from `portal.ts` when the portal became a
// static application; the page is drawn by `web_signing_key.ts`.
//
// YOUR SIGNING KEYS (2026-09-12): RFC 7523 SECTION 2.1 AND RFC 7522, ISSUED
// BY THE PERSON THEY ARE FOR. A key pair from this realm's Issuing CA whose
// whole authority is *this is me*: `common/person_assertions.js` refuses an
// assertion signed with it that names anybody else as `sub`, on the
// registered key and on the certificate alike. Two profiles — RFC 7523's JWT
// key pairs and RFC 7522's SAML ones — each holding SEVERAL since #1290
// (rcbj, 2026-11-03), up to `pki.personSigningKeyMax` valid ones, each with
// its own label and revoked on its own row, as the TLS card's certificates
// are. Generate ADDS one; there is no Take off any more.
// And since 2026-09-13 a TLS CLIENT CERTIFICATE, the third card: a key and a
// certificate that sign a TLS handshake at `GET /tls/sign-in`
// (`common/tls_client_certificates.js`).
//
// **THE PRIVATE KEY IS SHOWN ONCE, AND THAT IS WHY `generate` ANSWERS A
// VIEW.** Every other act here answers a message. These two cannot: a
// credential on a URL is a credential in a browser history entry, this
// service's own access log and every proxy log between here and the person.
// So both generations answer `view.fresh.files` — the private key and the
// certificate chain, two PEM files, each as base64 the page turns into a
// `download` link in the certificate's own row — and the runtime draws them
// in place. **AND THERE IS NO SECOND CHANCE**: a signing key is written to
// the entry sealed under the key-encryption key and nothing opens it again,
// and a TLS client certificate's key is not kept at all.
//
// **NO FILE PASSWORD AND NO PKCS#12 (#671, rcbj, 2026-11-03).** The TLS card
// asked for a password and answered a `.p12` beside an encrypted PEM key;
// rcbj asked for the three cards to work alike, with no password, accepting
// that a browser can no longer import the result. The key file is the
// unencrypted PKCS#8 PEM the issue handed over, as the two signing keys'
// are, and the files are the same pair on every card.
//
// **THE SETTING IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE**
// (`pki.personSelfService`, 403 when off), and BOTH generations are RATE
// LIMITED (`portal-signing-key`, per identity and per address): generating
// an RSA key pair is hundreds of milliseconds of CPU in a process that
// answers every protocol on one thread.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT.** The form
// has no name field, and a TLS certificate's serial is looked up among THIS
// person's certificates only in `tlsClient.revoke()`, as a signing key's
// handle is among this person's key pairs only in
// `personAssertions.revoke()` — one belonging to somebody else matches
// nothing.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import Classes = require('../common/domain_classes');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import pki = require('../common/pki');
import personAssertions = require('../common/person_assertions');
import tlsClient = require('../common/tls_client_certificates');
import validation = require('../common/validation');
import ModelZod = require('../common/model_zod');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountAnswering<K extends keyof IyaApi.Account.Operations> =
  import('../types/account-api').AccountAnswering<K>;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

// THE TWO PROFILES. Their names on the page are the page's own (the
// `portal.signingKey.*` catalog); the grant type is what the one-time card
// tells somebody to send.
const SIGNING_KEY_PROFILES = [
  { id: 'jwt', rfc: 'RFC 7523',
    grantType: 'urn:ietf:params:oauth:grant-type:jwt-bearer' },
  { id: 'saml', rfc: 'RFC 7522',
    grantType: 'urn:ietf:params:oauth:grant-type:saml2-bearer' }
];

// THE SIGNING KEY'S FORM (2026-09-12). No lifetime field and no algorithm
// field — the deployment's answers — and above all NO NAME FIELD: a
// `username` here would let anybody signed in issue THEMSELVES a key pair on
// somebody else's entry, which is a takeover rather than a leak.
// `remove` (take off) left with #1290: a signing key pair is REVOKED, one
// at a time, by `revoke` with its `handle`.
const SIGNING_KEY_FORM = ModelZod.body('account', 'changeSigningKeys');

interface AccountSigningKeyDeps {
  log: typeof helpers.log;
  config: typeof config;
  pki: typeof pki;
  personAssertions: typeof personAssertions;
  tlsClient: typeof tlsClient;
  portal(): Json;
}

/**
 * `/portal/signing-key`'s account API operations.
 */
class AccountSigningKey {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountSigningKeyDeps) {
    deps.log.debug("Entering AccountSigningKey.constructor().");
    deps.log.debug("Leaving AccountSigningKey.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountSigningKeyDeps {
    helpers.log.debug("Entering AccountSigningKey.defaultDeps().");
    helpers.log.debug("Leaving AccountSigningKey.defaultDeps().");
    return {
      log: helpers.log, config: config, pki: pki,
      personAssertions: personAssertions, tlsClient: tlsClient,
      // The portal's directory slot, for the person's own `mail`: reached
      // when a request arrives, as this module is built beside it.
      portal: function portal(): Json {
        helpers.log.debug("Entering portal().");
        helpers.log.debug("Leaving portal().");
        return require('./portal');
      }
    };
  }

  /**
   * A profile by its id.
   *
   * @param id - `jwt` or `saml`
   * @returns the profile, or null
   */
  profileOf(id: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccountSigningKey.profileOf().");
    log.debug("Leaving AccountSigningKey.profileOf().");
    return SIGNING_KEY_PROFILES.filter(function (one) {
      return one.id === id;
    })[0] || null;
  }

  // What a person holds for one profile (#1290): every key pair with its
  // state, newest first, as the TLS card lists certificates — read off
  // `recordFor()`'s record, which is the register's own, so this page and
  // `/admin/users` cannot disagree. No private key is in it.
  /**
   * What the person holds for one profile.
   *
   * @param held - `personAssertions.recordFor()`'s record, or null
   * @param profile - the profile
   * @returns `{ keys, issuers, valid }`
   */
  heldProfile(held: Json, profile: Json): Json {
    const { log } = this.deps;
    log.debug("Entering AccountSigningKey.heldProfile().");
    const keys: Json[] = ((held && held.keys && held.keys[profile.id]) || [])
      .map(function (one: Json): Json {
        return { handle: String(one.id || ''),
                 label: String(one.label || ''),
                 source: String(one.source || ''),
                 serialHex: String(one.serialHex || ''),
                 keyAlg: String(one.keyAlg || ''),
                 notAfter: String(one.notAfter || ''),
                 expiresAt: String(one.expiresAt || ''),
                 state: String(one.state || ''),
                 reason: String(one.reason || ''),
                 revokedAt: String(one.revokedAt || ''),
                 certificate: String(one.certificatePem || '') };
      });
    log.debug("Leaving AccountSigningKey.heldProfile(). " + keys.length);
    return {
      keys: keys,
      valid: keys.filter(function (one: Json): boolean {
        return one.state === 'valid';
      }).length,
      issuers: [].concat((held && (profile.id === 'saml'
        ? held.samlEffectiveIssuers : held.effectiveIssuers)) || [])
    };
  }

  // The signed-in person's `mail`, off their own entry, for the rfc822Name a
  // certificate picker shows beside the common name. Absent is fine.
  /**
   * The person's own `mail`.
   *
   * @param username - the signed-in person
   * @returns the address, or ''
   */
  mailOf(username: string): string {
    const { log } = this.deps;
    log.debug("Entering AccountSigningKey.mailOf().");
    let entry: Json = null;
    try {
      entry = this.deps.portal().personEntry(username);
    } catch (e) {
      log.debug("Caught in AccountSigningKey.mailOf(): " +
                ((e && e.message) || e));
      // No directory to ask: the certificate is issued with no address.
      entry = null;
    }
    const user = Classes.User.fromEntry((entry && entry.attributes) || {});
    log.debug("Leaving AccountSigningKey.mailOf().");
    return user.email || '';
  }

  // THE TLS CLIENT CERTIFICATE CARD'S FACTS: the person's certificates, what
  // the register says about whether the main port accepts them, and the
  // closed lists the form offers. WHERE A CLIENT CERTIFICATE WORKS is ONE URL
  // since 2026-09-16 — the main port's `/tls/sign-in` — built from the base
  // the request arrived on, never a bare `Host`, so it honours
  // `global.publicBaseUrl`, a trusted proxy's headers and the realm prefix.
  /**
   * The TLS client certificate card's facts.
   *
   * @param username - the signed-in person
   * @param base - this realm's base URL
   * @returns the card's view
   */
  tlsView(username: string, base: string): Json {
    const { log, tlsClient } = this.deps;
    log.debug("Entering AccountSigningKey.tlsView().");
    let held: Json[] = [];
    try {
      held = tlsClient.listFor(undefined, username) || [];
    } catch (e) {
      // A process with no certificate authority holds no register to read.
      // The card says there is nothing, which is true.
      log.debug("Caught in AccountSigningKey.tlsView(): " +
                ((e && e.message) || e));
      held = [];
    }
    const report: Json = tlsClient.report() || {};
    const root = String(base || '').replace(/\/+$/, '');
    log.debug("Leaving AccountSigningKey.tlsView(). " + held.length);
    return {
      signIn: helpers.rebaseTo(root, 'authn') + '/tls/sign-in',
      trusted: !!report.trusted, note: String(report.note || ''),
      maxPerPerson: Number(report.maxPerPerson || 0),
      keyAlgs: (tlsClient.KEY_ALGS || []).slice(0),
      defaultKeyAlg: tlsClient.DEFAULT_KEY_ALG,
      held: held.map(function (one: Json): Json {
        return { label: String(one.label || ''),
                 serialHex: String(one.serialHex || ''),
                 keyAlg: String(one.keyAlg || ''),
                 notAfter: String(one.notAfter || ''),
                 state: String(one.state || ''),
                 reason: String(one.reason || ''),
                 revokedAt: String(one.revokedAt || '') };
      })
    };
  }

  // THE TWO FILES EVERY GENERATION ANSWERS (#671): the private key and the
  // certificate chain, leaf first, each as base64 for a `data:` link. One
  // shape for the three cards, so the page draws them one way.
  /**
   * A PEM file as the page's `download` link wants it.
   *
   * @param name - the file name
   * @param text - the PEM text
   * @returns `{ name, mime, base64 }`
   */
  static pemFile(name: string, text: string): Json {
    return { name: name, mime: 'application/x-pem-file',
             base64: Buffer.from(String(text), 'utf8').toString('base64') };
  }

  /**
   * The page's view.
   *
   * @param caller - the signed-in person
   * @param base - this realm's base URL
   * @param fresh - what a generation just answered, shown once, or null
   * @returns the view
   */
  view(caller: AccountCaller, base: string, fresh?: Json): Json {
    const { log, config, personAssertions, pki } = this.deps;
    const self = this;
    log.debug("Entering AccountSigningKey.view().");
    const username = caller.username;
    const held: Json = personAssertions.recordFor(username);
    const max = Number(personAssertions.maxPerPerson() || 0);
    const out = {
      username: username,
      entry: !!held,
      holdsAny: !!(held && (held.hasKeyPair || held.hasSamlKeyPair)),
      offered: config.value('pki.personSelfService') !== false,
      issuable: !!pki.hasChain(),
      tokenEndpoint: String(base || '') + '/oauth2/token',
      // THE CAP (#1290), per profile, and the two reasons a holder may give.
      maxPerPerson: max,
      reasons: (personAssertions.REVOCATION_REASONS || []).slice(0),
      profiles: SIGNING_KEY_PROFILES.map(function (profile) {
        const mine = self.heldProfile(held, profile);
        return { id: profile.id, rfc: profile.rfc,
                 grantType: profile.grantType,
                 held: mine,
                 atCap: max > 0 && mine.valid >= max };
      }),
      tls: this.tlsView(username, base),
      fresh: fresh || null
    };
    log.debug("Leaving AccountSigningKey.view().");
    return out;
  }

  /**
   * Carries out one of the page's four actions.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async act(ctx: AccountContext, req: Json,
            res: AccountAnswering<'changeSigningKeys'>, caller: AccountCaller,
            body: Json): Promise<unknown> {
    const { log, config, pki, personAssertions, tlsClient } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountSigningKey.act().");
    const self = this;
    const username = caller.username;
    const base = ctx.baseUrlOf(req);
    const action = String(body.action || '');
    const profile = this.profileOf(String(body.purpose || 'jwt'));
    const t = ctx.translatorFor(username);
    const codeOf = function (result: Json, fallback: string): string {
      return ctx.errorCodes.codeOf(result) ||
        String((result && result.errorCode) || '') || fallback;
    };
    const refuse = function (status: number, code: string,
                             why: string): unknown {
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, status, code, why,
                        { view: self.view(caller, base) });
    };
    const limited = async function (): Promise<Json> {
      return websecurity.attemptShared('portal-signing-key', req, username, {
        identity: config.value('pki.personSelfServicePerIdentity'),
        address: config.value('pki.personSelfServicePerAddress')
      });
    };

    // A TLS CLIENT CERTIFICATE: revoke one of yours. A message, because
    // nothing secret comes back.
    if (action === 'revoke-tls-client') {
      const revoked: Json = tlsClient.revoke(undefined, username,
                                             String(body.serial || ''),
                                             body.reason);
      if (!revoked.ok) {
        log.debug("Leaving AccountSigningKey.act(). Not revoked.");
        return refuse(400, codeOf(revoked, 'STS-PORTAL-0039'),
          (revoked.errors || ['That certificate could not be revoked.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.tls-client.revoked',
        actor: username, outcome: 'success',
        summary: username + ' revoked their own TLS client certificate ' +
                 revoked.certificate.serialHex + ' (' + revoked.reason + ')',
        detail: { serialHex: revoked.certificate.serialHex,
                  label: revoked.certificate.label, reason: revoked.reason,
                  already: !!revoked.already,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' revoked their TLS client ' +
               'certificate ' + revoked.certificate.serialHex + ' (' +
               revoked.reason + '). The main port refuses it from now on.');
      log.debug("Leaving AccountSigningKey.act(). TLS client revoked.");
      return ctx.json(res, 200, { ok: true,
                                  message: t.text('portal.done.tlsRevoked') });
    }

    // A TLS CLIENT CERTIFICATE: generate one, and answer with the files —
    // shown once, in the view. The self-service switch and both rate limits
    // are the signing keys' own, checked in the same order.
    if (action === 'generate-tls-client') {
      if (config.value('pki.personSelfService') === false) {
        log.debug("Leaving AccountSigningKey.act(). Self-service is off.");
        return refuse(403, 'STS-PORTAL-0028', 'This service does not let ' +
          'people issue their own certificates. An administrator can issue ' +
          'one to you.');
      }
      const allowedTls = await limited();
      if (!allowedTls.ok) {
        log.debug("Leaving AccountSigningKey.act(). Rate limited.");
        return refuse(429, codeOf(allowedTls, 'STS-PORTAL-0020'),
                      allowedTls.detail);
      }
      const made: Json = await tlsClient.issue(undefined, {
        username: username,
        label: String(body.label || '').trim(),
        keyAlg: body.key_alg,
        email: this.mailOf(username)
      });
      if (!made.ok) {
        log.debug("Leaving AccountSigningKey.act(). Not issued.");
        return refuse(400, codeOf(made, 'STS-PORTAL-0041'),
          (made.errors || ['A TLS client certificate could not be ' +
                           'issued.'])[0]);
      }
      // THE KEY AND THE CHAIN AS THEY CAME OUT OF THE ISSUE (#671): nothing
      // is encrypted or packaged, so nothing between the issue and the
      // answer can fail and leave a certificate whose key is lost.
      const files: Json = tlsClient.pemFiles(made.issued);
      audit.record({
        category: 'authentication', action: 'portal.tls-client.issued',
        actor: username, outcome: 'success',
        summary: username + ' issued themselves a TLS client certificate, ' +
                 'serial ' + made.issued.serialHex,
        detail: { serialHex: made.issued.serialHex, label: made.issued.label,
                  keyAlg: made.issued.keyAlg, notAfter: made.issued.notAfter,
                  realm: made.issued.scope,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' issued themselves a TLS client ' +
               'certificate, serial ' + made.issued.serialHex + ', valid ' +
               'until ' + made.issued.notAfter + '. The private key went out ' +
               'once in the answer and is not readable again.');
      const fresh = {
        kind: 'tls-client',
        issued: { subject: String(made.issued.subject || ''),
                  serialHex: String(made.issued.serialHex || ''),
                  keyAlg: String(made.issued.keyAlg || ''),
                  notAfter: String(made.issued.notAfter || '') },
        files: {
          key: AccountSigningKey.pemFile(files.key.name, files.key.text),
          chain: AccountSigningKey.pemFile(files.chain.name, files.chain.text)
        }
      };
      log.debug("Leaving AccountSigningKey.act(). TLS client issued.");
      return ctx.json(res, 200, { ok: true,
                                  view: this.view(caller, base, fresh) });
    }

    // A SIGNING KEY PAIR: revoke one of yours (#1290), which replaced
    // "take off". A message, because nothing secret comes back. The handle
    // is looked up among THIS person's key pairs only.
    if (action === 'revoke') {
      const revoked: Json = personAssertions.revoke(username, profile.id,
        String(body.handle || ''), body.reason,
        { initiatingEntity: 'user', via: 'portal' });
      if (!revoked.ok) {
        log.debug("Leaving AccountSigningKey.act(). Not revoked.");
        return refuse(400, codeOf(revoked, 'STS-PORTAL-0625'),
          (revoked.errors || ['That key pair could not be revoked.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.signing-key.revoked',
        actor: username, outcome: 'success',
        summary: username + ' revoked their own ' + profile.rfc + ' signing ' +
                 'key pair ' + revoked.key.id + ' (' + revoked.reason + ')',
        detail: { purpose: profile.id, handle: revoked.key.id,
                  serialHex: revoked.key.serialHex, label: revoked.key.label,
                  reason: revoked.reason, already: !!revoked.already,
                  onList: !!revoked.onList,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' revoked their ' + profile.rfc +
               ' signing key pair ' + revoked.key.id + ' (' + revoked.reason +
               '). Assertions signed with it are refused from now on.');
      log.debug("Leaving AccountSigningKey.act(). Revoked.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portal.done.keyRevoked', { rfc: profile.rfc }) });
    }

    if (action === 'generate') {
      if (config.value('pki.personSelfService') === false) {
        log.debug("Leaving AccountSigningKey.act(). Self-service is off.");
        return refuse(403, 'STS-PORTAL-0028', 'This service does not let ' +
          'people issue their own signing keys. An administrator can issue ' +
          'one to you.');
      }
      // THE CAP AND THE LABEL BEFORE A KEY PAIR IS GENERATED (#1290), and
      // before the rate limit: an RSA key pair is CPU on the one thread, and
      // generating one only for `write()` to refuse it would spend that and
      // lose the key — and a refusal that generates nothing should not use
      // up one of the person's generations either.
      const label = String(body.label || '').trim();
      const labelSaid = personAssertions.labelProblem(label);
      if (labelSaid) {
        log.debug("Leaving AccountSigningKey.act(). Label refused.");
        return refuse(400, 'STS-PKI-0225', labelSaid);
      }
      if (personAssertions.atCap(username, profile.id)) {
        log.debug("Leaving AccountSigningKey.act(). At the cap.");
        return refuse(400, 'STS-PKI-0223', 'You already hold ' +
          personAssertions.maxPerPerson() + ' ' + profile.rfc + ' signing ' +
          'key pairs that are still valid, which is the most this service ' +
          'issues to one person. Revoke one you no longer use and generate ' +
          'again.');
      }
      // RATE LIMITED, two settings since 2026-09-12 whose defaults are the
      // five it was: per identity, and per address so that everybody behind
      // one NAT does not share five key generations a window between them.
      const allowed = await limited();
      if (!allowed.ok) {
        log.debug("Leaving AccountSigningKey.act(). Rate limited.");
        return refuse(429, codeOf(allowed, 'STS-PORTAL-0020'),
                      allowed.detail);
      }
      const issued: Json = await pki.issueSigningKeyPair(undefined, {
        identifier: username,
        purpose: profile.id,
        // WHAT PUTS `urn:sts:person:<name>` IN THE CERTIFICATE, and the whole
        // reason this page may exist: it holds the key to asserting about its
        // own holder even when it is presented on its `x5c` alone.
        subjectKind: 'person',
        commonName: username,
        days: config.value('pki.leafLifetimeDays')
      });
      if (!issued.ok) {
        log.debug("Leaving AccountSigningKey.act(). The issue failed.");
        return refuse(400, codeOf(issued, 'STS-PORTAL-0029'),
          (issued.errors || ['A key pair could not be issued.'])[0]);
      }
      const record = issued.issued;
      const written: Json = personAssertions.write(username, record,
        { purpose: profile.id, label: label, initiatingEntity: 'user',
          via: 'portal' });
      if (!written.ok) {
        // THE KEY PAIR IS GONE AND THE PAGE SAYS SO. `common/pki.js` hands
        // one over ONCE and keeps no copy, so a failed write is not a state
        // to retry from.
        log.error(ctx.errorCodes.tag('STS-PORTAL-0030') +
                  'portal: a signing key pair was issued to ' + username +
                  ' and could not be written: ' +
                  (written.errors || []).join(' '));
        log.debug("Leaving AccountSigningKey.act(). Not written.");
        return refuse(500, codeOf(written, 'STS-PORTAL-0030'),
          (written.errors || ['It could not be written to your entry.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.signing-key.issued',
        actor: username, outcome: 'success',
        summary: username + ' issued themselves an ' + profile.rfc +
                 ' signing key pair',
        detail: { purpose: profile.id, kid: record.kid, label: label,
                  thumbprint: record.certificateThumbprint,
                  notAfter: record.notAfter, keyAlg: record.keyAlg,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' issued themselves an ' +
               profile.rfc + ' signing key pair, ' +
               (profile.id === 'saml'
                 ? 'thumbprint=' + record.certificateThumbprint
                 : 'kid=' + record.kid) +
               ', valid until ' + record.notAfter + '. The private half was ' +
               'offered to them once and is not readable again.');
      log.debug("Leaving AccountSigningKey.act(). Issued and showing.");
      // The files are named for the person, the profile and the label, as a
      // TLS client certificate's are for the person and the device — two
      // key pairs of one profile are two pairs of files a person can tell
      // apart in a downloads folder.
      const stem = (String(username + (label ? '-' + label : ''))
        .replace(/[^A-Za-z0-9._-]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'person') + '-' + profile.id + '-signing';
      const chain = [record.certificatePem].concat(record.chainPem || [])
        .map(function (one: Json): string {
          return String(one).trim() + '\n';
        }).join('');
      return ctx.json(res, 200, { ok: true, view: this.view(caller, base, {
        purpose: profile.id,
        // WHICH ROW OF THE LIST IS THE NEW ONE (#1290): the page draws the
        // two downloads in that key pair's own row.
        handle: profile.id === 'saml' ? record.certificateThumbprint || ''
                                      : record.kid || '',
        label: label,
        files: {
          key: AccountSigningKey.pemFile(stem + '-key.pem',
                                         record.privateKeyPem),
          chain: AccountSigningKey.pemFile(stem + '-chain.pem', chain)
        },
        kid: record.kid || '',
        thumbprint: record.certificateThumbprint || '',
        jwsAlg: record.jwsAlg || '',
        issuer: username
      }) });
    }

    // An `action` the schema allowed and this door does not know is not
    // reachable from the page.
    log.debug("Leaving AccountSigningKey.act(). No action.");
    return refuse(400, 'STS-PORTAL-0026', 'Nothing was asked for.');
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountSigningKey.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/signing-key',
        operationId: 'getSigningKeys', access: 'person', query: ModelZod.query('account', 'getSigningKeys'),
        handler: function (req, res,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller, ctx.baseUrlOf(req)));
        } },
      { method: 'POST', path: ctx.BASE + '/signing-key',
        operationId: 'changeSigningKeys', access: 'person', recentAuth: true, body: SIGNING_KEY_FORM,
        handler: function (req, res, caller: AccountCaller,
                           input): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountSigningKey.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountSigningKey>(
  'portal/account_signing_key',
  () => new AccountSigningKey(AccountSigningKey.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/signing-key`'s account API operations (#568).
 * @namespace
 */
export = {
  AccountSigningKey: AccountSigningKey,
  installInstance: (instance: AccountSigningKey): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
