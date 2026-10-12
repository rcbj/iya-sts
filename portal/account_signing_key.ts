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
// key pair and RFC 7522's SAML one — each with its own Generate and Take off.
// And since 2026-09-13 a TLS CLIENT CERTIFICATE, the third card: a key and a
// certificate that sign a TLS handshake at `GET /tls/sign-in`
// (`common/tls_client_certificates.js`).
//
// **THE PRIVATE KEY IS SHOWN ONCE, AND THAT IS WHY `generate` ANSWERS A
// VIEW.** Every other act here answers a message. These two cannot: a
// credential on a URL is a credential in a browser history entry, this
// service's own access log and every proxy log between here and the person.
// So `generate` answers `view.fresh.privateKeyPem`, and `generate-tls-client`
// answers `view.fresh.files` — the PKCS#12, the key and the chain, each as
// base64 the page turns into a `download` link — and the runtime draws them
// in place. **AND THERE IS NO SECOND CHANCE**: the key is written to the
// entry sealed under the key-encryption key and nothing opens it again.
//
// **THE SETTING IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE**
// (`pki.personSelfService`, 403 when off), and BOTH generations are RATE
// LIMITED (`portal-signing-key`, per identity and per address): generating
// an RSA key pair is hundreds of milliseconds of CPU in a process that
// answers every protocol on one thread.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT.** The form
// has no name field, and a TLS certificate's serial is looked up among THIS
// person's certificates only in `tlsClient.revoke()` — one belonging to
// somebody else matches nothing.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import pki = require('../common/pki');
import personAssertions = require('../common/person_assertions');
import tlsClient = require('../common/tls_client_certificates');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
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
const SIGNING_KEY_FORM = vz.object({
  action: vt.opt(vt.oneOf(['generate', 'remove',
                          // A TLS client certificate (2026-09-13).
                          'generate-tls-client', 'revoke-tls-client']))
    .describe('`generate` or `remove` a signing key pair (for `purpose`); ' +
              '`generate-tls-client` or `revoke-tls-client` a TLS client ' +
              'certificate.'),
  label: vz.string().max(80).optional()
    .describe('For `generate-tls-client`: what you call the device.'),
  key_alg: vt.opt(vt.oneOf(tlsClient.KEY_ALGS))
    .describe('For `generate-tls-client`: the key algorithm.'),
  p12_password: vz.string().max(512).optional()
    .describe('For `generate-tls-client`: the password protecting the ' +
              'PKCS#12 file. Used once and not stored.'),
  p12_confirm: vz.string().max(512).optional()
    .describe('The same password again.'),
  serial: vz.string().max(80).regex(/^[0-9A-Fa-f:]*$/).optional()
    .describe('For `revoke-tls-client`: the certificate\'s serial, one of ' +
              'yours.'),
  reason: vt.opt(vt.oneOf(tlsClient.REVOCATION_REASONS))
    .describe('For `revoke-tls-client`: why.'),
  // WHICH PROFILE (2026-09-13). Absent means `jwt`, which is what every form
  // and client posted before the second profile existed.
  purpose: vt.opt(vt.oneOf(['jwt', 'saml']))
    .describe('For `generate` and `remove`: RFC 7523\'s `jwt` key pair (the ' +
              'default) or RFC 7522\'s `saml` one.')
});

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

  // What a person holds for one profile, read off `recordFor()`'s record by
  // the register's own attribute table — so this page and `/admin/users`
  // cannot disagree about which attribute holds the handle. Null where
  // nothing is held.
  /**
   * What the person holds for one profile.
   *
   * @param held - `personAssertions.recordFor()`'s record
   * @param profile - the profile
   * @returns the handle, expiry, certificate and issuers, or null
   */
  heldProfile(held: Json, profile: Json): Json {
    const { log, personAssertions } = this.deps;
    log.debug("Entering AccountSigningKey.heldProfile().");
    const names = personAssertions.KEY_PAIR_ATTRIBUTES[profile.id];
    if (!held || !names || !held[names.present]) {
      log.debug("Leaving AccountSigningKey.heldProfile(). Nothing held.");
      return null;
    }
    log.debug("Leaving AccountSigningKey.heldProfile().");
    return {
      handle: String(held[names.handle] || ''),
      expiresAt: String(held[names.expiresAt] || ''),
      certificate: String(held[names.certificate] || ''),
      issuers: [].concat((profile.id === 'saml' ? held.samlEffectiveIssuers
                                                : held.effectiveIssuers) || [])
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
    const attributes = (entry && entry.attributes) || {};
    const key = Object.keys(attributes).filter(function (one) {
      return one.toLowerCase() === 'mail';
    })[0];
    const values = key ? [].concat(attributes[key]) : [];
    log.debug("Leaving AccountSigningKey.mailOf().");
    return values.length ? String(values[0]) : '';
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
      passwordMin: tlsClient.PKCS12_PASSWORD_MIN,
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
    const out = {
      username: username,
      entry: !!held,
      holdsAny: !!(held && (held.hasKeyPair || held.hasSamlKeyPair)),
      offered: config.value('pki.personSelfService') !== false,
      issuable: !!pki.hasChain(),
      tokenEndpoint: String(base || '') + '/oauth2/token',
      profiles: SIGNING_KEY_PROFILES.map(function (profile) {
        return { id: profile.id, rfc: profile.rfc,
                 grantType: profile.grantType,
                 held: self.heldProfile(held, profile) };
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
  async act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
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
      const passwordSaid = tlsClient.pkcs12PasswordProblem(body.p12_password,
                                                           body.p12_confirm);
      if (passwordSaid) {
        log.debug("Leaving AccountSigningKey.act(). File password.");
        return refuse(400, 'STS-PORTAL-0040', passwordSaid);
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
      let files: Json = null;
      try {
        files = await tlsClient.bundle(made.issued, body.p12_password);
      } catch (e) {
        // THE CERTIFICATE EXISTS AND ITS KEY IS GONE. Revoked at once rather
        // than left valid in the register: a certificate nobody can ever
        // present is only a line on a list, and one nobody can revoke
        // because nobody knows its key was lost is worse.
        log.error(ctx.errorCodes.tag('STS-PORTAL-0042') + 'portal: a TLS ' +
                  'client certificate was issued to ' + username + ' and ' +
                  'its files could not be built, so it was revoked: ' +
                  ((e && e.message) || e));
        tlsClient.revoke(undefined, username, made.issued.serialHex,
                         'cessationOfOperation');
        log.debug("Leaving AccountSigningKey.act(). Not packaged.");
        return refuse(500, 'STS-PORTAL-0042', 'The certificate could not be ' +
                      'packaged for download, so it was revoked. Try again.');
      }
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
      // THE FILES AS BASE64, which the page turns into `download` links —
      // the PKCS#12 already is; the key and the chain are PEM text.
      const b64 = function (text: Json): string {
        return Buffer.from(String(text), 'utf8').toString('base64');
      };
      const fresh = {
        kind: 'tls-client',
        issued: { subject: String(made.issued.subject || ''),
                  serialHex: String(made.issued.serialHex || ''),
                  keyAlg: String(made.issued.keyAlg || ''),
                  notAfter: String(made.issued.notAfter || '') },
        files: {
          pkcs12: { name: files.pkcs12.name, mime: files.pkcs12.mime,
                    base64: files.pkcs12.base64 },
          key: { name: files.key.name, mime: files.key.mime,
                 base64: b64(files.key.text) },
          chain: { name: files.chain.name, mime: files.chain.mime,
                   base64: b64(files.chain.text) }
        }
      };
      log.debug("Leaving AccountSigningKey.act(). TLS client issued.");
      return ctx.json(res, 200, { ok: true,
                                  view: this.view(caller, base, fresh) });
    }

    if (action === 'remove') {
      // ONE PROFILE AT A TIME: taking the RFC 7522 key pair off leaves the
      // RFC 7523 one working, and the reverse.
      const removed: Json = personAssertions.clear(username, profile.id,
        { initiatingEntity: 'user', via: 'portal' });
      if (!removed.ok) {
        log.debug("Leaving AccountSigningKey.act(). Nothing to remove.");
        return refuse(400, 'STS-PORTAL-0027', 'You hold no ' + profile.rfc +
          ' signing key, so there was nothing to take off.');
      }
      audit.record({
        category: 'authentication', action: 'portal.signing-key.removed',
        actor: username, outcome: 'success',
        summary: username + ' took their own ' + profile.rfc + ' signing ' +
                 'key off',
        detail: { purpose: profile.id, attributes: removed.removed,
                  address: websecurity.addressOf(req) }
      });
      log.info('portal: ' + username + ' removed their ' + profile.rfc +
               ' assertion signing key. Assertions signed with it are ' +
               'refused from now on; the certificate itself is on no ' +
               'revocation list.');
      log.debug("Leaving AccountSigningKey.act(). Removed.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portal.done.keyOff', { rfc: profile.rfc }) });
    }

    if (action === 'generate') {
      if (config.value('pki.personSelfService') === false) {
        log.debug("Leaving AccountSigningKey.act(). Self-service is off.");
        return refuse(403, 'STS-PORTAL-0028', 'This service does not let ' +
          'people issue their own signing keys. An administrator can issue ' +
          'one to you.');
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
        { purpose: profile.id, initiatingEntity: 'user', via: 'portal' });
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
        detail: { purpose: profile.id, kid: record.kid,
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
               'shown to them once and is not readable again.');
      log.debug("Leaving AccountSigningKey.act(). Issued and showing.");
      return ctx.json(res, 200, { ok: true, view: this.view(caller, base, {
        purpose: profile.id,
        privateKeyPem: record.privateKeyPem,
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
        operationId: 'getSigningKeys', tag: 'Signing keys',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/signing-key',
        summary: 'Your signing key pairs and TLS client certificates',
        description: '`profiles`: RFC 7523\'s JWT and RFC 7522\'s SAML key ' +
          'pairs — for each, what you hold (its kid or thumbprint, the ' +
          'issuers you may assert as, its expiry and certificate) or null. ' +
          '`tls`: your TLS client certificates, where one signs you in, and ' +
          'what the form offers. `offered` (`pki.personSelfService`) and ' +
          '`issuable` (a certificate authority exists) say whether you may ' +
          'generate. No private key is ever in this answer.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(caller, ctx.baseUrlOf(req)));
        } },
      { method: 'POST', path: ctx.BASE + '/signing-key',
        operationId: 'changeSigningKeys', tag: 'Signing keys',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/signing-key',
        summary: 'Generates or takes off a signing key or TLS certificate',
        description: '`generate` issues a key pair for `purpose` from this ' +
          'realm\'s Issuing CA and answers its private key ONCE, in ' +
          '`view.fresh.privateKeyPem`; `remove` takes one off. ' +
          '`generate-tls-client` issues a TLS client certificate and answers ' +
          'its PKCS#12, key and chain ONCE, in `view.fresh.files` (base64); ' +
          '`revoke-tls-client` revokes one of yours. Both generations are ' +
          'refused (403) where self-service is off, and rate limited. A ' +
          'refusal carries the page\'s `view`.',
        body: SIGNING_KEY_FORM,
        statuses: { 403: 'Self-service issue is off in this service.',
                    429: 'Too many generations; try again later.',
                    500: 'Issued and then lost; nothing usable was kept.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
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
