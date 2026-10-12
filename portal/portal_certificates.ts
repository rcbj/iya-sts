// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_certificates.ts — /portal/certificates, WHERE A PERSON GETS
// WHAT ACME AND SCEP NEED TO ISSUE THEM A CERTIFICATE, AND SEES WHAT THEY WERE
// ISSUED (2026-09-13).
//
// ACME and SCEP authenticate with a credential bound to ONE directory entry —
// an External Account Binding key and a single-use challenge password
// (`common/cert_enrollment.ts`). An administrator can make one for anybody on
// `/admin/acme` and `/admin/scep`; this page is where a person makes one for
// THEMSELVES, which is rcbj's rule read from the person's side: *any user can
// only issue key pairs that map to their authenticated user identity*.
//
// **SINCE #568 THESE ARE TWO `/account-api` OPERATIONS** — the view and the
// acts — and the page is drawn in the browser by `web_certificates.ts`.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md). The body carries no name; every
// credential is created FOR `{ kind: 'person', id: caller.username }`, and
// every delete, and every revocation, is checked against that same entry — a
// kid, a challenge id or a serial belonging to somebody else matches nothing
// and is answered as though it did not exist, so the page is not an oracle
// for which credentials other people hold.
//
// **A SECRET IS SHOWN ONCE, IN THE ANSWER'S `view`** — the HMAC key and the
// challenge password are in that answer and nowhere else, never on a URL, for
// `/portal/signing-key`'s reason: a secret on a query string is a secret in
// the browser history, the access log and the next request's `Referer`.
//
// THE ADDRESSES THE PAGE PRINTS — the ACME directory, the EST and SCEP
// endpoints, SCEP's plain-HTTP twin — are built HERE, on the base the request
// arrived on and each family's own listener (`helpers.rebaseTo()`, #472), and
// carried in the view: the browser has neither.
// ---------------------------------------------------------------------------

import stsCrypto = require('../common/crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import core = require('../common/cert_enrollment');
import monitor = require('../common/enrollment_monitor');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalCertificatesDeps {
  log: { debug(message: string): void; info(message: string): void };
  core: Json;
  monitor: Json;
  stsCrypto: typeof stsCrypto;
  // The plain-HTTP revocation listener's base in this realm (#210), asked
  // for when a challenge is drawn.
  pkiRevocation: () => Json;
}

// The one-time secret an act just made.
interface Fresh {
  kind: string;
  kid?: string;
  hmacKey?: string;
  challenge?: string;
  profile?: string;
  expiresAt?: unknown;
}

/**
 * The RFC 5280 revocation reasons a person may give when revoking their own
 * certificate.
 */
const REVOCATION_REASONS = ['unspecified', 'keyCompromise',
                            'affiliationChanged', 'superseded',
                            'cessationOfOperation'];

/**
 * `/portal/certificates`' account API operations: what ACME and SCEP need to
 * issue a person a certificate, and what they were issued.
 */
class PortalCertificates {
  /**
   * The revocation reasons a person may give for their own certificate.
   */
  static readonly REVOCATION_REASONS = REVOCATION_REASONS;

  private form: Json = null;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalCertificatesDeps) {
    deps.log.debug("Entering PortalCertificates.constructor().");
    deps.log.debug("Leaving PortalCertificates.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalCertificatesDeps {
    helpers.log.debug("Entering PortalCertificates.defaultDeps().");
    helpers.log.debug("Leaving PortalCertificates.defaultDeps().");
    return {
      log: helpers.log,
      core: core,
      monitor: monitor,
      stsCrypto: stsCrypto,
      pkiRevocation: function pkiRevocation() {
        helpers.log.debug("Entering pkiRevocation().");
        helpers.log.debug("Leaving pkiRevocation().");
        return require('../common/pki_revocation');
      }
    };
  }

  /**
   * The body's schema, built once from the core's profiles.
   *
   * @returns the zod object
   */
  formSchema(): Json {
    const { log, core } = this.deps;
    log.debug("Entering PortalCertificates.formSchema().");
    if (!this.form) {
      this.form = vz.object({
        action: vt.opt(vt.oneOf(['create-eab', 'delete-eab',
                                 'create-challenge', 'delete-challenge',
                                 'revoke']))
          .describe('What to do.'),
        kid: vz.string().max(600).regex(/^[A-Za-z0-9_-]*$/).optional()
          .describe('The account binding key to delete.'),
        id: vz.string().max(600).regex(/^[A-Za-z0-9_-]*$/).optional()
          .describe('The challenge password to delete.'),
        // `device` (#164 phase 2): a SCEP challenge for a device of theirs.
        profile: vt.opt(vt.oneOf(core.PROFILE_IDS.concat(
          [core.DEVICE_PROFILE])))
          .describe('The profile a new SCEP challenge is for.'),
        serial: vz.string().max(80).regex(/^[0-9A-Fa-f:]*$/).optional()
          .describe('The serial of the certificate to revoke.'),
        reason: vt.opt(vt.oneOf(REVOCATION_REASONS))
          .describe('The RFC 5280 reason for a revocation.')
      });
    }
    log.debug("Leaving PortalCertificates.formSchema().");
    return this.form;
  }

  /**
   * The caller's own entry, as the core names it.
   *
   * @param caller - the signed-in person
   * @returns `{ kind, id }`
   */
  selfEntry(caller: AccountCaller): { kind: string; id: string } {
    const { log } = this.deps;
    log.debug("Entering PortalCertificates.selfEntry().");
    log.debug("Leaving PortalCertificates.selfEntry().");
    return { kind: 'person', id: String(caller.username) };
  }

  /**
   * Whether a family is on in this realm.
   *
   * @param ctx - the account API's helpers
   * @param family - `acme`, `est` or `scep`
   * @returns whether it is
   */
  enabled(ctx: AccountContext, family: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PortalCertificates.enabled(). family=" + family);
    log.debug("Leaving PortalCertificates.enabled().");
    return ctx.config.value(family + '.enabled') !== false;
  }

  // THE PAGE'S VIEW: everything the server-drawn page read while it drew —
  // the entry, its certificates, the families on, each family's credentials,
  // the profiles, the host names — and the addresses it printed, built here.
  /**
   * The page's view.
   *
   * @param ctx - the account API's helpers
   * @param caller - the signed-in person
   * @param base - the base the request arrived on
   * @param fresh - the secret just made, or null
   * @returns the view
   */
  view(ctx: AccountContext, caller: AccountCaller, base: string,
       fresh: Fresh | null): Json {
    const { log, core } = this.deps;
    log.debug("Entering PortalCertificates.view().");
    const entry = this.selfEntry(caller);
    const resolved: Json = core.resolveEntry(entry.kind, entry.id) || {};
    const scepBase = helpers.rebaseTo(base, 'scep') + '/enroll/scep';
    const out: Json = {
      name: entry.id,
      resolved: !!resolved.ok,
      reasons: REVOCATION_REASONS.slice(0),
      familyLabels: Object.assign({}, core.FAMILY_LABELS),
      urls: {
        acmeDirectory: helpers.rebaseTo(base, 'acme') +
                       '/enroll/acme/directory',
        scep: scepBase,
        est: helpers.rebaseTo(base, 'est') + '/.well-known/est'
      }
    };
    if (fresh) {
      out.fresh = Object.assign({}, fresh);
      if (fresh.kind !== 'eab') {
        // The plain-HTTP address too (#210): sscep and most device firmware
        // speak no TLS, and SCEP secures its own messages.
        out.fresh.scepUrl = scepBase + '/' + fresh.profile;
        out.fresh.plainScepUrl = this.deps.pkiRevocation()
          .httpBaseInRealm() + '/enroll/scep/' + fresh.profile;
      }
    }
    if (!resolved.ok) {
      log.debug("Leaving PortalCertificates.view(). No entry.");
      return out;
    }
    out.enrolled = core.enrolledOf(entry);
    out.hostNames = (resolved.hostNames || []).slice(0);
    out.acme = this.enabled(ctx, 'acme')
      ? { keys: core.eabsOf(entry) } : null;
    out.est = this.enabled(ctx, 'est')
      ? { profiles: core.allowedProfiles('est') } : null;
    out.scep = this.enabled(ctx, 'scep')
      ? { challenges: core.scepChallengesOf(entry),
          profiles: core.allowedProfiles('scep'),
          defaultProfile: core.defaultProfile('scep') }
      : null;
    log.debug("Leaving PortalCertificates.view().");
    return out;
  }

  /**
   * Makes, deletes or revokes one of the caller's enrollment credentials or
   * certificates.
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
    const { log, core, monitor, stsCrypto } = this.deps;
    const self = this;
    log.debug("Entering PortalCertificates.act().");
    const entry = this.selfEntry(caller);
    const base = ctx.baseUrlOf(req);
    const action = String(body.action || '');
    const t = ctx.translatorFor(caller.username);
    const refuse = function (status: number, code: string,
                             why: string): unknown {
      return ctx.refuse(res, status, code, why,
                        { view: self.view(ctx, caller, base, null) });
    };

    if (action === 'create-eab' || action === 'create-challenge') {
      const family = action === 'create-eab' ? 'acme' : 'scep';
      if (!this.enabled(ctx, family)) {
        log.debug("Leaving PortalCertificates.act(). Family off.");
        return refuse(403, 'STS-PORTAL-0050',
                      core.FAMILY_LABELS[family] +
                      ' is turned off in this realm.');
      }
      // One budget for the cluster (#46): `attemptShared()`.
      const allowed = await ctx.websecurity.attemptShared(
        'portal-enrollment', req, entry.id, {
          identity: ctx.config.value('pki.personSelfServicePerIdentity'),
          address: ctx.config.value('pki.personSelfServicePerAddress')
        });
      if (!allowed.ok) {
        log.debug("Leaving PortalCertificates.act(). Rate limited.");
        return refuse(429, ctx.errorCodes.codeOf(allowed) ||
                      'STS-PORTAL-0020', allowed.detail);
      }
      const made = family === 'acme'
        ? core.createEab({ target: entry, createdBy: entry.id })
        : core.createScepChallenge({ target: entry, createdBy: entry.id,
                                     profile: body.profile });
      if (!made.ok) {
        monitor.record(family, { operation: 'portal.' + action,
                                 outcome: 'refused', status: made.status,
                                 principal: entry.id,
                                 errorCode: ctx.errorCodes.codeOf(made) });
        log.debug("Leaving PortalCertificates.act(). Refused by the core.");
        return refuse(made.status || 400, 'STS-PORTAL-0047',
                      (made.errors || ['Not made.'])[0]);
      }
      monitor.record(family, { operation: 'portal.' + action,
                               outcome: 'credential', status: 200,
                               principal: entry.id,
                               profile: made.profile || null });
      log.info('portal: ' + entry.id + ' made themselves a ' +
               (family === 'acme' ? 'ACME account binding key' :
                'SCEP challenge password') + '. It was shown once.');
      log.debug("Leaving PortalCertificates.act(). Made.");
      const fresh: Fresh = family === 'acme'
        ? { kind: 'eab', kid: made.kid, hmacKey: made.hmacKey,
            expiresAt: made.expiresAt }
        : { kind: 'challenge', challenge: made.challenge,
            profile: made.profile, expiresAt: made.expiresAt };
      return ctx.json(res, 200, { ok: true,
                                  view: this.view(ctx, caller, base, fresh) });
    }

    if (action === 'delete-eab' || action === 'delete-challenge') {
      // Checked against THIS person's credentials before anything is
      // deleted, and one that is not theirs is answered as not found.
      const id = String(action === 'delete-eab' ? body.kid || '' :
                        body.id || '');
      const mine = (action === 'delete-eab' ? core.eabsOf(entry)
                                            : core.scepChallengesOf(entry))
        .some(function (one: Json) {
          const held = String(one.kid || one.id || '');
          // constantTimeEquals() answers false for two of different
          // lengths, where node's compare threw for two strings of one
          // length and different UTF-8 lengths.
          return id.length > 0 && stsCrypto.constantTimeEquals(held, id);
        });
      if (!mine) {
        log.debug("Leaving PortalCertificates.act(). Not theirs.");
        return refuse(404, 'STS-PORTAL-0048', 'You hold no such ' +
                      (action === 'delete-eab' ? 'account binding key.'
                                               : 'challenge password.'));
      }
      const gone = action === 'delete-eab'
        ? core.deleteEab(id, entry.id)
        : core.deleteScepChallenge(id, entry.id);
      if (!gone.ok) {
        log.debug("Leaving PortalCertificates.act(). Not deleted.");
        return refuse(400, 'STS-PORTAL-0048',
                      (gone.errors || ['Not deleted.'])[0]);
      }
      log.debug("Leaving PortalCertificates.act(). Deleted.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portalCertificates.done.deleted') });
    }

    if (action === 'revoke') {
      const revoked = await core.revokeEnrolled(String(body.serial || ''),
        body.reason || 'unspecified', entry.id, { entry: entry });
      if (!revoked.ok) {
        const code = ctx.errorCodes.codeOf(revoked);
        // A certificate that is somebody else's is answered as one that does
        // not exist, which is what the core's 0071 would otherwise reveal.
        const hidden = code === 'STS-ENROLL-0071' ||
                       code === 'STS-ENROLL-0070';
        log.debug("Leaving PortalCertificates.act(). Not revoked.");
        return refuse(hidden ? 404 : 400, 'STS-PORTAL-0049',
                      hidden ? 'You hold no certificate with that serial.'
                             : (revoked.errors || ['Not revoked.'])[0]);
      }
      monitor.record(revoked.family, { operation: 'portal.revoke',
                                       outcome: 'revoked', status: 200,
                                       principal: entry.id,
                                       serialHex: revoked.serialHex });
      log.debug("Leaving PortalCertificates.act(). Revoked.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portalCertificates.done.revoked') });
    }

    log.debug("Leaving PortalCertificates.act(). No such action.");
    return refuse(400, 'STS-PORTAL-0051',
                  'That is not something this page does.');
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
    log.debug("Entering PortalCertificates.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/certificates',
        operationId: 'getCertificates', tag: 'Certificates',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/certificates',
        summary: 'Your certificates and the enrollment credentials you hold',
        description: 'The certificates ACME, EST and SCEP issued for your ' +
          'entry, your ACME account binding keys and SCEP challenge ' +
          'passwords (never their secrets), the EST and SCEP profiles you ' +
          'may ask for, the host names registered on your entry, and the ' +
          'addresses of each family in this realm. A family turned off is ' +
          'null.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return ctx.json(res, 200, self.view(ctx, caller,
                                              ctx.baseUrlOf(req), null));
        } },
      { method: 'POST', path: ctx.BASE + '/certificates',
        operationId: 'changeCertificates', tag: 'Certificates',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/certificates',
        summary: 'Makes or deletes an enrollment credential, or revokes a ' +
                 'certificate',
        description: '`create-eab` and `create-challenge` (rate limited) ' +
          'make an ACME account binding key or a SCEP challenge password for ' +
          'your entry; its secret is in the answer\'s `view.fresh`, ONCE. ' +
          '`delete-eab` and `delete-challenge` remove an unused one of ' +
          'yours; `revoke` revokes a certificate issued for you. Anything ' +
          'that is not yours is answered as not found.',
        body: self.formSchema(),
        statuses: { 403: 'The family is turned off in this realm.',
                    404: 'You hold no such credential or certificate.',
                    429: 'Too many made; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalCertificates.accountOperations().");
    return rows;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`; a process that never runs the root gets a default
// instance, built from `defaultDeps()` when the module loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PortalCertificates>(
  'portal/portal_certificates',
  () => new PortalCertificates(PortalCertificates.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/certificates`' account API operations (#568).
 * @namespace
 */
export = {
  PortalCertificates: PortalCertificates,
  installInstance: (instance: PortalCertificates): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations'),
  REVOCATION_REASONS: PortalCertificates.REVOCATION_REASONS
};
