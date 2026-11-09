// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_wallet.ts — /portal/wallet, WHERE A PERSON PUTS A CREDENTIAL
// ABOUT THEMSELVES INTO THEIR OWN WALLET (#589, 2026-10-12).
//
// OpenID4VCI's pre-authorized code flow (Appendix H.2, and H.3 where the
// issuance is deferred) starts with an End-User the issuer has ALREADY
// identified: the issuer makes a Credential Offer whose pre-authorized code
// IS the authorization, shows it as a QR code for the wallet on their other
// device, and shows the Transaction Code beside it — never inside it — for
// them to type into that wallet. Until #589 that was the product behaviour
// of the demo issuer's `/issuer/offer?mode=cross-device|deferred`, which from
// 2026-09-12 required a sign-on session and minted for the person signed in.
// rcbj decided on 2026-10-12 that it is a real self-service feature, not a
// demo: it belongs to the person's own pages, and the demo pages become
// development-only (#585). So it is here, as two `/account-api` operations:
//
//   GET  /account-api/credentials/offerable   what this person may be offered,
//                                             and what they were issued
//   POST /account-api/credentials/offers      an offer, for this person
//   POST /account-api/credentials/remove      one of their credentials
//                                             removed: every copy, or one
//
// and the page is drawn in the browser by `web_wallet.ts`, the QR code by
// `common/web_qr.ts`, from the offer URI the answer carries.
//
// **THE SUBJECT IS THE TOKEN'S, AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (OWASP A01, `portal/CLAUDE.md`): the offer names
// `caller.username` and its subject, and nobody else can be named.
//
// **THE OFFER IS MADE BY `oid4vc/vc_offers.ts`'s `makeOffer()`** (which the
// demo issuer's `/issuer/offer` called too, until it left the service on
// #594) — not a second implementation. What
// an offer is (the code, its lifetime, the Transaction Code, the reference
// stamped for its cell, the URIs) is said once there.
//
// **IT IS MADE ON THE SIGN-ON SESSION, AND CAEP SAYS SO** (#240): the
// portal's token was issued on a sign-on session (#568 binds it, and the
// gate refuses a token whose session has ended), and that session is what
// the offer's authority rests on — nobody authenticates for the code. So the
// sign-on session is handed to `makeOffer()`, which reports it
// `session-presented` naming OpenID4VCI. A
// token whose session the registry no longer knows, or a session that
// continued without signing in, is REFUSED rather than offered on nothing
// (`STS-PORTAL-0590`): an offer is a credential about the person, made on
// the strength of having identified them, and here that strength is the
// session.
//
// **THE HISTORY AND REMOVE (#661, 2026-10-16).** The page lists every
// credential `oid4vc/vc_issued.ts` still records for the person
// (`historyForSubject()`), 20 to a page,
// with its state and what their wallet last reported over OpenID4VCI's
// Notification Endpoint, and a Remove button for one that is still good.
// Neither OpenID4VP nor OpenID4VCI lets an issuer delete a credential from a
// wallet — OpenID4VP is a verifier ASKING for a presentation, and
// OpenID4VCI's notification runs the other way, wallet to issuer — so Remove
// is this service's half (`removeForSubject()`: the status-list entry
// INVALID, the issued register revoked, sign-in refused), and the page says
// the wallet's copy must be deleted in the wallet.
//
// **ONE ROW PER ISSUANCE, AND ITS COPIES UNDER IT (#670, rcbj 2026-10-17).**
// With batch issuance on (`oid4vci.batchSize`, 4 by default) a wallet takes
// four copies of a credential in one Credential Response, each bound to a
// different key of the wallet's so that verifiers cannot link its
// presentations by the key; listed one per copy, one "Add to your wallet"
// was four rows. So `issued` is `issuancesForSubject()`: one entry per
// issuance with its copies in `copies` (each told apart by its position,
// the RFC 7638 thumbprint of the key it is bound to or its holder's DID,
// and its status-list index), and the page says batching is on when the
// batch size is over one. Remove takes an issuance's id (every copy still
// good) or a copy's (that copy) — ONE operation, argued at
// `removeIssuedCredential` below. A page counts issuances.
//
// **THE SIGNING ALGORITHM IS THE PERSON'S CHOICE** (2026-10-16): each
// configuration's `signingAlgs` (`vc_configs.ts`'s `vciSigningAlgsFor()`,
// the configured `oid4vci.credentialSigningAlgorithm` first and the default)
// is in the view, and the offer's optional `signingAlg` must be one of its
// configuration's (`STS-PORTAL-0592`). It rides the pre-authorized code to
// the access token and the credential endpoint signs with it; the realm's
// Status List Token keeps the configured algorithm.
//
// **THE TOKEN'S SUBJECT AND ITS PERSON MUST NAME EACH OTHER** (2026-10-20).
// The history is read by `caller.sub` (the issued register's subject index)
// and the page is about `caller.username`; where the two disagree the
// history was somebody else's or, with no index entry, an empty list that
// read as "nothing issued". Each of the three operations refuses that
// (STS-PORTAL-0617, 403) unless either direction ties them — the subject is
// the person's entry's (`subjectForName()`, which folds a name the way the
// directory files it), or the subject's entry is filed under that name
// (`nameForSubject()`, which also reads the legacy `urn:sts:user:` form) —
// so a token the authorization server issued for a person always passes:
// its `sub` is the session user's and its `username` that user's name. In
// a process with no directory nothing can be compared and nothing is
// refused. With them agreeing and nothing indexed, the empty list stays.
//
// The same in both modes: this is the person's own credential, made for the
// person who asked. The demo issuer that minted for `oid4vci.offerUsername`
// for anybody left for the development companion on #594, which sends a
// person here for a pre-authorized offer.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalWalletDeps {
  log: { debug(message: string): void };
  userFor(username: string): any;
  // The directory's two lookups, for the subject check (the header).
  hasSubjectResolver(): boolean;
  nameForSubject(sub: string): string;
  subjectForName(name: string): string;
  // Required when first asked, never at load: `portal/` is built at 8a,
  // before the OpenID4VCI family (11–14), and `vc_offers.ts` is the module
  // that breaks `oauth2.ts`'s require cycle (root `CLAUDE.md` rule 2), so a
  // require from here must not be the one that loads it.
  loadOffers(): Json;
  loadConfigs(): Json;
  loadIssuer(): Json;
  loadIssued(): Json;
}

// The two kinds of pre-authorized offer. A SAME-DEVICE offer is not one: it
// carries an issuer_state and no authorization, and the wallet takes the
// person through the authorization endpoint, so it is nothing a person
// needs this page for.
const MODES = ['cross-device', 'deferred'];

// THE HISTORY IS PAGED (#662, 2026-10-16), as `/portal/sign-ins` and
// `/portal/claim-sources` are: `page` moves it, `paging` says where it is,
// and `web_portal_kit.ts`'s `pageNav()` draws the control.
const PER_PAGE = 20;

const PAGE_FIELD = vt.opt(vt.integer(1, 100000))
  .describe('Which page of `issued`, newest first. Clamped to the last.');

const PAGE_QUERY = vz.object({ page: PAGE_FIELD });

const REMOVE_FORM = vz.object({
  id: vz.string().min(1).max(64)
    .describe('An issuance\'s `id`, from `issued` in ' +
              '`GET /account-api/credentials/offerable`, which removes ' +
              'every copy of it; or one copy\'s, from its `copies`, which ' +
              'removes that copy alone.'),
  page: PAGE_FIELD
});

// The states a credential in the history can be in (`vc_issued.ts`).
const STATES = ['valid', 'suspended', 'revoked', 'removed', 'signed-out',
                'expired'];

// The states a copy may still be removed in.
const REMOVABLE = ['valid', 'suspended'];

// What each algorithm is, and which document defines it for JOSE (or, for
// bbs-2023, for Data Integrity) — drafts named as drafts. The first is drawn
// beside the algorithm's name and is kept to a few words (rcbj, 2026-10-17:
// the option text ran past the pane), since the name already carries the
// hash or the parameter set; the second is the option's tooltip and is in
// the API's answer, so a person choosing ML-DSA-44 can still learn it is
// not yet an RFC.
const ALG_NOTES: Json = {
  RS256: ['RSA PKCS#1 v1.5', 'RFC 7518'],
  RS384: ['RSA PKCS#1 v1.5', 'RFC 7518'],
  RS512: ['RSA PKCS#1 v1.5', 'RFC 7518'],
  PS256: ['RSA-PSS', 'RFC 7518'],
  PS384: ['RSA-PSS', 'RFC 7518'],
  PS512: ['RSA-PSS', 'RFC 7518'],
  ES256: ['ECDSA P-256', 'RFC 7518'],
  ES384: ['ECDSA P-384', 'RFC 7518'],
  ES512: ['ECDSA P-521', 'RFC 7518'],
  ES256K: ['ECDSA secp256k1', 'RFC 8812'],
  EdDSA: ['EdDSA', 'RFC 8037'],
  'ML-DSA-44': ['post-quantum',
                'draft-ietf-cose-dilithium'],
  'ML-DSA-65': ['post-quantum',
                'draft-ietf-cose-dilithium'],
  'ML-DSA-87': ['post-quantum',
                'draft-ietf-cose-dilithium'],
  'SLH-DSA-SHA2-128s': ['post-quantum',
                        'draft-ietf-cose-sphincs-plus'],
  'SLH-DSA-SHAKE-128s': ['post-quantum',
                         'draft-ietf-cose-sphincs-plus'],
  'ML-DSA-44-ES256': ['composite post-quantum',
                      'draft-ietf-jose-pq-composite-sigs'],
  'ML-DSA-65-ES256': ['composite post-quantum',
                      'draft-ietf-jose-pq-composite-sigs'],
  'ML-DSA-87-ES384': ['composite post-quantum',
                      'draft-ietf-jose-pq-composite-sigs'],
  'ML-DSA-44-Ed25519': ['composite post-quantum',
                        'draft-ietf-jose-pq-composite-sigs'],
  'ML-DSA-65-Ed25519': ['composite post-quantum',
                        'draft-ietf-jose-pq-composite-sigs'],
  'ML-DSA-87-Ed448': ['composite post-quantum',
                      'draft-ietf-jose-pq-composite-sigs'],
  'bbs-2023': ['BBS, selective disclosure',
               'W3C Data Integrity BBS Cryptosuites v1.0']
};

const OFFER_FORM = vz.object({
  configuration: vz.string().min(1).max(validation.CAP.SCOPE)
    .describe('The `credential_configuration_id` to offer, one of ' +
              '`GET /account-api/credentials/offerable`\'s.'),
  mode: vt.oneOf(MODES)
    .describe('`cross-device` (Appendix H.2: issued as soon as the wallet ' +
              'asks) or `deferred` (H.3: the credential endpoint answers ' +
              'a `transaction_id` first).'),
  signingAlg: vz.string().max(64).optional()
    .describe('The algorithm the credential is signed with, one of the ' +
              'configuration\'s `signingAlgs`; left out or empty, the ' +
              'configured `oid4vci.credentialSigningAlgorithm`.'),
  page: PAGE_FIELD
});

// The answer's shape, documented.



/**
 * `/portal/wallet`'s account API operations: a pre-authorized Credential
 * Offer for the signed-in person's own wallet (#589).
 */
class PortalWallet {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalWalletDeps) {
    deps.log.debug("Entering PortalWallet.constructor().");
    deps.log.debug("Leaving PortalWallet.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalWalletDeps {
    helpers.log.debug("Entering PortalWallet.defaultDeps().");
    helpers.log.debug("Leaving PortalWallet.defaultDeps().");
    return {
      log: helpers.log,
      userFor: helpers.userFor,
      hasSubjectResolver: helpers.hasSubjectResolver,
      nameForSubject: helpers.nameForSubject,
      subjectForName: helpers.subjectForName,
      loadOffers: function (): Json {
        helpers.log.debug("Entering loadOffers().");
        helpers.log.debug("Leaving loadOffers().");
        return require('../oid4vc/vc_offers');
      },
      loadConfigs: function (): Json {
        helpers.log.debug("Entering loadConfigs().");
        helpers.log.debug("Leaving loadConfigs().");
        return require('../oid4vc/vc_configs');
      },
      loadIssuer: function (): Json {
        helpers.log.debug("Entering loadIssuer().");
        helpers.log.debug("Leaving loadIssuer().");
        return require('../oid4vc/vc_issuer');
      },
      loadIssued: function (): Json {
        helpers.log.debug("Entering loadIssued().");
        helpers.log.debug("Leaving loadIssued().");
        return require('../oid4vc/vc_issued');
      }
    };
  }

  /**
   * Says why the token's subject and its person do not name each other, or
   * '' where they do (the header; STS-PORTAL-0617).
   *
   * @param caller - the signed-in person
   * @returns the reason, or ''
   */
  subjectDisagreement(caller: AccountCaller): string {
    const { log, hasSubjectResolver, nameForSubject,
            subjectForName } = this.deps;
    log.debug("Entering PortalWallet.subjectDisagreement().");
    if (!hasSubjectResolver()) {
      log.debug("Leaving PortalWallet.subjectDisagreement(). No directory.");
      return '';
    }
    const sub = String((caller && caller.sub) || '');
    const who = String((caller && caller.username) || '');
    if (!sub) {
      log.debug("Leaving PortalWallet.subjectDisagreement(). No subject.");
      return 'Your sign-in names no subject, and the credentials this ' +
        'realm issued are filed by subject. Sign out and sign in again.';
    }
    const named = String(nameForSubject(sub) || '');
    const own = String(subjectForName(who) || '');
    if ((named && named === who) ||
        (own && own.toLowerCase() === sub.toLowerCase())) {
      log.debug("Leaving PortalWallet.subjectDisagreement(). Agree.");
      return '';
    }
    log.debug("Leaving PortalWallet.subjectDisagreement(). Disagree.");
    return 'Your sign-in names ' + JSON.stringify(who) + ' and the subject ' +
      JSON.stringify(sub) + ', which ' + (named
        ? 'is ' + JSON.stringify(named) + '\'s'
        : 'is no entry\'s in this realm\'s directory') +
      ', so the credentials it would show are not yours. Sign out and ' +
      'sign in again.';
  }

  /**
   * Refuses an operation whose token's subject and person disagree, with an
   * audit row, or answers null where they agree.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param caller - the signed-in person
   * @param action - the audit action of the operation refused
   * @returns the refusal sent, or null
   */
  refuseDisagreement(ctx: AccountContext, res: Json, caller: AccountCaller,
                     action: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalWallet.refuseDisagreement(). " + action);
    const why = this.subjectDisagreement(caller);
    if (!why) {
      log.debug("Leaving PortalWallet.refuseDisagreement(). Agree.");
      return null;
    }
    const who = caller.username;
    ctx.audit.record({
      category: 'protocol', action: action, errorCode: 'STS-PORTAL-0617',
      actor: who, target: who, outcome: 'failure',
      summary: 'was refused on /portal/wallet: the token\'s subject and ' +
               'person do not name each other',
      detail: { sub: caller.sub || undefined, errors: [why] }
    });
    log.debug("Leaving PortalWallet.refuseDisagreement(). Refused.");
    return ctx.refuse(res, 403, 'STS-PORTAL-0617', why);
  }

  /**
   * The page's view: every credential configuration this realm's issuer
   * offers, with the name its metadata gives it, the two kinds of offer,
   * how long an offer lives, and the credentials the caller was issued.
   *
   * @param req - the request (the realm's metadata is built from it)
   * @param caller - the signed-in person
   * @param wanted - the page of `issued` asked for; the first when left out
   * @returns `{ configurations, modes, lifetimeSeconds, wallet, batchSize,
   *   issued, paging }`
   */
  view(req: Json, caller: AccountCaller, wanted?: number): Json {
    const { log, loadOffers, loadConfigs, loadIssuer, loadIssued } = this.deps;
    log.debug("Entering PortalWallet.view().");
    const configs = loadConfigs();
    // THE NAMES ARE THE METADATA'S, read off `vciMetadata()` rather than
    // written here again: what a wallet will call the credential is what
    // the person chooses it by.
    let supported: Json = {};
    try {
      supported = loadIssuer().vciMetadata(req)
        .credential_configurations_supported || {};
    } catch (e) {
      // The names are a courtesy; the ids are the choice. Drawn without.
      log.debug("Caught in PortalWallet.view(): " + ((e && e.message) || e));
      supported = {};
    }
    const rows = configs.vciConfigIds().map(function (id: string): Json {
      // OpenID4VCI 1.0 section 12.2.4 puts `display` in a configuration's
      // `credential_metadata`; read there, and at the top for an older
      // shape.
      const meta = supported[id] || {};
      const shown = (meta.credential_metadata &&
                     meta.credential_metadata.display) || meta.display;
      const display = Array.isArray(shown) && shown[0] ? shown[0] : {};
      const algs: string[] = configs.vciSigningAlgsFor(id);
      return { id: id, format: configs.vciFormatOf(id),
               name: String(display.name || id),
               issuerDid: !!configs.vciUsesIssuerDid(id),
               signingAlgs: algs.map(function (alg: string): Json {
                 const note = ALG_NOTES[alg] || ['', ''];
                 return { alg: alg, what: note[0], spec: note[1] };
               }),
               defaultSigningAlg: algs[0] || '' };
    });
    const offers = loadOffers();
    const names: Json = {};
    rows.forEach(function (one: Json) {
      names[one.id] = one.name;
    });
    const at = function (ms: number): string {
      return ms ? new Date(ms).toISOString() : '';
    };
    // THE SUBJECT IS THE TOKEN'S (`account-api/CLAUDE.md`).
    // ONE ENTRY PER ISSUANCE, its copies under it (#670): a page counts
    // issuances.
    const all: Json[] = caller && caller.sub
      ? loadIssued().issuancesForSubject(caller.sub) : [];
    // Paged on the history, decorated on the page, as `/portal/claim-sources`
    // is: only the rows shown are turned into the answer's shape.
    const pages = Math.max(1, Math.ceil(all.length / PER_PAGE));
    const page = Math.min(Math.max(1, Number(wanted) || 1), pages);
    const issued = all.slice((page - 1) * PER_PAGE, page * PER_PAGE)
      .map(function (one: Json): Json {
        const copies: Json[] = one.copies || [];
        return { id: one.id, configurationId: one.configId,
                 name: String(names[one.configId] || one.configId ||
                              one.format),
                 format: one.format, issuedAt: at(one.issuedAt),
                 expiresAt: at(one.expiresAt), status: one.status,
                 counts: one.counts,
                 removable: copies.some(function (c: Json): boolean {
                   return REMOVABLE.indexOf(c.status) >= 0;
                 }),
                 removedAt: at(one.removedAt),
                 walletEvent: one.walletEvent,
                 walletEventAt: at(one.walletEventAt),
                 copies: copies.map(function (c: Json, i: number): Json {
                   return { id: c.id, position: i + 1, of: copies.length,
                            issuedAt: at(c.issuedAt),
                            expiresAt: at(c.expiresAt), status: c.status,
                            removable: REMOVABLE.indexOf(c.status) >= 0,
                            removedAt: at(c.removedAt),
                            walletEvent: c.walletEvent,
                            walletEventAt: at(c.walletEventAt),
                            keyThumbprint: c.keyThumbprint,
                            holderDid: c.holderDid,
                            statusIndex: c.statusIndex };
                 }) };
      });
    log.debug("Leaving PortalWallet.view(). " + rows.length + ", page " +
              page + " of " + pages + " of " + all.length + " issued.");
    return { configurations: rows, modes: MODES.slice(0),
             lifetimeSeconds: Math.round(offers.offerTtlMs() / 1000),
             wallet: offers.configuredWalletUrl(),
             batchSize: Math.max(1, Number(configs.vciBatchSize()) || 1),
             issued: issued,
             paging: { page: page, pages: pages, per: PER_PAGE,
                       total: all.length } };
  }

  /**
   * Removes one of the caller's credentials — every copy of an issuance, or
   * one copy (`vc_issued.ts`'s `removeForSubject()`): revoked here, and the
   * wallet's copies left for them to delete.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  remove(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
         body: Json): unknown {
    const { log, loadIssued } = this.deps;
    log.debug("Entering PortalWallet.remove().");
    const refused = this.refuseDisagreement(ctx, res, caller,
                                            'portal.vc.remove');
    if (refused) {
      log.debug("Leaving PortalWallet.remove(). Subject disagrees.");
      return refused;
    }
    const who = caller.username;
    const id = String(body.id);
    const result = caller.sub
      ? loadIssued().removeForSubject(caller.sub, id,
                                      who + ' on /portal/wallet')
      : { ok: false, error: 'Your sign-in names no subject this service ' +
                            'issues credentials to.' };
    ctx.audit.record({
      category: 'protocol', action: 'portal.vc.remove',
      errorCode: result.ok ? undefined : 'STS-PORTAL-0591',
      actor: who, target: who, outcome: result.ok ? 'success' : 'failure',
      summary: (result.ok ? (result.already ? 'asked again to remove'
                                            : 'removed')
                          : 'could not remove') +
               (result.ok && result.scope === 'issuance' &&
                result.copies > 1 ? ' every copy of' : '') +
               ' a credential this realm issued them, on /portal/wallet',
      detail: { id: id, scope: result.scope || undefined,
                removed: result.ok ? result.removed : undefined,
                copies: result.ok ? result.copies : undefined,
                errors: result.ok ? undefined : [result.error] }
    });
    if (!result.ok) {
      log.debug("Leaving PortalWallet.remove(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0591', String(result.error),
                        { view: this.view(req, caller, body.page) });
    }
    // WHAT WAS REMOVED, in the person's words: one copy of several, every
    // copy of several, or the one credential an issuance was.
    const copies = Number(result.copies) || 0;
    const said = result.scope === 'copy'
      ? 'portalWallet.doneRemovedCopy'
      : (copies > 1 ? 'portalWallet.doneRemovedAll'
                    : 'portalWallet.doneRemoved');
    log.debug("Leaving PortalWallet.remove(). Removed.");
    return ctx.json(res, 200, { ok: true,
      message: ctx.translatorFor(who).text(said),
      scope: result.scope, removed: Number(result.removed) || 0,
      view: this.view(req, caller, body.page) });
  }

  /**
   * Makes a pre-authorized Credential Offer for the caller, on the sign-on
   * session their token was issued on.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  offer(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
        body: Json): unknown {
    const { log, userFor, loadOffers, loadConfigs } = this.deps;
    log.debug("Entering PortalWallet.offer().");
    const refused = this.refuseDisagreement(ctx, res, caller,
                                            'portal.vc.offer');
    if (refused) {
      log.debug("Leaving PortalWallet.offer(). Subject disagrees.");
      return refused;
    }
    const who = caller.username;
    const configurationId = String(body.configuration);
    const record = function (outcome: string, code?: string,
                             why?: string): void {
      log.debug("Entering record(). " + outcome);
      ctx.audit.record({
        category: 'protocol', action: 'portal.vc.offer',
        errorCode: code, actor: who, target: who, outcome: outcome,
        summary: (outcome === 'success' ? 'made' : 'was refused') +
                 ' a ' + body.mode + ' Credential Offer of ' +
                 configurationId + ' for their own wallet on /portal/wallet',
        detail: { configuration: configurationId, mode: body.mode,
                  signingAlg: body.signingAlg || undefined,
                  sessionId: caller.sessionId || undefined,
                  errors: why ? [why] : undefined }
      });
      log.debug("Leaving record().");
    };
    // THE ALGORITHM, where one was chosen: the configuration's own list.
    const chosenAlg = String(body.signingAlg || '');
    const allowedAlgs: string[] =
      loadConfigs().vciSigningAlgsFor(configurationId);
    if (chosenAlg && allowedAlgs.length &&
        allowedAlgs.indexOf(chosenAlg) < 0) {
      const why = configurationId + ' credentials are not signed with "' +
        chosenAlg + '". Choose one of: ' + allowedAlgs.join(', ') + '.';
      record('failure', 'STS-PORTAL-0592', why);
      log.debug("Leaving PortalWallet.offer(). Unknown algorithm.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0592', why,
                        { view: this.view(req, caller, body.page) });
    }
    if (loadConfigs().vciConfigIds().indexOf(configurationId) < 0) {
      const why = 'This issuer offers no credential configuration "' +
        configurationId + '". GET /account-api/credentials/offerable lists ' +
        'the ones it does.';
      record('failure', 'STS-PORTAL-0589', why);
      log.debug("Leaving PortalWallet.offer(). Unknown configuration.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0589', why,
                        { view: this.view(req, caller, body.page) });
    }
    // THE SESSION THE OFFER IS MADE ON. `caller.signOn` is the sign-on
    // session the token was issued on (`account-api/CLAUDE.md`, the gate's
    // step 4); null where the token registry no longer says which.
    const session = caller.signOn;
    if (!session || !session.user || session.authenticated === false) {
      const why = 'A pre-authorized Credential Offer is made on the ' +
        'strength of the sign-in you are using, and this service no longer ' +
        'knows which sign-in that is' + (session ? ' — it continued ' +
        'without signing in' : '') + '. Sign in again and ask once more.';
      record('failure', 'STS-PORTAL-0590', why);
      log.debug("Leaving PortalWallet.offer(). No sign-on session.");
      return ctx.refuse(res, 403, 'STS-PORTAL-0590', why,
                        { view: this.view(req, caller, body.page) });
    }
    const offers = loadOffers();
    const user = Object.assign({}, userFor(who),
                               caller.sub ? { sub: caller.sub } : {});
    const made = offers.makeOffer(req, {
      configurationIds: [configurationId], mode: body.mode, user: user,
      session: session, byReference: true,
      wallet: offers.configuredWalletUrl(),
      // The configured one is the default, and is not recorded as a
      // choice: a change of that setting before the wallet redeems the
      // offer then applies to it.
      signingAlg: chosenAlg && chosenAlg !== allowedAlgs[0] ? chosenAlg
                                                            : '' });
    const offer = {
      configurationId: configurationId,
      signingAlg: chosenAlg || allowedAlgs[0] || '',
      mode: made.built.mode,
      credentialOffer: made.built.offer,
      txCode: made.built.txCode,
      expiresAt: new Date(made.built.expires).toISOString(),
      byValue: { offerUri: made.byValue.offerUri,
                 walletUrl: made.byValue.walletUrl || '' },
      byReference: made.byReference
        ? { credentialOfferUri: made.byReference.credentialOfferUri,
            offerUri: made.byReference.offerUri,
            walletUrl: made.byReference.walletUrl || '' }
        : null
    };
    record('success');
    const view = Object.assign(this.view(req, caller, body.page),
                               { offer: offer });
    log.debug("Leaving PortalWallet.offer(). Offered.");
    return ctx.json(res, 200, { ok: true,
      message: ctx.translatorFor(who).text('portalWallet.doneOffered'),
      offer: offer, view: view });
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
    log.debug("Entering PortalWallet.accountOperations().");
    const example = 'openid-credential-offer://?credential_offer_uri=' +
      encodeURIComponent('https://sts.example/oid4vci/credential-offer/' +
                         '3q2-7w...');
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/credentials/offerable',
        operationId: 'getOfferableCredentials', access: 'person', query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          const refused = self.refuseDisagreement(ctx, res, caller,
                                                  'portal.vc.view');
          if (refused) {
            return refused;
          }
          return ctx.json(res, 200, self.view(req, caller,
                                              input.query.page || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/credentials/offers',
        operationId: 'createCredentialOffer', access: 'person', body: OFFER_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.offer(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/credentials/remove',
        operationId: 'removeIssuedCredential', access: 'person',
        body: REMOVE_FORM,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.remove(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving PortalWallet.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalWallet>(
  'portal/portal_wallet',
  () => new PortalWallet(PortalWallet.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/wallet`'s account API operations (#589).
 * @namespace
 */
export = {
  PortalWallet: PortalWallet,
  installInstance: (instance: PortalWallet): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
