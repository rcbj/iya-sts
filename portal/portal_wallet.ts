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
//   POST /account-api/credentials/remove      one of their credentials removed
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
    .describe('The credential\'s `id`, from `issued` in ' +
              '`GET /account-api/credentials/offerable`.'),
  page: PAGE_FIELD
});

// The states a credential in the history can be in (`vc_issued.ts`).
const STATES = ['valid', 'suspended', 'revoked', 'removed', 'signed-out',
                'expired'];

const OFFER_FORM = vz.object({
  configuration: vz.string().min(1).max(validation.CAP.SCOPE)
    .describe('The `credential_configuration_id` to offer, one of ' +
              '`GET /account-api/credentials/offerable`\'s.'),
  mode: vt.oneOf(MODES)
    .describe('`cross-device` (Appendix H.2: issued as soon as the wallet ' +
              'asks) or `deferred` (H.3: the credential endpoint answers ' +
              'a `transaction_id` first).'),
  page: PAGE_FIELD
});

// The answer's shape, documented.
const OFFERABLE_ANSWER = {
  type: 'object',
  properties: {
    configurations: { type: 'array', items: { type: 'object', properties: {
      id: { type: 'string' }, format: { type: 'string' },
      name: { type: 'string' }, issuerDid: { type: 'boolean' } } } },
    modes: { type: 'array', items: { type: 'string', enum: MODES } },
    lifetimeSeconds: { type: 'integer' },
    wallet: { type: 'string' },
    issued: { type: 'array', items: { type: 'object', properties: {
      id: { type: 'string' }, configurationId: { type: 'string' },
      name: { type: 'string' }, format: { type: 'string' },
      issuedAt: { type: 'string', format: 'date-time' },
      expiresAt: { type: 'string', format: 'date-time' },
      status: { type: 'string', enum: STATES },
      removable: { type: 'boolean' },
      removedAt: { type: 'string', format: 'date-time' },
      walletEvent: { type: 'string', enum: ['', 'credential_accepted',
        'credential_failure', 'credential_deleted'] },
      walletEventAt: { type: 'string', format: 'date-time' } } } },
    paging: { type: 'object', properties: {
      page: { type: 'integer' }, pages: { type: 'integer' },
      per: { type: 'integer' }, total: { type: 'integer' } } },
    offer: { type: 'object', description: 'Present in a POST\'s `view`.' }
  }
};

const OFFER_ANSWER = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    message: { type: 'string' },
    offer: { type: 'object', properties: {
      configurationId: { type: 'string' },
      mode: { type: 'string', enum: MODES },
      credentialOffer: { type: 'object',
        description: 'The Credential Offer (OpenID4VCI section 4.1.1).' },
      txCode: { type: 'string',
        description: 'The Transaction Code, for the person to type into ' +
                     'the wallet; it is not in the offer.' },
      expiresAt: { type: 'string', format: 'date-time' },
      byValue: { type: 'object', properties: {
        offerUri: { type: 'string' }, walletUrl: { type: 'string' } } },
      byReference: { type: 'object', properties: {
        credentialOfferUri: { type: 'string' },
        offerUri: { type: 'string' }, walletUrl: { type: 'string' } } } } },
    view: { type: 'object',
            description: 'The page\'s view with `offer` in it, drawn in ' +
                         'place: the Transaction Code never reaches a URL.' }
  }
};

const REMOVE_ANSWER = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    message: { type: 'string' },
    view: { type: 'object',
            description: 'The page\'s view, `issued` showing the credential ' +
                         'removed.' }
  }
};

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
   * The page's view: every credential configuration this realm's issuer
   * offers, with the name its metadata gives it, the two kinds of offer,
   * how long an offer lives, and the credentials the caller was issued.
   *
   * @param req - the request (the realm's metadata is built from it)
   * @param caller - the signed-in person
   * @param wanted - the page of `issued` asked for; the first when left out
   * @returns `{ configurations, modes, lifetimeSeconds, wallet, issued,
   *   paging }`
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
      return { id: id, format: configs.vciFormatOf(id),
               name: String(display.name || id),
               issuerDid: !!configs.vciUsesIssuerDid(id) };
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
    const all: Json[] = caller && caller.sub
      ? loadIssued().historyForSubject(caller.sub) : [];
    // Paged on the history, decorated on the page, as `/portal/claim-sources`
    // is: only the rows shown are turned into the answer's shape.
    const pages = Math.max(1, Math.ceil(all.length / PER_PAGE));
    const page = Math.min(Math.max(1, Number(wanted) || 1), pages);
    const issued = all.slice((page - 1) * PER_PAGE, page * PER_PAGE)
      .map(function (one: Json): Json {
        return { id: one.id, configurationId: one.configId,
                 name: String(names[one.configId] || one.configId ||
                              one.format),
                 format: one.format, issuedAt: at(one.issuedAt),
                 expiresAt: at(one.expiresAt), status: one.status,
                 removable: one.status === 'valid' ||
                            one.status === 'suspended',
                 removedAt: at(one.removedAt),
                 walletEvent: one.walletEvent,
                 walletEventAt: at(one.walletEventAt) };
      });
    log.debug("Leaving PortalWallet.view(). " + rows.length + ", page " +
              page + " of " + pages + " of " + all.length + " issued.");
    return { configurations: rows, modes: MODES.slice(0),
             lifetimeSeconds: Math.round(offers.offerTtlMs() / 1000),
             wallet: offers.configuredWalletUrl(), issued: issued,
             paging: { page: page, pages: pages, per: PER_PAGE,
                       total: all.length } };
  }

  /**
   * Removes one of the caller's credentials (`vc_issued.ts`'s
   * `removeForSubject()`): revoked here, and the wallet's copy left for them
   * to delete.
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
               ' a credential this realm issued them, on /portal/wallet',
      detail: { id: id, errors: result.ok ? undefined : [result.error] }
    });
    if (!result.ok) {
      log.debug("Leaving PortalWallet.remove(). Refused.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0591', String(result.error),
                        { view: this.view(req, caller, body.page) });
    }
    log.debug("Leaving PortalWallet.remove(). Removed.");
    return ctx.json(res, 200, { ok: true,
      message: ctx.translatorFor(who).text('portalWallet.doneRemoved'),
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
                  sessionId: caller.sessionId || undefined,
                  errors: why ? [why] : undefined }
      });
      log.debug("Leaving record().");
    };
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
      wallet: offers.configuredWalletUrl() });
    const offer = {
      configurationId: configurationId,
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
        operationId: 'getOfferableCredentials', tag: 'Wallet',
        access: 'person', mirrors: 'GET ' + ctx.PORTAL + '/wallet',
        summary: 'The credentials you can put into your own wallet',
        description: '`configurations`: each credential configuration this ' +
          'realm\'s OpenID4VCI issuer offers — its ' +
          '`credential_configuration_id` (`id`), its format, the name its ' +
          'metadata gives it, and whether it names the issuer by DID. ' +
          '`modes`: the two pre-authorized offers, `cross-device` ' +
          '(Appendix H.2) and `deferred` (H.3). `lifetimeSeconds`: how long ' +
          'an offer and its code are honoured (`oid4vci.offerTtlS`). ' +
          '`wallet`: the configured web wallet a link opens, or empty. ' +
          '`issued`: the credentials this realm still records as issued to ' +
          'you, newest first — each one\'s `id`, configuration, when it was ' +
          'issued and expires, its `status` (`valid`, `suspended`, ' +
          '`revoked`, `removed` by you, `signed-out` by a global sign-out, ' +
          '`expired`), whether you can remove it, and the last event your ' +
          'wallet reported to the Notification Endpoint (OpenID4VCI 1.0 ' +
          'section 11). `issued` is one page (`paging`, moved by `page`, ' +
          '20 to a page); `paging.total` counts them all.',
        answer: OFFERABLE_ANSWER,
        query: PAGE_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200, self.view(req, caller,
                                              input.query.page || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/credentials/offers',
        operationId: 'createCredentialOffer', tag: 'Wallet',
        access: 'person', mirrors: 'POST ' + ctx.PORTAL + '/wallet',
        summary: 'Makes a Credential Offer for your own wallet',
        description: 'A pre-authorized Credential Offer (OpenID4VCI section ' +
          '4.1, Appendix H.2 or H.3) of one configuration, about YOU — the ' +
          'token\'s person; nobody else can be named. Answered once, in ' +
          'place: `offer.credentialOffer`, the offer by value ' +
          '(`offer.byValue.offerUri`, an `openid-credential-offer://` URI, ' +
          'and `walletUrl`, the configured web wallet\'s link) and by ' +
          'reference (`offer.byReference`, whose `offerUri` is short ' +
          'enough for a QR code, e.g. `' + example + '`), when the offer ' +
          'and its code stop being honoured (`expiresAt`), and the ' +
          'Transaction Code (`txCode`, e.g. `40317`) the wallet will ask ' +
          'for — shown to you, never carried in the offer. The offer is ' +
          'made on the sign-on session your token was issued on, which is ' +
          'reported over CAEP as session-presented (OpenID4VCI). The same ' +
          '`offer` is in `view`, for the page.',
        body: OFFER_FORM,
        answer: OFFER_ANSWER,
        statuses: {
          400: 'The configuration is not one this issuer offers ' +
               '(STS-PORTAL-0589).',
          403: 'The sign-on session the token was issued on is no longer ' +
               'known, or continued without signing in (STS-PORTAL-0590).'
        },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.offer(ctx, req, res, caller, input.body);
        } },
      { method: 'POST', path: ctx.BASE + '/credentials/remove',
        operationId: 'removeIssuedCredential', tag: 'Wallet',
        access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/remove-wallet-credential',
        summary: 'Removes one of the credentials issued to you',
        description: 'The credential named by its `id` (from `issued`) is ' +
          'revoked: its Token Status List entry is set INVALID, which is ' +
          'final and what a verifier reads, it is marked revoked in the ' +
          'issued register, it no longer signs you in, and your relying ' +
          'parties are told over CAEP (credential-change, revoke). It is NOT ' +
          'deleted from your wallet: neither OpenID4VP nor OpenID4VCI lets ' +
          'an issuer do that, so delete it in the wallet yourself. Only a ' +
          'credential of yours can be named; removing one already removed ' +
          'is answered as done. The page\'s `view` is in the answer.',
        body: REMOVE_FORM,
        answer: REMOVE_ANSWER,
        statuses: {
          400: 'No credential of yours has that id (STS-PORTAL-0591).'
        },
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
