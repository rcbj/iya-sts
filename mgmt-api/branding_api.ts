// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: branding_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/branding OPERATIONS (#717), mirroring Server configuration
// → Sign-in appearance (rule 7). Every one calls `common/branding.ts` in the
// AMBIENT realm, so `/realm/acme/admin-api/branding` is acme's appearance
// and a realm administrator changes their own realm's and no other:
//
//   GET  /admin-api/branding              `Branding.describe()`, with the
//                                         realm's own addresses and the
//                                         page's settings block
//   POST /admin-api/branding/save         `Branding.saveSettings()`
//   POST /admin-api/branding/logo         `Branding.setLogo()`: the BYTES
//   POST /admin-api/branding/remove-logo  `Branding.removeLogo()`
//
// POST, NOT PUT AND DELETE. The ticket's design named `PUT` and `DELETE` on
// `/admin-api/branding/logo`. This API's route table registers GET and POST
// only, its document, its gate and both of its walking jobs read those two
// verbs, and the static console sends every form as a POST to the operation
// whose last path segment is the form's `action` (`web_forms.ts`). Every
// other act here is `POST /<resource>/<action>` and every other upload is a
// POST whose body is the file (`/admin-api/risk/upload`), so the logo is
// both. A third verb for one resource would have been the only one.
//
// THE LOGO'S BODY IS THE IMAGE, never JSON and never multipart. The body
// parsers in `common/app.js` have already read it, bounded at 5 MB:
// `application/octet-stream` arrives as a Buffer from the raw parser, and an
// `image/*` type as the text parser's string with the bytes kept beside it
// in `req.rawBody`, which is what is read here — the decoded string is not
// the image. `branding.logoMaxBytes` (2 MiB at most) is then
// `Branding.setLogo()`'s check. The declared type decides nothing: the
// bytes do (D1).
//
// A SAVE IS A SETTINGS WRITE and is recorded as `/config/set` records one:
// no audit row of its own. The logo's upload and removal are audited by
// `Branding.setLogo()` and `removeLogo()`, with the caller this gate let in.
//
// It registers no route. `mgmt-api/admin_api.ts` spreads `ROUTES`.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface BrandingApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // `common/branding.ts`, lazily, asked only inside a handler.
  loadBranding(): Json;
  // The realm registry, for the ambient realm's path prefix.
  loadRealms(): Json;
  // The console, lazily, for this page's settings block. Requiring it here
  // at load would be a cycle through the management API.
  loadAdmin(): Json;
}

const BASE = '/admin-api';
const PAGE = '/admin/sign-in-appearance';

// EVERY ACTION `/branding` HAS, which is what the unknown-action refusal
// names. `logo` is answered by a route of its own above `/branding/:action`
// (its body is the image), but it is still one of this resource's actions:
// `tests/protocol/admin_api.js` reads this sentence for the console/API
// parity, and `sts_admin_api_operations.js` compares it with the document —
// risk's `upload` is the precedent (`admin-ui/risk_admin.ts`).
const ACTIONS = ['save', 'remove-logo'];
const NAMED_ACTIONS = ['save', 'logo', 'remove-logo'];

// The settings a save takes: every `branding.*` row a realm may carry, in
// the order `saveSchema()` declares them (`tests/branding_api.js` holds the
// two equal). `branding.logoMaxBytes` is the process's (`perProcess`), and
// `Branding.saveSettings()` refuses it; it is set on the settings tab, by
// `/config/set-many`, in the default realm.
const SAVED_KEYS = ['branding.layout', 'branding.accentColor',
                    'branding.pageColor', 'branding.cardColor',
                    'branding.textColor', 'branding.displayName',
                    'branding.logoAlt', 'branding.logoLinkUrl'];

/**
 * The `/admin-api/branding` operations: a realm's sign-in appearance.
 */
class BrandingApi {
  /**
   * @param deps - the logger, the body parser, and the three loaders
   */
  constructor(private readonly deps: BrandingApiDeps) {
    deps.log.debug("Entering BrandingApi.constructor().");
    deps.log.debug("Leaving BrandingApi.constructor().");
  }

  /**
   * The dependencies the composition root builds this with.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): BrandingApiDeps {
    helpers.log.debug("Entering BrandingApi.defaultDeps().");
    helpers.log.debug("Leaving BrandingApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadBranding: function (): Json {
        return require('../common/branding');
      },
      loadRealms: function (): Json {
        return require('../common/realms');
      },
      loadAdmin: function (): Json {
        return require('../admin-ui/admin');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: BrandingApi): void {
    helpers.log.debug("Entering BrandingApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving BrandingApi.wire().");
  }

  /**
   * Sends JSON with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body
   */
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering BrandingApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving BrandingApi.sendJson().");
  }

  /**
   * Who this request was let in as, for an audit row: the name the gate
   * wrote on the response, or '' where nobody was named (development's
   * open API).
   *
   * @param res - the response
   * @returns the caller's name
   */
  static callerOf(res: Res): string {
    helpers.log.debug("Entering BrandingApi.callerOf().");
    const caller = res && res.locals && res.locals.apiCaller;
    helpers.log.debug("Leaving BrandingApi.callerOf().");
    return caller ? String(caller.name || '') : '';
  }

  /**
   * The image a logo upload carried: the raw parser's Buffer, or the bytes
   * the text parser kept beside its string. Anything else is no image.
   *
   * @param req - the request
   * @returns the bytes, empty where none were sent
   */
  static uploadedBytes(req: Req): Buffer {
    helpers.log.debug("Entering BrandingApi.uploadedBytes().");
    if (req && Buffer.isBuffer(req.body)) {
      helpers.log.debug("Leaving BrandingApi.uploadedBytes(). Raw.");
      return req.body;
    }
    if (req && Buffer.isBuffer(req.rawBody)) {
      helpers.log.debug("Leaving BrandingApi.uploadedBytes(). Kept bytes.");
      return req.rawBody;
    }
    helpers.log.debug("Leaving BrandingApi.uploadedBytes(). None.");
    return Buffer.alloc(0);
  }

  /**
   * The view `GET /admin-api/branding` answers: `Branding.describe()`, its
   * two addresses put in the ambient realm (the page links them, and an
   * address without the realm's prefix is the default realm's), and the
   * page's settings block.
   *
   * @returns the view
   */
  view(): Json {
    const { log, loadBranding, loadRealms, loadAdmin } = this.deps;
    log.debug("Entering BrandingApi.view().");
    const out = loadBranding().describe();
    const prefix = String(loadRealms().currentPrefix() || '');
    out.realm = loadRealms().currentId() || 'default';
    out.previewUrl = prefix + String(out.preview || '');
    if (out.logo) {
      out.logo.src = prefix + String(out.logo.url || '');
    }
    out.settings = loadAdmin().configSettingsJson(PAGE);
    log.debug("Leaving BrandingApi.view().");
    return out;
  }

  /**
   * Carries out `save` or `remove-logo`.
   *
   * @param body - the request body, `action` and `actor` among it
   * @returns `{ ok, errors, … }`, a refusal marked with its code
   */
  act(body: Json): Json {
    const { log, loadBranding, errorCodes: codes } = this.deps;
    log.debug("Entering BrandingApi.act().");
    const b = Object.assign({}, body || {});
    const action = String(b.action || '');
    const actor = String(b.actor || '');
    delete b.action;
    delete b.actor;
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving BrandingApi.act(). Unknown action.");
      return codes.mark({ ok: false, errors: ['Unknown action "' + action +
        '". The ' + helpers.numberWord(NAMED_ACTIONS.length) + ' are: ' +
        NAMED_ACTIONS.join(', ') + '.'] }, 'STS-API-0038');
    }
    if (action === 'remove-logo') {
      const removed = loadBranding().removeLogo(actor);
      log.debug("Leaving BrandingApi.act(). Removed " + removed.removed);
      return Object.assign({}, removed, {
        message: removed.removed ? 'The logo was removed.'
                                 : 'This realm has no logo to remove.' });
    }
    const saved = loadBranding().saveSettings(b);
    if (saved.ok) {
      saved.message = 'The sign-in appearance was saved.';
    }
    log.debug("Leaving BrandingApi.act(). Saved " + !!saved.ok);
    return saved;
  }

  /**
   * The JSON Schema of a save's body, one property per setting.
   *
   * @returns the schema
   */
  static saveSchema(): Json {
    helpers.log.debug("Entering BrandingApi.saveSchema().");
    const colour = function (what: string): Json {
      helpers.log.debug("Entering colour().");
      helpers.log.debug("Leaving colour().");
      // No pattern: `config.js`'s `color` type is the one judge of a
      // colour, and its refusal carries its own code (STS-CORE-0006).
      return { type: 'string', maxLength: 7,
               description: what + ', `#rgb` or `#rrggbb`; stored as six ' +
                            'lower-case digits.' };
    };
    const properties: Json = {
      'branding.layout': { type: 'string',
                           enum: ['centered', 'split', 'banner'],
                           description: 'centered (the card alone), split ' +
                             '(a brand panel beside the card) or banner (a ' +
                             'band above it).' },
      'branding.accentColor': colour('Buttons, links and focus rings'),
      'branding.pageColor': colour('The page behind the card'),
      'branding.cardColor': colour('The card'),
      'branding.textColor': colour('The text on the card'),
      'branding.displayName': { type: 'string', maxLength: 80,
                                description: 'Shown beside the logo and in ' +
                                  'the document title. Text, never markup, ' +
                                  'and never translated. Empty for none.' },
      'branding.logoAlt': { type: 'string', maxLength: 160,
                            description: 'The logo\'s alternative text. ' +
                              'Required while a logo is set.' },
      'branding.logoLinkUrl': { type: 'string', maxLength: 2048,
                                description: 'An absolute https URL the ' +
                                  'logo links to, or empty for no link.' }
    };
    helpers.log.debug("Leaving BrandingApi.saveSchema().");
    return {
      type: 'object', properties: properties,
      examples: [{ 'branding.layout': 'split',
                   'branding.accentColor': '#0b5394',
                   'branding.displayName': 'Example Corp' }],
      additionalProperties: false
    };
  }

  /**
   * The route table.
   *
   * @returns the rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes: codes, loadBranding } = this.deps;
    const self = this;
    log.debug("Entering BrandingApi.buildRoutes().");
    const schema = BrandingApi.saveSchema();
    const failed = function (res: Res, e: any, what: string): void {
      log.debug("Entering failed(). " + what);
      log.error(codes.tag('STS-API-0038') + 'branding: ' + what +
                ' failed: ' + ((e && e.message) || e));
      codes.mark(res, 'STS-API-0038');
      self.sendJson(res, 500, { ok: false, errors:
        ['The sign-in appearance could not be changed.'] });
      log.debug("Leaving failed().");
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/branding',
        tag: 'Configuration', operationId: 'getBranding',
        summary: 'This realm\'s sign-in appearance (#717)',
        description: 'Everything Server configuration → Sign-in appearance ' +
          'draws: the layout and the layouts there are, the four colours ' +
          'and the tones derived from them, the contrast of the text, the ' +
          'links and the button text against WCAG 2.2 AA (4.5:1), the ' +
          'display name, the logo\'s alternative text and link, the ' +
          'stored logo (its type, sides, size and digest, never its ' +
          'bytes), and the page\'s settings. `previewUrl` and `logo.src` ' +
          'are in this realm.',
        mirrors: 'GET ' + PAGE,
        responseDescription: 'The realm\'s appearance.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`layout`, `layouts`, `colours`, ' +
                            '`derived`, `contrast`, `displayName`, ' +
                            '`logoAlt`, `logoLinkUrl`, `logoMaxBytes`, ' +
                            '`logo`, `customised`, `preview`, ' +
                            '`previewUrl`, `realm`, `settings`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API branding endpoint.");
          try {
            self.sendJson(res, 200, self.view());
          } catch (e) {
            log.debug("Caught in the management API branding endpoint: " +
                      ((e && (e as Error).message) || e));
            failed(res, e, 'the view');
          }
          log.debug("Leaving the management API branding endpoint.");
        } },

      // THE LOGO (D1, D2): the body is the image. ABOVE `/branding/:action`,
      // which would otherwise take `logo` as an action it does not know.
      { method: 'POST', path: BASE + '/branding/logo', tag: 'Configuration',
        operationId: 'uploadBrandingLogo',
        summary: 'Upload this realm\'s sign-in logo',
        description: 'The request body is the image itself: a PNG, a JPEG ' +
          'or a WebP, which the bytes decide whatever `Content-Type` ' +
          'says. Each side 16 to 2048 pixels, at most ' +
          'branding.logoMaxBytes. It replaces the logo the realm had. A ' +
          'logo needs alternative text: send it as `alt`, or set ' +
          'branding.logoAlt first. Served at this realm\'s ' +
          '/web/branding/logo. Audited, with its digest and never its ' +
          'bytes.',
        mirrors: 'POST ' + PAGE,
        handlerOwnsBody: true,
        parameters: [
          { name: 'alt', in: 'query', required: false,
            schema: { type: 'string', maxLength: 160,
                      examples: ['Our company logo'] },
            description: 'The alternative text, written to ' +
                         'branding.logoAlt with the image.' }
        ],
        requestBodyTypes: ['image/png', 'image/jpeg', 'image/webp',
                           'application/octet-stream'],
        responseDescription: 'The stored logo, in `logo`.',
        extraResponses: {
          '413': 'Larger than branding.logoMaxBytes.',
          '415': 'Not a PNG, a JPEG or a WebP, by its bytes.'
        },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API branding logo upload.");
          try {
            const q = req.query || {};
            const result = loadBranding().setLogo(
              BrandingApi.uploadedBytes(req),
              { alt: typeof q.alt === 'string' ? q.alt : undefined,
                actor: BrandingApi.callerOf(res) });
            if (!result.ok) {
              // The refusal's own code, read off the marked result.
              codes.mark(res, codes.codeOf(result) || 'STS-AUTHN-0545');
              self.sendJson(res, Number(result.status) || 400, result);
              log.debug("Leaving the management API branding logo upload. " +
                        "Refused.");
              return;
            }
            self.sendJson(res, 200, Object.assign({}, result,
              { message: 'The logo was stored.' }));
          } catch (e) {
            log.debug("Caught in the management API branding logo " +
                      "upload: " + ((e && (e as Error).message) || e));
            failed(res, e, 'a logo upload');
          }
          log.debug("Leaving the management API branding logo upload.");
        } },

      { method: 'POST', route: BASE + '/branding/:action',
        tag: 'Configuration', mirrors: 'POST ' + PAGE,
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API branding action.");
          try {
            const body = Object.assign({}, parseBody(req),
                                       { action: String(req.params.action ||
                                                        '') });
            const result = self.act(body);
            if (!result.ok) {
              // The refusal's own code, read off the marked result.
              codes.mark(res, codes.codeOf(result) || 'STS-API-0038');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
          } catch (e) {
            log.debug("Caught in the management API branding action: " +
                      ((e && (e as Error).message) || e));
            failed(res, e, 'an action');
          }
          log.debug("Leaving the management API branding action.");
        },
        actions: [
          { action: 'save', operationId: 'saveBranding',
            summary: 'Change this realm\'s sign-in appearance',
            description: 'Writes the `branding.*` settings named, in this ' +
              'realm: the default realm\'s are the process\'s overrides, a ' +
              'realm\'s are its own, as `POST /admin-api/config/set` would ' +
              'write them. They are judged TOGETHER, so a text colour and a ' +
              'card colour that pass only as a pair are taken as a pair, ' +
              'and nothing is written when any is refused: a colour that ' +
              'is not one, text or links below WCAG 2.2 AA (4.5:1) against ' +
              'the card, a link that is not https, an empty alternative ' +
              'text while a logo is set. A key that is not one of these ' +
              'eight is refused by name. branding.logoMaxBytes is the ' +
              'process\'s, set with `/config/set`.',
            requestBodyRequired: true,
            requestBody: schema,
            responseDescription: 'The keys written, in `saved`.' },
          { action: 'remove-logo', operationId: 'removeBrandingLogo',
            summary: 'Remove this realm\'s sign-in logo',
            description: 'The sign-in pages show no logo afterwards. The ' +
              'alternative text stays, so the next upload needs none. ' +
              'Audited where there was a logo to remove.',
            requestBodyRequired: false,
            requestBody: { type: 'object', properties: {},
                           examples: [{}], additionalProperties: false },
            responseDescription: '`removed`: whether there was one.' }
        ] }
    ];
    log.debug("Leaving BrandingApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<BrandingApi>(
  'mgmt-api/branding_api',
  () => new BrandingApi(BrandingApi.defaultDeps()),
  BrandingApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The sign-in appearance operations of `/admin-api` (#717).
 *
 * It registers no route: the management API spreads `ROUTES`.
 *
 * @namespace
 */
export = {
  BrandingApi: BrandingApi,
  PAGE: PAGE,
  SAVED_KEYS: SAVED_KEYS,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance every facade forwards to
   */
  installInstance: (instance: BrandingApi): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The installed instance's route table.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
