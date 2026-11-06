// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_response_models.ts
//
// ---------------------------------------------------------------------------
// WHAT `/authn-api` ANSWERS, PER OPERATION AND STATUS (#1353), keyed by
// operationId. `common/response_model_kit.ts` says how a model is written;
// `tests/openapi_response_models.js` fails on an operation with none.
//
// **AN ANSWER THAT DOES NOT FIT IS NOT SENT, AND HERE THAT MEANS SOMEBODY
// CANNOT SIGN IN.** So each model is the UNION of what every branch can send,
// read from the code that builds it, and hardly anything is `required`:
//
//   * a view is `authn/authn.ts`'s (`screenView()`, `selectIdpView()`,
//     `accountsView()`, `passwordChangeView()`, `mfaView()` and what it calls),
//     `authn/email_factor.ts`'s, `oauth-oidc/consent_screen.ts`'s,
//     `logout/logout.ts`'s or `oid4vc/vc_signin.ts`'s;
//   * an act's answer is one of the shapes `authn.ts` lists under *What the
//     sign-in screen's acts answer*, and a refusal of one carries the same
//     members at whichever status it was refused with, so `Models.act()` names
//     one model for every status an act can refuse at. `refuse()` in
//     `authn_api.ts` adds `error` and `error_description` to `ok` and `errors`,
//     and a refusal may come from there as well as from the module that owns
//     the act.
//
// **`Kit.applyModels()` GIVES A STATUS WITH NO MODEL OF ITS OWN THE 200's WHEN
// IT IS 400**, so every operation here names its 400: a view's would otherwise
// be a refusal held to the view's members.
//
// **A GEOFENCE REFUSES IN PLAIN TEXT** (`CellPlacement.servePermitted()`): a
// person homed in another cell who may not be served from here gets a 403 as
// `text/plain` from the first-factor acts, so those declare both media types
// (`Models.withGeofence()`). The validator refuses a media type a status does
// not declare, and this is the one non-JSON answer this API has.
//
// **WHAT IS NOT MODELLED AS A CLOSED OBJECT, AND WHY** — two places, each with
// its reason in `x-free-form`: the inner paths of this API's own OpenAPI
// document, and the `limits` member of an RFC 9396 authorization detail, whose
// members beyond the six `common/access_limits.ts` names are the API's own
// under a schema an operator declared.
//
// No function here is entered and left out loud: each runs only while this
// table is built, once per load, as `common/response_model_kit.ts`'s helpers
// do, and this module has no logger of its own for the same reason.
// ---------------------------------------------------------------------------

import Kit = require('../common/response_model_kit');

type Json = any;

const STRINGS: Json = Kit.listOf(Kit.str());

// How a model is listed: helpers, on the code style's rule, each run only while
// this table is built (see the header for why none logs).
class Models {
  // SEVERAL DOCUMENTS IN ONE PLACE (a step's page is `mfaView()`'s or the
  // emailed factor's, a sign-out's view an inventory, a result or a refusal)
  // ARE ONE CLOSED OBJECT HOLDING EVERY ONE'S MEMBERS, not an `anyOf`: what is
  // being
  // guarded is a member nobody declared, and an `anyOf`'s failure names every
  // arm's complaint about every member, where this names the member. An
  // enumerated member takes each document's values.
  static unionOf(...models: Json[]): Json {
    const members: Json = {};
    models.forEach(function (model: Json): void {
      Object.keys(model.properties).forEach(function (name: string): void {
        const had = members[name];
        const next = model.properties[name];
        members[name] = had && had.enum && next.enum
          ? Object.assign({}, had, { enum: Array.from(new Set(
              had.enum.concat(next.enum))) })
          : had || next;
      });
    });
    return Kit.closed(members);
  }

  // A view: its answer, and a refusal of the request. `extra` for a view that
  // has refusals of its own.
  static view(answer: Json, extra?: Json): Json {
    return Object.assign({ 200: answer, 400: ERROR }, extra || {});
  }

  // An act: every status it can refuse at carries the same members as its
  // success, because the same functions answer them. 415 and the other binding
  // refusals are `refuse()`'s, which that model holds too.
  static act(answer: Json, also?: string[]): Json {
    const out: Json = {};
    ['200', '400', '403', '415', '429'].concat(also || [])
      .forEach(function (status: string): void {
        out[status] = answer;
      });
    return out;
  }

  // The acts through `screenAct()` and `certificateSignIn()`, which may meet
  // `servePermitted()`: see the header.
  static withGeofence(models: Json): Json {
    return Object.assign({}, models, {
      403: Object.assign(Kit.media('text/plain'), { schema: models['403'] })
    });
  }

  static envelope(viewModel: Json, extra?: Json): Json {
    return Kit.closed(Object.assign({}, VIEW_ENVELOPE, { view: viewModel },
                                    extra || {}));
  }

  static walletView(answer: Json): Json {
    const out: Json = {};
    ['200', '400', '401', '403', '404', '409', '410', '500', '503']
      .forEach(function (status: string): void {
        out[status] = answer;
      });
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE REFUSALS.
// ---------------------------------------------------------------------------

// A refusal, from the gate or from a handler. `next` because several handlers
// answer `{ ok: false, next: 'refused', errors }` at a status no operation
// lists (a 500 from the wallet's door, a 429 at a passkey's options); the two
// `error` members because `oauthError()` and `refuse()` carry them, and the
// session store's 503 (`refuseUnread()`) carries only them.
const ERROR: Json = Kit.closed({
  ok: Kit.bool(),
  next: Kit.strEnum(['refused']),
  errors: STRINGS,
  error: Kit.str(),
  error_description: Kit.str()
}, { description: 'A refusal or a failure, in English. No error code is ever ' +
                  'in it.' });

// `refuse()`'s members and the rest of a plain refusal, for spreading into an
// answer that may also be one.
const REFUSAL_MEMBERS: Json = {
  ok: Kit.bool(),
  errors: STRINGS,
  error: Kit.str(),
  error_description: Kit.str()
};

// ---------------------------------------------------------------------------
// WHAT SEVERAL VIEWS SHARE.
// ---------------------------------------------------------------------------

// `preferredLanguageOf()`: a person's own language, for the browser's chooser.
const PREFERRED_LANGUAGE: Json = Kit.closed({
  value: Kit.str(),
  populated: Kit.bool()
});

// `common/applications.js`, `clientDisplayOf()` (#1300): null where the client
// registered no logo, policy or terms.
const CLIENT_DISPLAY: Json = Kit.nullable(Kit.closed({
  name: Kit.str(),
  logo: Kit.str(),
  logoOrigin: Kit.str(),
  policy: Kit.str(),
  tos: Kit.str()
}));

// The calling protocol's own rows, drawn as they are.
const DETAIL_ROW: Json = Kit.closed({
  label: Kit.str(),
  value: Kit.str(),
  note: Kit.str()
});

// `partnerLinks()`: one federation partner as a link.
const PARTNER_LINK: Json = Kit.closed({
  id: Kit.str(),
  label: Kit.str(),
  protocolLabel: Kit.str(),
  peer: Kit.str(),
  category: Kit.str(),
  provider: Kit.str(),
  href: Kit.str()
});

// `accountRows()`: a signed-in account has `signedInAt` and `authTime`, a
// remembered one `signedOutAt`.
const ACCOUNT_ROW: Json = Kit.closed({
  key: Kit.str(),
  sub: Kit.str(),
  username: Kit.str(),
  displayName: Kit.str(),
  state: Kit.strEnum(['signed-in', 'signed-out']),
  signedInAt: Kit.num(),
  authTime: Kit.num(),
  signedOutAt: Kit.num(),
  current: Kit.bool()
});

// ---------------------------------------------------------------------------
// WEBAUTHN'S OPTIONS (WebAuthn Level 3), as this service's own vocabulary
// carries them: `authn/webauthn_policy.ts` hands the browser's script these
// and the script builds the dictionaries from them, so `algorithms` here is
// `pubKeyCredParams`'s COSE identifiers and `credProps` and `minPinLength` are
// the extensions asked for.
// ---------------------------------------------------------------------------

const AUTHENTICATOR_SELECTION: Json = Kit.closed({
  userVerification: Kit.str(),
  residentKey: Kit.str(),
  requireResidentKey: Kit.bool(),
  authenticatorAttachment: Kit.str()
});

// `creationOptions()`, and `upgradeCreationOptions()` over it. An algorithm
// name with no COSE identifier would be `undefined` in the list, which JSON
// writes as null, so an item may be null: the page's complaint about that is
// more use to a person than a 500 here.
const CREATION_OPTIONS: Json = Kit.closed({
  rp: Kit.closed({ name: Kit.str(), id: Kit.str() }),
  algorithms: Kit.listOf(Kit.nullable(Kit.num())),
  attestation: Kit.str(),
  timeout: Kit.num(),
  authenticatorSelection: AUTHENTICATOR_SELECTION,
  credProps: Kit.bool(),
  minPinLength: Kit.bool(),
  hints: STRINGS
});

// `requestOptions()` and `discoverableRequestOptions()`.
const REQUEST_OPTIONS: Json = Kit.closed({
  rpId: Kit.str(),
  userVerification: Kit.str(),
  timeout: Kit.num(),
  hints: STRINGS
});

// `webauthnFacts()` and `upgradeStepFacts()`: the retry's facts; `upgrade` is
// the second's.
const CEREMONY_FALLBACK: Json = Kit.nullable(Kit.closed({
  asksPostQuantum: Kit.bool(),
  classical: Kit.bool(),
  retrying: Kit.bool(),
  upgrade: Kit.bool()
}));

// `facts.ceremony`, the members both a ceremony's own answer and the view it
// was deleted from speak of.
const CEREMONY_MEMBERS: Json = {
  mode: Kit.strEnum(['create', 'get']),
  challenge: Kit.str(),
  rpId: Kit.str(),
  user: Kit.closed({
    name: Kit.str(),
    displayName: Kit.str(),
    id: Kit.str()
  }),
  allow: STRINGS,
  exclude: STRINGS,
  options: Models.unionOf(CREATION_OPTIONS, REQUEST_OPTIONS),
  fallback: CEREMONY_FALLBACK
};

// A reason this step's ceremony cannot run, told before it does.
const CEREMONY_REFUSAL: Json = Kit.nullable(Kit.closed({
  why: Kit.str()
}));

const KEY_CHOICE: Json = Kit.closed({ id: Kit.str(), name: Kit.str() });

// `webauthnFacts()` less `ceremony`, which `mfaView()` deletes;
// `upgradeStepFacts()` answers the same members with `postLogin.upgrade` set.
const WEBAUTHN_FACTS: Json = Kit.closed({
  mode: Kit.strEnum(['create', 'get']),
  passwordless: Kit.bool(),
  choices: Kit.listOf(KEY_CHOICE),
  chosen: Kit.nullable(KEY_CHOICE),
  problem: Kit.str(),
  postQuantumRefused: CEREMONY_REFUSAL,
  hardwareRefused: CEREMONY_REFUSAL,
  postQuantumHelp: Kit.nullable(Kit.closed({ register: Kit.str() })),
  postQuantumAllowCredentials: Kit.str(),
  fallback: CEREMONY_FALLBACK,
  rpId: Kit.str(),
  widened: Kit.bool(),
  challenge: Kit.str(),
  attestation: Kit.str(),
  algorithms: STRINGS,
  postLogin: Kit.nullable(Kit.closed({
    required: Kit.bool(),
    upgrade: Kit.closed({
      phase: Kit.strEnum(['proof', 'registration']),
      name: Kit.str(),
      previousAlgorithm: Kit.str()
    })
  })),
  lanes: STRINGS,
  lane: Kit.str(),
  userVerification: Kit.str(),
  residentKey: Kit.str(),
  attachment: Kit.str()
});

// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN.
// ---------------------------------------------------------------------------

// `screenView()`.
const SCREEN_VIEW: Json = Kit.closed({
  id: Kit.str(),
  base: Kit.str(),
  protocol: Kit.str(),
  application: Kit.str(),
  error: Kit.str(),
  locked: Kit.str(),
  hint: Kit.str(),
  screen: Kit.bool(),
  password: Kit.bool(),
  keys: Kit.closed({
    enabled: Kit.bool(),
    mfaAllowed: Kit.bool(),
    primaryAllowed: Kit.bool()
  }),
  demands: Kit.closed({
    mfa: Kit.bool(),
    key: Kit.bool(),
    passwordless: Kit.bool(),
    via: Kit.str()
  }),
  remember: Kit.bool(),
  anonymous: Kit.bool(),
  passkey: Kit.bool(),
  usernameless: Kit.bool(),
  email: Kit.closed({ code: Kit.bool(), link: Kit.bool() }),
  clientDisplay: CLIENT_DISPLAY,
  reauthentication: Kit.str(),
  certificate: Kit.nullable(Kit.closed({
    name: Kit.str(),
    mfaNote: Kit.bool()
  })),
  postQuantumRequired: Kit.nullable(Kit.closed({ register: Kit.str() })),
  forgot: Kit.str(),
  // `partnersOf()`.
  partners: Kit.nullable(Kit.closed({
    kind: Kit.strEnum(['own-one', 'own-many', 'any']),
    options: Kit.listOf(PARTNER_LINK)
  })),
  // `kerberosOption()`.
  kerberos: Kit.nullable(Kit.closed({
    state: Kit.strEnum(['offered', 'withheld-key', 'withheld-mfa']),
    href: Kit.str()
  })),
  // `walletOption()`.
  wallet: Kit.nullable(Kit.closed({
    state: Kit.strEnum(['offered', 'withheld']),
    mfaNote: Kit.bool(),
    href: Kit.str(),
    siop: Kit.str()
  })),
  verifiesCredentials: Kit.bool(),
  fingerprint: Kit.bool(),
  details: Kit.listOf(DETAIL_ROW)
});

const SELECT_IDP_VIEW: Json = Kit.closed({
  id: Kit.str(),
  base: Kit.str(),
  protocol: Kit.str(),
  application: Kit.str(),
  problems: STRINGS,
  partners: Kit.listOf(PARTNER_LINK),
  details: Kit.listOf(DETAIL_ROW)
});

const ACCOUNTS_VIEW: Json = Kit.closed({
  id: Kit.str(),
  base: Kit.str(),
  protocol: Kit.str(),
  application: Kit.str(),
  reason: Kit.str(),
  accounts: Kit.listOf(ACCOUNT_ROW),
  another: Kit.closed({ open: Kit.bool() }),
  max: Kit.num(),
  details: Kit.listOf(DETAIL_ROW)
});

const PASSWORD_CHANGE_VIEW: Json = Kit.closed({
  id: Kit.str(),
  username: Kit.str(),
  notice: Kit.str()
});

// ---------------------------------------------------------------------------
// A STEP'S PAGE: `mfaView()`, with the member its page adds, or the emailed
// factor's `view()`, which is a different document in the same place.
// ---------------------------------------------------------------------------

const MFA_VIEW: Json = Kit.closed({
  page: Kit.str(),
  id: Kit.str(),
  username: Kit.str(),
  passwordless: Kit.bool(),
  // `stepLinks()`.
  links: Kit.closed({
    totp: Kit.bool(),
    webauthn: Kit.bool(),
    wallet: Kit.bool(),
    password: Kit.bool(),
    email: Kit.str(),
    backup: Kit.bool()
  }),
  clientDisplay: CLIENT_DISPLAY,
  totp: Kit.closed({ digits: Kit.num(), period: Kit.num() }),
  amr: STRINGS,
  backup: Kit.closed({
    factor: Kit.strEnum(['passkey', 'code', 'link', 'app']),
    back: Kit.str(),
    remaining: Kit.num(),
    total: Kit.num(),
    low: Kit.bool()
  }),
  webauthn: WEBAUTHN_FACTS,
  // `mfaSetupFacts()`.
  setup: Kit.closed({
    state: Kit.strEnum(['choose', 'totp']),
    offered: Kit.closed({ totp: Kit.bool(), webauthn: Kit.bool() }),
    optional: Kit.bool(),
    proved: Kit.bool(),
    recovery: Kit.bool(),
    totp: Kit.nullable(Kit.closed({
      uri: Kit.str(),
      secret: Kit.str(),
      algorithm: Kit.str(),
      digits: Kit.num(),
      period: Kit.num()
    }))
  }),
  postLogin: Kit.closed({
    activity: Kit.str(),
    reason: Kit.str(),
    required: Kit.bool(),
    canSkip: Kit.bool(),
    method: Kit.str(),
    failed: Kit.str(),
    separate: Kit.bool(),
    snoozeDays: Kit.num(),
    deadline: Kit.str()
  })
});

// `EmailFactor.view()`: `stepFacts()` where the step is live; `elsewhere`,
// `open` and `end` (its `endView()`) otherwise.
const EMAIL_VIEW: Json = Kit.closed({
  state: Kit.strEnum(['ask', 'code', 'wait', 'open', 'elsewhere', 'end']),
  kind: Kit.strEnum(['code', 'link']),
  id: Kit.str(),
  primary: Kit.bool(),
  username: Kit.str(),
  address: Kit.str(),
  minutes: Kit.num(),
  seconds: Kit.num(),
  notice: Kit.str(),
  others: Kit.closed({
    totp: Kit.bool(),
    webauthn: Kit.bool(),
    password: Kit.bool(),
    backup: Kit.bool()
  }),
  clientDisplay: CLIENT_DISPLAY,
  title: Kit.str(),
  sentence: Kit.str()
});

// ---------------------------------------------------------------------------
// THE WALLET'S VIEWS (#574), `oid4vc/vc_signin.ts`: a start, a wait, or a
// refusal of kind `refused` (`refusedView()`).
// ---------------------------------------------------------------------------

const WALLET_START_VIEW: Json = Kit.closed({
  wallet: Kit.strEnum(['start']),
  kind: Kit.str(),
  secondFactor: Kit.bool()
});

const WALLET_WAIT_VIEW: Json = Kit.closed({
  wallet: Kit.strEnum(['wait']),
  state: Kit.str(),
  kind: Kit.str(),
  secondFactor: Kit.bool(),
  authn: Kit.str(),
  mfa: Kit.str(),
  enrol: Kit.bool(),
  // `VcVerifier.dcApiRequestFor()`.
  dcRequest: Kit.nullable(Kit.closed({
    protocol: Kit.str(),
    data: Kit.closed({ request: Kit.str() })
  })),
  sameDevice: Kit.str(),
  webWallet: Kit.str(),
  qr: Kit.str(),
  expiresIn: Kit.num(),
  pollSeconds: Kit.num(),
  protocol: Kit.str(),
  verifier: Kit.str(),
  back: Kit.str(),
  backKind: Kit.strEnum(['portal', 'screen', 'none'])
});

const WALLET_REFUSED_VIEW: Json = Kit.closed({
  wallet: Kit.strEnum(['refused']),
  heading: Kit.str(),
  retry: Kit.str(),
  checks: Kit.listOf(Kit.closed({
    ok: Kit.bool(),
    name: Kit.str(),
    detail: Kit.str()
  })),
  verdict: Kit.str(),
  back: Kit.str(),
  backKind: Kit.strEnum(['portal', 'screen', 'none']),
  reissue: Kit.str()
});

// ---------------------------------------------------------------------------
// THE ANSWERS TO AN ACT.
// ---------------------------------------------------------------------------

// The next step, or its refusal: `authn.ts`'s `screenRefused()` (`location`
// where a step's end refused the session, `passkey` after a refused passkey),
// `stepAnswer()`, `leave()`, `restartFrom()`, `sendHome()` (`home-cell`, whose
// `fields` are a request's own parameters), `stepRefused()`,
// `passwordChangeRefused()`, the emailed factor's `endAnswer()` (`end`) and
// `sendAct()` (`stay`), the account picker's and the consent screen's answers
// are all this.
const NEXT_MEMBERS: Json = Object.assign({}, REFUSAL_MEMBERS, {
  next: Kit.strEnum(['redirect', 'mfa', 'password-change', 'home-cell',
                     'stay', 'refused']),
  location: Kit.str(),
  step: Kit.str(),
  id: Kit.str(),
  form: Kit.closed({
    method: Kit.strEnum(['GET', 'POST']),
    action: Kit.str(),
    fields: Kit.mapOf(Kit.str(), 'A request\'s own parameters, by name.')
  }),
  notice: Kit.str(),
  end: Kit.closed({ title: Kit.str() }),
  passkey: Kit.closed({
    unknownCredential: Kit.str(),
    autofill: Kit.bool()
  })
});

const NEXT: Json = Kit.closed(NEXT_MEMBERS, { description:
  'What the act leads to. `redirect`: go to `location` with a GET. `mfa`: ' +
  'the second-factor step `step`, whose page is `location`. ' +
  '`password-change`: the forced change, at `location`. `home-cell`: send ' +
  '`form` as it is. ' +
  '`stay`: draw the page again. `refused`: `errors` says why, in English; ' +
  'with `location` the sign-in screen says it, and with `end` the page ends.'
});

// `POST /wallet`, the poll and the Digital Credentials API's answer: a wait, a
// refusal with its view (`VcSignin.refuse()`), or what `finish()` ends in,
// which is whatever a sign-in's end is, a next step included.
const WALLET_ACT: Json = Kit.closed(Object.assign({}, NEXT_MEMBERS, {
  next: Kit.strEnum(['wait', 'redirect', 'mfa', 'password-change',
                     'home-cell', 'stay', 'refused']),
  go: Kit.str(),
  state: Kit.str(),
  expiresIn: Kit.num(),
  view: WALLET_REFUSED_VIEW
}));

// A row of a sign-out's result.
const LOGOUT_RESULT_ROW: Json = Kit.closed({
  id: Kit.str(),
  label: Kit.str(),
  message: Kit.str()
});

// `accountStep()`.
const LOGOUT_ACCOUNTS_VIEW: Json = Kit.closed({
  state: Kit.strEnum(['accounts']),
  accounts: Kit.listOf(Kit.closed({
    key: Kit.str(),
    username: Kit.str(),
    displayName: Kit.str(),
    current: Kit.bool()
  })),
  preselected: Kit.str(),
  naming: Kit.strEnum(['open', 'off', 'product'])
});

// `subjectRefusal()`: a name that may not be used, and nobody to act on.
const LOGOUT_REFUSED_VIEW: Json = Kit.closed({
  state: Kit.strEnum(['refused', 'nobody']),
  verifiesCredentials: Kit.bool()
});

// `resultView()`.
const LOGOUT_RESULT_VIEW: Json = Kit.closed({
  state: Kit.strEnum(['result']),
  scope: Kit.strEnum(['global', 'selected']),
  key: Kit.str(),
  message: Kit.str(),
  terminated: Kit.listOf(LOGOUT_RESULT_ROW),
  skipped: Kit.listOf(LOGOUT_RESULT_ROW),
  remaining: Kit.num()
});

// `POST /logout` and `/logout/accounts` (`signOutAct()`,
// `signOutAccountsAct()`): the result, the signed-out document's form, the next
// page, or a refusal.
const LOGOUT_ACT: Json = Kit.closed(Object.assign({}, REFUSAL_MEMBERS, {
  next: Kit.strEnum(['signed-out', 'inventory', 'refused']),
  username: Kit.str(),
  account: Kit.str(),
  location: Kit.str(),
  ownSessionEnded: Kit.bool(),
  scope: Kit.strEnum(['global', 'selected']),
  form: Kit.closed({
    method: Kit.strEnum(['POST']),
    action: Kit.str(),
    fields: Kit.closed({ result: Kit.str() })
  }),
  view: Models.unionOf(LOGOUT_RESULT_VIEW, LOGOUT_REFUSED_VIEW,
                       LOGOUT_ACCOUNTS_VIEW)
}));

// ---------------------------------------------------------------------------
// THE SIGN-OUT'S INVENTORY: `Logout.row()`'s members, whichever family's
// `collect()` made it (each passes only those; `secret` is deleted on the way
// out). A LDAP connection's id is a socket's number or its address, and a row
// can come from a store that recorded nothing, hence the handle's two types and
// the times' null: a sign-out page refused over a missing timestamp would be
// the worst page to lose.
// ---------------------------------------------------------------------------
const INVENTORY_ROW: Json = Kit.closed({
  id: Kit.str(),
  family: Kit.str(),
  kind: Kit.str(),
  handle: Kit.oneOf(Kit.str(), Kit.num()),
  label: Kit.nullable(Kit.str()),
  detail: Kit.nullable(Kit.str()),
  startedAt: Kit.nullable(Kit.num()),
  expiresAt: Kit.nullable(Kit.num()),
  terminable: Kit.bool(),
  why: Kit.nullable(Kit.str()),
  sessionId: Kit.nullable(Kit.str())
});

// `inventoryFor()`.
const INVENTORY_MEMBERS: Json = {
  key: Kit.str(),
  sessions: Kit.num(),
  families: Kit.listOf(Kit.closed({
    id: Kit.str(),
    label: Kit.str(),
    protocol: Kit.str(),
    spec: Kit.str(),
    what: Kit.str(),
    terminable: Kit.bool(),
    rows: Kit.listOf(INVENTORY_ROW),
    held: Kit.num(),
    notListed: Kit.num(),
    failure: Kit.str()
  })),
  total: Kit.num(),
  listed: Kit.num(),
  notListed: Kit.num(),
  maxRows: Kit.num(),
  at: Kit.num()
};

const LOGOUT_INVENTORY_VIEW: Json = Kit.closed(Object.assign({
  state: Kit.strEnum(['inventory']),
  username: Kit.str(),
  named: Kit.bool(),
  naming: Kit.strEnum(['open', 'off', 'product']),
  account: Kit.str()
}, INVENTORY_MEMBERS));

// ---------------------------------------------------------------------------
// THE CONSENT SCREEN: `consentView()`.
// ---------------------------------------------------------------------------
const CONSENT_VIEW: Json = Kit.closed({
  consent: Kit.bool(),
  username: Kit.str(),
  base: Kit.str(),
  client: Kit.closed({ id: Kit.str(), name: Kit.str() }),
  clientDisplay: CLIENT_DISPLAY,
  scopes: Kit.listOf(Kit.closed({
    scope: Kit.str(),
    permission: Kit.nullable(Kit.closed({
      description: Kit.str(),
      name: Kit.str(),
      identifier: Kit.str(),
      baseUri: Kit.str()
    })),
    releasesDid: Kit.bool()
  })),
  authorizationDetails: Kit.listOf(Kit.closed({
    type: Kit.str(),
    description: Kit.str(),
    resource: Kit.str(),
    audience: Kit.str(),
    members: Kit.listOf(Kit.closed({ name: Kit.str(), value: Kit.str() }))
  })),
  already: Kit.listOf(Kit.closed({
    scope: Kit.str(),
    global: Kit.bool(),
    at: Kit.str()
  })),
  limits: Kit.listOf(Kit.closed({
    r: Kit.int(),
    type: Kit.str(),
    limits: Kit.freeForm('The limits member of an RFC 9396 authorization ' +
      'detail, as the client sent it: beyond the six members ' +
      'common/access_limits.ts names, every member is the API\'s own, under ' +
      'a schema an operator declared for its type.'),
    rows: Kit.listOf(Kit.closed({
      member: Kit.str(),
      label: Kit.str(),
      value: Kit.str()
    }))
  })),
  attribute: Kit.str(),
  protocol: Kit.str(),
  details: Kit.listOf(DETAIL_ROW)
});

// ---------------------------------------------------------------------------
// THE ACTS, BY WHAT THEY ANSWER.
// ---------------------------------------------------------------------------




const NEXT_ACT: Json = Models.act(NEXT);
const SCREEN_ACT: Json = Models.withGeofence(NEXT_ACT);
// `accountsRefused()`, and the 503 of a set that could not be read.
const ACCOUNTS_ACT: Json = Models.act(NEXT, ['409', '503']);
// `refuse()` at the wallet's door, with `answerDcApi()`'s statuses (400 and
// 403) and a claim store's 503 among them.
const WALLET_ACTS: Json = Models.act(WALLET_ACT, ['401', '404', '409', '410',
                                                  '500', '503']);
const LOGOUT_ACTS: Json = Models.act(LOGOUT_ACT, ['401', '409']);

// The members every view's envelope has beside the view.
const VIEW_ENVELOPE: Json = {
  ok: Kit.bool(),
  csrf: Kit.str(),
  uiLocales: Kit.str(),
  preferredLanguage: PREFERRED_LANGUAGE
};


// A step's page: `mfaStep()`. A refused emailed-factor page is a whole answer
// with its `end` view and `errors`, and a refused second-factor page
// `refuse()`'s, both at 400.
const STEP_VIEW: Json = Models.envelope(Models.unionOf(MFA_VIEW, EMAIL_VIEW),
                                 { errors: STRINGS, error: Kit.str(),
                                   error_description: Kit.str() });

const WALLET_VIEW_REFUSALS: Json = {
  next: Kit.strEnum(['refused']),
  errors: STRINGS
};

// `startView()`, `waitView()` and what `admitted()`, `startable()`, `closed()`
// refuse them with.
const WALLET_START: Json = Models.envelope(
  Models.unionOf(WALLET_START_VIEW, WALLET_REFUSED_VIEW), WALLET_VIEW_REFUSALS);
const WALLET_WAIT: Json = Models.envelope(
  Models.unionOf(WALLET_WAIT_VIEW, WALLET_REFUSED_VIEW), WALLET_VIEW_REFUSALS);


// `signOutView()`: the inventory, the account step where the browser holds
// several, or `subjectRefusal()`.
const SIGN_OUT_VIEW: Json = Models.envelope(
  Models.unionOf(LOGOUT_INVENTORY_VIEW, LOGOUT_ACCOUNTS_VIEW,
                 LOGOUT_REFUSED_VIEW),
  { errors: STRINGS, error: Kit.str(), error_description: Kit.str() });

// `signOutAccountsView()`, or `accountsOff()`.
const SIGN_OUT_ACCOUNTS: Json = Models.envelope(LOGOUT_ACCOUNTS_VIEW,
  { errors: STRINGS, error: Kit.str(), error_description: Kit.str() });

const OPERATION_INDEX: Json = Kit.closed({
  api: Kit.str(),
  openapi: Kit.str(),
  operations: Kit.listOf(Kit.closed({
    method: Kit.strEnum(['GET', 'POST']),
    path: Kit.str(),
    operationId: Kit.str(),
    access: Kit.str(),
    mirrors: Kit.nullable(Kit.str()),
    action: Kit.nullable(Kit.str()),
    summary: Kit.str()
  }))
});

const OPENAPI_REASON = 'The operations and components of an OpenAPI document ' +
  'are that specification\'s vocabulary, not this API\'s, and this document ' +
  'describes itself with them.';

const OPENAPI_DOCUMENT: Json = Kit.closed({
  openapi: Kit.str(),
  info: Kit.closed({
    title: Kit.str(),
    version: Kit.str(),
    description: Kit.str()
  }),
  servers: Kit.listOf(Kit.closed({ url: Kit.str() })),
  tags: Kit.listOf(Kit.closed({ name: Kit.str() })),
  paths: Kit.freeForm(OPENAPI_REASON),
  components: Kit.freeForm(OPENAPI_REASON)
});

const operations: Record<string, Record<string, Json>> = {
  getIndex: Models.view(OPERATION_INDEX),
  getOpenApi: Models.view(OPENAPI_DOCUMENT),

  // --- the screen -----------------------------------------------------------
  getScreen: Models.view(Models.envelope(SCREEN_VIEW)),
  // `go` where fewer than two partners are left: the screen, instead.
  getPartners: Models.view(Models.envelope(SELECT_IDP_VIEW, { go: Kit.str() })),
  signInWithPassword: SCREEN_ACT,
  cancelSignIn: SCREEN_ACT,
  continueAnonymously: SCREEN_ACT,
  continueWithCertificate: SCREEN_ACT,
  signInByEmail: SCREEN_ACT,
  signInWithPasskey: SCREEN_ACT,
  // `AuthnApi.passkeyOptions()`, and `refuse()` before it.
  passkeyOptions: Models.act(Kit.closed(Object.assign({}, REFUSAL_MEMBERS, {
    next: Kit.strEnum(['refused']),
    challenge: Kit.str(),
    rpId: Kit.str(),
    options: REQUEST_OPTIONS
  }))),

  // --- the forced password change -------------------------------------------
  getPasswordChange: Models.view(Models.envelope(PASSWORD_CHANGE_VIEW)),
  changePassword: NEXT_ACT,
  startOverFromPasswordChange: NEXT_ACT,

  // --- the steps after the screen -------------------------------------------
  getStep: { 200: STEP_VIEW, 400: STEP_VIEW },
  checkCode: NEXT_ACT,
  spendRecoveryCode: NEXT_ACT,
  checkFactorPassword: NEXT_ACT,
  // `mfaWebauthnOptions()`: `facts.ceremony`, or `stepRefused()`.
  passkeyStepOptions: Models.act(Kit.closed(Object.assign({}, REFUSAL_MEMBERS,
    CEREMONY_MEMBERS, { next: Kit.strEnum(['refused']) }))),
  finishPasskeyStep: NEXT_ACT,
  beginAppEnrolment: NEXT_ACT,
  confirmAppEnrolment: NEXT_ACT,
  beginKeyEnrolment: NEXT_ACT,
  ignoreOffer: NEXT_ACT,
  registerPostLoginPasskey: NEXT_ACT,
  skipPostLoginActivity: NEXT_ACT,
  sendEmailedFactor: NEXT_ACT,
  checkEmailedCode: NEXT_ACT,
  spendEmailedLink: NEXT_ACT,
  startOver: NEXT_ACT,

  // --- the wallet -----------------------------------------------------------
  getWalletStart: Models.walletView(WALLET_START),
  startWalletSignIn: WALLET_ACTS,
  getWalletWait: Models.walletView(WALLET_WAIT),
  walletStatus: WALLET_ACTS,
  answerWalletDcApi: WALLET_ACTS,

  // --- the sign-out ---------------------------------------------------------
  getSignOut: { 200: SIGN_OUT_VIEW, 400: SIGN_OUT_VIEW, 401: SIGN_OUT_VIEW,
                403: SIGN_OUT_VIEW },
  signOut: LOGOUT_ACTS,
  getSignOutAccounts: { 200: SIGN_OUT_ACCOUNTS, 400: SIGN_OUT_ACCOUNTS },
  chooseSignOutAccount: LOGOUT_ACTS,

  // --- several accounts in one browser --------------------------------------
  getAccountChoice: Models.view(Models.envelope(ACCOUNTS_VIEW), { 503: ERROR }),
  selectAccount: ACCOUNTS_ACT,
  useAnotherAccount: ACCOUNTS_ACT,
  forgetAccount: ACCOUNTS_ACT,
  // `browserAccounts()`, with `anotherAccount` where the setting is on.
  getAccounts: Models.view(Kit.closed({
    ok: Kit.bool(),
    enabled: Kit.bool(),
    accounts: Kit.listOf(ACCOUNT_ROW),
    max: Kit.num(),
    anotherAccount: Kit.str(),
    csrf: Kit.str()
  })),

  // --- the consent screen ---------------------------------------------------
  getConsent: Models.view(Models.envelope(CONSENT_VIEW)),
  answerConsent: NEXT_ACT
};

export = { ERROR: ERROR, operations: operations };
