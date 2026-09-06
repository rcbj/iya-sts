'use strict';
//
// File: portal.js
//
// ---------------------------------------------------------------------------
// THE USER PORTAL: THE FIRST PAGE IN THIS SERVICE THAT BELONGS TO THE PERSON
// LOOKING AT IT (2026-09-06).
//
// Every browser-facing surface here until now was for somebody else. The
// sign-in screen is a step in another protocol's flow; the consent screen asks
// one question and leaves; `/admin` is for an operator and is gated on two
// roles. **Nothing let a person see what this identity provider knows about
// THEM, or change how they authenticate.**
//
// Two routes and they are not the same thing:
//
//   `/portal/activate?user=…&token=…`   UNAUTHENTICATED. Spending an activation
//                                       link to set up a credential. This is
//                                       how somebody provisioned through SCIM
//                                       or /admin-api comes to have a way in.
//   `/portal`                           AUTHENTICATED. Their own information,
//                                       their password, their security keys.
//
// ---------------------------------------------------------------------------
// IT IS A SEPARATE APPLICATION FROM THE ADMIN CONSOLE AND SHARES NOTHING BUT
// THE SESSION.
//
// Not the shell, not the navigation, not the gate. That is deliberate: the
// console's `respond()` draws a sidebar of forty administrative pages and its
// gate answers "does this person hold Admin Read" — neither of which is
// anything a person managing their own account should meet. **What they share
// is `authn.js`'s session**, because there is one answer in this service to
// "who is this browser" and a second would be the thing that eventually
// disagrees.
//
// ---------------------------------------------------------------------------
// ACCESS CONTROL: THE IDENTITY COMES FROM THE SESSION AND NEVER FROM THE
// REQUEST. OWASP A01.
//
// This is the one rule in this file that matters more than the rest of it put
// together, and it is the vulnerability class that tops the Top Ten: **no route
// here takes a username, an id or a DN from the query string or the body.**
// Every page reads `sessionOf(req).user.username` and nothing else, so there is
// no parameter for anybody to change. `/portal/activate` is the single
// exception and it is not one: it takes a username BECAUSE nobody is signed in,
// and what authorises it is the token, which is a credential.
//
// `tests/portal_access.js` asserts it by trying — one session, another person's
// name in every parameter this file could plausibly have read.
//
// ---------------------------------------------------------------------------
// THE OWASP CONTROLS THIS PAGE CARRIES, and where each lives:
//
//   A01 access control    the rule above, plus `tests/portal_access.js`
//   A02 crypto            scrypt for passwords, the activation token hashed at
//                         rest — `common/credentials.js`
//   A03 injection         every value through `esc()`; this service builds no
//                         SQL from user input anywhere
//   A04 insecure design   rate limiting on activation and password change —
//                         `common/websecurity.js`
//   A05 misconfiguration  the CSP `app.js` sets on every response, including
//                         `script-src 'none'` and `frame-ancestors 'none'`
//   A07 auth failures     CSRF tokens on every POST here, session replaced on
//                         sign-in, and no message that distinguishes "no such
//                         person" from "wrong credential"
//   A09 logging           every act audited through `audit.js`
//
// A LIBRARY? No — it registers routes (rule 1), so its place in the require
// order is a place. It must come AFTER `authn.js`, whose session it reads.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const helpers = require('../common/helpers');
const { log, parseBody, baseUrlOf } = helpers;
const config = require('../common/config');
const mode = require('../common/mode');
const credentials = require('../common/credentials');
const websecurity = require('../common/websecurity');
const authn = require('../authn/authn');
// The access-control gate. A LEAF (rule 3), armed by xacml/xacml_access_pep.js
// at 23c — before that line every check is allowed, which is what a process
// without the XACML family does.
const accessGate = require('../common/access_gate');
const audit = require('../common/audit');

// The input validator. A LEAF (rule 3): it registers no route and requires only
// `config`, `bunyan` and zod, so it closes no cycle here and moves nothing.
const validation = require('../common/validation');
const vt = validation.types;
const vz = validation.z;
const stats = require('../common/admin_stats');

const BASE = '/portal';
const ACTIVATE = BASE + '/activate';

// Everything drawn here goes through it. The console has its own; this is a
// separate application and shares no markup with it.
function esc(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CSS =
  'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
  'background:#f4f4f7;margin:0;padding:2rem 1rem;color:#222;line-height:1.5}' +
  '.wrap{max-width:720px;margin:0 auto}' +
  '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
  'padding:24px 28px;margin-bottom:18px;box-shadow:0 2px 10px rgba(0,0,0,.04)}' +
  'h1{font-size:1.4em;margin:0 0 4px}h2{font-size:1.05em;margin:0 0 12px}' +
  'p.sub{color:#666;font-size:.9em;margin:0 0 18px}' +
  'label{display:block;font-size:.85em;font-weight:600;margin:12px 0 4px}' +
  'input[type=text],input[type=password]{width:100%;padding:9px 10px;' +
  'border:1px solid #c9c9d2;border-radius:6px;font-size:1em;box-sizing:border-box}' +
  'button{margin-top:14px;padding:9px 16px;border:0;border-radius:6px;' +
  'background:#2c5cc5;color:#fff;font-size:.95em;cursor:pointer}' +
  'button.danger{background:#b00020}button.secondary{background:#5a5a68}' +
  'table{border-collapse:collapse;width:100%;font-size:.9em}' +
  'th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e6e6ec}' +
  'th{color:#555;font-weight:600;width:34%}' +
  '.err{background:#fdecef;border:1px solid #f5c2cb;color:#8a1027;' +
  'padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:.9em}' +
  '.ok{background:#eaf6ec;border:1px solid #bfe3c6;color:#1d5b2a;' +
  'padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:.9em}' +
  '.note{color:#555;font-size:.85em;margin:10px 0 0}' +
  'code{background:#f0f0f5;padding:1px 5px;border-radius:4px;font-size:.9em}';

function page(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + esc(title) + ' — mock STS</title><style>' + CSS +
    '</style></head><body><div class="wrap">' + inner + '</div></body></html>\n';
}

function send(res, status, html) {
  // `no-store` on every page: this one draws a person's own account details and
  // is reached from a shared browser as often as not.
  res.status(status).set('Cache-Control', 'no-store').type('html').send(html);
}

// ---------------------------------------------------------------------------
// THE ACTIVATION FLOW. Unauthenticated, and the only route here that takes an
// identity from the request — because nobody is signed in yet and the TOKEN is
// what authorises it.
//
// **THE LINK IS NOT SPENT WHEN IT IS OPENED.** It is spent when the setup
// FINISHES. A link consumed on a GET would be burned by a browser prefetching
// it, by a corporate mail scanner following it, or by the person reloading the
// page — and each of those would strand somebody with an account they cannot
// set up and a link that no longer works.
// ---------------------------------------------------------------------------

// One sentence for every way an activation link can fail, and it is the SAME
// sentence. Wrong token, expired token, no token issued and no such person are
// four different facts and telling them apart would let anybody with the page
// enumerate which usernames have an activation outstanding.
const ACTIVATION_REFUSAL =
  'This activation link is not valid. It may have expired, it may already ' +
  'have been used, or it may never have been issued. Ask whoever set up your ' +
  'account for a new one.';

function activationForm(base, username, token, message, error) {
  const csrfless = ''; // the form carries the token instead; see below
  return page('Set up your account',
    '<div class="card">' +
    '<h1>Set up your account</h1>' +
    '<p class="sub">You are setting up how <strong>' + esc(username) +
    '</strong> will sign in to <code>' + esc(base) + '</code>.</p>' +
    (error ? '<div class="err">' + esc(error) + '</div>' : '') +
    (message ? '<div class="ok">' + esc(message) + '</div>' : '') +
    '<form method="post" action="' + ACTIVATE + '">' +
    // THE TOKEN RIDES IN THE FORM, and this is the one place in this service a
    // credential is a hidden field. It is unavoidable: the person is not signed
    // in, so there is no session to carry state on, and the alternative — a
    // server-side pending record keyed by something else — would be a second
    // credential protecting the first. It is a POST so the token does not end
    // up in a referer or an access log the way a GET's query string does.
    '<input type="hidden" name="user" value="' + esc(username) + '">' +
    '<input type="hidden" name="token" value="' + esc(token) + '">' +
    '<h2>1. A password</h2>' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="new-password">' +
    '<label for="confirm">Confirm it</label>' +
    '<input type="password" id="confirm" name="confirm" autocomplete="new-password">' +
    '<p class="note">Leave both empty if you would rather sign in with a ' +
    'security key alone. You need at least one of the two.</p>' +
    '<h2>2. A security key</h2>' +
    '<p class="note">A security key can be your ONLY credential (you sign in ' +
    'with the key and no password) or a SECOND factor beside a password. ' +
    'This service supports no other second factor.</p>' +
    '<label class="chk"><input type="radio" name="key_role" value="none" checked> ' +
    'No security key for now</label>' +
    '<label class="chk"><input type="radio" name="key_role" value="primary"> ' +
    'Use a security key instead of a password</label>' +
    '<label class="chk"><input type="radio" name="key_role" value="mfa"> ' +
    'Use a security key as a second factor, with the password above</label>' +
    '<p class="note">Choosing a security key takes you to the enrolment screen ' +
    'after this step.</p>' +
    '<button type="submit">Continue</button>' +
    '</form>' +
    '</div>');
}

// ---------------------------------------------------------------------------
// WHAT THE FIVE PORTAL ROUTES TAKE, AND THE ONE THAT IS ALLOWED A USERNAME.
//
// The rule at the top of this file is that no route here takes an identity from
// the request — every page reads `sessionOf(req).user.username`, so there is no
// parameter for anybody to change. **These schemas are the mechanical statement
// of that rule**: four of the five declare no identity field at all, and a
// reader checking whether the rule still holds can read five short objects
// instead of five handlers.
//
// `/portal/activate` is the exception and it is not one: it takes a username
// BECAUSE nobody is signed in, and what authorises it is the token beside it,
// which is a credential.
//
// **`done` IS THE ONE REFLECTED VALUE ON THIS SURFACE.** This service puts it
// in a `Location` after a successful change and reads it straight back onto the
// page — so anybody can craft `/portal?done=<anything>` and have it rendered.
// It is escaped through `esc()` and this console is `script-src 'none'`, so the
// bound here is depth rather than the fix; what it removes is the megabyte
// version and the one with a NUL in it.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A REFUSAL FROM `common/validation.js`, RENDERED AS A PAGE.
//
// That module returns a code, a field and a sentence and renders nothing; this
// surface answers a person in a browser, so the sentence goes on a page in this
// portal's own shell rather than into a JSON body nobody here would see.
//
// 400 and not 403: nothing was refused about WHO is asking. The request was
// malformed, which is true whether or not anybody is signed in — the same line
// `common/validation.js` draws between shape and existence.
// ---------------------------------------------------------------------------
function refuseShape(res, why) {
  log.debug('Entering refuseShape(). code=' + why.code + ' field=' + why.field);
  log.debug('Leaving refuseShape().');
  return send(res, 400, page('Bad request',
    '<div class="card"><h1>Bad request</h1><p class="err">' +
    esc(why.detail) + '</p></div>'));
}

const ACTIVATE_QUERY = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token)
});

const ACTIVATE_FORM = vz.object({
  user: vt.opt(vt.name),
  token: vt.opt(vt.token),
  password: vz.string().max(1024).optional(),
  confirm: vz.string().max(1024).optional(),
  // The three radio values the form itself draws. A closed set rather than a
  // string, because this one decides what the enrolled key is FOR.
  key_role: vt.opt(vt.oneOf(['none', 'primary', 'mfa'])),
  csrf_token: vt.opt(vt.token)
});

const PORTAL_QUERY = vz.object({
  done: vz.string().max(200).optional()
});

const PASSWORD_FORM = vz.object({
  current: vz.string().max(1024).optional(),
  next: vz.string().max(1024).optional(),
  confirm: vz.string().max(1024).optional(),
  csrf_token: vt.opt(vt.token)
});

// A WebAuthn credential id is base64url, and it is the ONE identifier this
// surface takes from a body. It names a key on the SIGNED-IN person's own entry
// and is checked against that entry — the file's header calls this the case
// worth understanding, because it looks like the rule's exception and is not.
const REMOVE_KEY_FORM = vz.object({
  credentialId: vt.opt(vt.base64url),
  csrf_token: vt.opt(vt.token)
});

app.get(ACTIVATE, function (req, res) {
  log.debug('Entering GET ' + ACTIVATE + '.');
  const asked = validation.check(req, 'query', ACTIVATE_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  const username = String(asked.value.user || '').trim();
  const token = String(asked.value.token || '');
  // RATE LIMITED even on the GET: this endpoint takes a credential, and an
  // endpoint that takes a credential must not be the one place in this service
  // that answers guesses at network speed.
  const allowed = websecurity.attempt('activation', req, username);
  if (!allowed.ok) {
    log.debug('Leaving GET ' + ACTIVATE + '. Rate limited.');
    return send(res, 429, page('Too many attempts',
      '<div class="card"><h1>Too many attempts</h1><p>' +
      esc(allowed.detail) + '</p></div>'));
  }
  const checked = credentials.checkActivation(username, token);
  if (!checked.ok) {
    log.info('portal: an activation link was refused for "' + username +
             '" (' + checked.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.activate.refused',
      actor: username, outcome: 'failure',
      summary: 'an activation link was refused',
      detail: { reason: checked.reason, address: websecurity.addressOf(req) }
    });
    log.debug('Leaving GET ' + ACTIVATE + '. Refused.');
    return send(res, 400, page('Activation link',
      '<div class="card"><h1>Activation link</h1><div class="err">' +
      esc(ACTIVATION_REFUSAL) + '</div></div>'));
  }
  log.debug('Leaving GET ' + ACTIVATE + '. Drawing the setup form.');
  return send(res, 200, activationForm(baseUrlOf(req), username, token, null, null));
});

app.post(ACTIVATE, function (req, res) {
  log.debug('Entering POST ' + ACTIVATE + '.');
  // `parseBody()` and not `req.body`: this service parses every body as raw
  // text, so `checkParsed()` is the entry point. Its header argues why.
  const posted = validation.checkParsed(parseBody(req), 'body', ACTIVATE_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;
  const username = String(body.user || '').trim();
  const token = String(body.token || '');
  const base = baseUrlOf(req);

  const allowed = websecurity.attempt('activation', req, username);
  if (!allowed.ok) {
    log.debug('Leaving POST ' + ACTIVATE + '. Rate limited.');
    return send(res, 429, page('Too many attempts',
      '<div class="card"><h1>Too many attempts</h1><p>' +
      esc(allowed.detail) + '</p></div>'));
  }
  // **THE TOKEN IS CHECKED AGAIN ON THE POST**, and not merely on the GET that
  // drew the form. A form is markup; the door is here. A POST assembled by hand
  // never met the GET at all.
  const checked = credentials.checkActivation(username, token);
  if (!checked.ok) {
    log.info('portal: an activation POST was refused for "' + username +
             '" (' + checked.reason + ').');
    log.debug('Leaving POST ' + ACTIVATE + '. Refused.');
    return send(res, 400, page('Activation link',
      '<div class="card"><h1>Activation link</h1><div class="err">' +
      esc(ACTIVATION_REFUSAL) + '</div></div>'));
  }

  const password = String(body.password || '');
  const confirm = String(body.confirm || '');
  const keyRole = String(body.key_role || 'none');

  if (password && password !== confirm) {
    return send(res, 400, activationForm(base, username, token, null,
      'The two passwords do not match.'));
  }
  // **AT LEAST ONE WAY IN, AND THE COMBINATION THAT IS NOT ONE IS REFUSED
  // HERE.** A security key marked `mfa` is a SECOND factor — it is not a way to
  // sign in by itself — so choosing it with no password would finish the setup
  // with an account nobody can use, including its owner. That is the same
  // lockout `credentials.removeKey()` refuses to create, caught at the other
  // end of the same rule.
  if (!password && keyRole !== 'primary') {
    return send(res, 400, activationForm(base, username, token, null,
      keyRole === 'mfa'
        ? 'A security key used as a SECOND factor needs a password to be the ' +
          'first one. Set a password as well, or choose to use the key instead ' +
          'of a password.'
        : 'Set a password, or choose to use a security key instead of one. ' +
          'You need at least one way to sign in.'));
  }
  if (password) {
    const set = credentials.setPassword(username, password);
    if (!set.ok) {
      return send(res, 400, activationForm(base, username, token, null,
        (set.errors || ['The password could not be set.'])[0]));
    }
  }

  // **THE LINK IS SPENT HERE**, once the account really can be used. Spending
  // it earlier would strand somebody whose password was refused.
  credentials.consumeActivation(username);
  audit.record({
    category: 'authentication', action: 'portal.activate',
    actor: username, outcome: 'success',
    summary: username + ' completed account setup',
    detail: { password: !!password, keyRole: keyRole,
              address: websecurity.addressOf(req) }
  });
  log.info('portal: ' + username + ' completed account setup (' +
           (password ? 'password' : 'no password') + ', security key: ' +
           keyRole + '). The activation link is now spent.');

  // **THEY ARE SENT TO THE SIGN-IN SCREEN AND NOT SIGNED IN.** Spending an
  // activation link proves possession of a link, which is not the credential
  // they have just configured — and a link that both set up an account and
  // granted a session would be a standing bypass of every mechanism the person
  // chose. So the last step of setup is to use it.
  const next = keyRole === 'none'
    ? authn.LOGIN_PATH
    // A key still has to be enrolled, and enrolment is a ceremony the sign-in
    // screen owns. They sign in with what they just set and enrol from the
    // portal, which is the only order that works: enrolling a key requires
    // knowing who is asking, and until they sign in nobody does.
    : BASE;
  log.debug('Leaving POST ' + ACTIVATE + '. Set up; sending to sign in.');
  return send(res, 200, page('Account ready',
    '<div class="card"><h1>Your account is ready</h1>' +
    '<div class="ok">' +
    esc(password ? 'Your password is set.' : 'Your account is set up.') +
    ' This activation link has now been used and will not work again.</div>' +
    (keyRole !== 'none'
      ? '<p>You asked to use a security key' +
        (keyRole === 'mfa' ? ' as a second factor' : ' instead of a password') +
        '. Sign in first, then enrol it from your account page — enrolling a ' +
        'key requires this service to know who is asking.</p>'
      : '') +
    '<p><a href="' + esc(next) + '">Sign in</a></p></div>'));
});

// ---------------------------------------------------------------------------
// THE AUTHENTICATED PORTAL.
//
// **THE IDENTITY COMES FROM THE SESSION AND NOWHERE ELSE.** Not from a query
// parameter, not from a body field, not from a header. There is nothing here
// for anybody to change, which is the only version of OWASP A01 that survives
// somebody adding a page later without reading this comment.
// ---------------------------------------------------------------------------
function requireSignIn(req, res, returnTo, want) {
  const session = authn.sessionOf(req);
  if (session) {
    // -------------------------------------------------------------------
    // AND THE POLICY (2026-09-06). OWASP A01, decided by the PDP.
    //
    // **THE STRUCTURAL RULE STAYS AND THIS IS NOT AN ALTERNATIVE TO IT.**
    // Taking the identity from the session rather than the request is how a
    // TRUSTWORTHY subject is obtained; the policy is what decides about that
    // subject. Reading the id from the request would mean the PDP faithfully
    // deciding about whoever the caller nominated, which is the same
    // vulnerability one layer up.
    //
    // **THE OWNER IS THE SUBJECT, HERE AND TODAY.** Every route on this page
    // is about the signed-in person's own account, so the resource's owner IS
    // `session.user.username` — and the policy's owner arm is what permits it.
    // That looks circular and is the point: it is written as a comparison
    // between two attributes rather than as an equality buried in a handler,
    // so a deployment that wants a HELPDESK ROLE able to manage somebody
    // else's account adds a rule instead of changing this file. Until then the
    // owner and the subject are the same name and the answer is the same
    // answer.
    const answer = accessGate.check({
      resource: accessGate.RESOURCE.PORTAL,
      action: want || accessGate.ACTION.MANAGE_OWN,
      subject: { name: session.user.username,
                 authenticated: session.authenticated !== false,
                 sessionId: session.id },
      owner: session.user.username,
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (!answer.allowed) {
      log.info('portal: the access policy refused ' + req.method + ' ' +
               (req.originalUrl || req.url) + ' for ' +
               session.user.username + '. ' + answer.why);
      send(res, 403, page('Not permitted',
        '<div class="card"><h1>Not permitted</h1>' +
        '<div class="err">' + esc(answer.why) + '</div>' +
        '<p class="note">This is a policy decision rather than a missing ' +
        'sign-in. You are signed in as <strong>' +
        esc(session.user.username) + '</strong>.</p></div>'));
      return null;
    }
    return session;
  }
  // ---------------------------------------------------------------------
  // **THROUGH `beginAuthentication()` AND NOT A BARE REDIRECT TO THE LOGIN
  // PATH**, which is what this did at first and what does not work.
  //
  // `/authn/login` is not a page somebody can simply be sent to: it draws a
  // form for a PENDING AUTHENTICATION RECORD, and a POST that names no record
  // is answered `This sign-in form has expired`. Every other flow here enters
  // it the same way — `saml2_sso.js`, `consent_screen.js`, `wsfed.js` — by
  // asking this function for the address to send the browser to, and the
  // portal is no different from them in this respect even though it is not a
  // protocol.
  //
  // `returnTo` is a path on THIS service, which is what that function requires
  // and refuses anything else, so the portal cannot be used as an open
  // redirect by asking it to send somebody somewhere after signing in.
  // ---------------------------------------------------------------------
  const where = authn.beginAuthentication({
    returnTo: returnTo || BASE,
    protocol: 'User Portal',
    // NO `application`. The portal is not one — nobody registered it, it
    // issues no token, and naming one here would put a fictional entry in the
    // application registry and hand it to the role gate as the thing being
    // authenticated to.
    details: [['Where', 'the User Portal — a person\'s own account']]
  });
  res.status(303).set('Location', where).end();
  return null;
}

function portalPage(req, session, message, error) {
  const username = session.user.username;
  const mechanisms = credentials.mechanismsFor(username);
  const csrf = websecurity.field(session.id);
  const detail = stats.userDetail ? stats.userDetail(username) : null;
  const keys = mechanisms.keys;

  return page('Your account',
    '<div class="card">' +
    '<h1>Your account</h1>' +
    '<p class="sub">What this identity provider knows about you, and how you ' +
    'sign in.</p>' +
    (error ? '<div class="err">' + esc(error) + '</div>' : '') +
    (message ? '<div class="ok">' + esc(message) + '</div>' : '') +
    '<table>' +
    '<tr><th>Username</th><td>' + esc(username) + '</td></tr>' +
    '<tr><th>Subject</th><td><code>' + esc(session.user.sub || '') +
      '</code></td></tr>' +
    (session.user.email
      ? '<tr><th>Email</th><td>' + esc(session.user.email) + '</td></tr>' : '') +
    (session.user.name
      ? '<tr><th>Name</th><td>' + esc(session.user.name) + '</td></tr>' : '') +
    '<tr><th>Signed in</th><td>' +
      esc(new Date((session.authTime || 0) * 1000).toISOString()) + '</td></tr>' +
    '<tr><th>How</th><td>' + esc((session.amr || []).join(', ') || 'unstated') +
      ' (acr ' + esc(session.acr || '') + ')</td></tr>' +
    '<tr><th>This session ends</th><td>' +
      esc(new Date(session.expires || 0).toISOString()) + '</td></tr>' +
    (detail
      ? '<tr><th>Times you have signed in</th><td>' +
        esc(String(detail.authentications || 0)) + '</td></tr>'
      : '') +
    '</table>' +
    '</div>' +

    '<div class="card">' +
    '<h2>How you sign in</h2>' +
    '<table>' +
    '<tr><th>Password</th><td>' +
      (mechanisms.password ? 'set' : '<em>none set</em>') + '</td></tr>' +
    '<tr><th>Security keys</th><td>' +
      (keys.length
        ? esc(String(keys.length)) + ' enrolled'
        : '<em>none enrolled</em>') + '</td></tr>' +
    '<tr><th>Second factor</th><td>' +
      (mechanisms.mfaRequired
        ? 'required — you hold a key marked as a second factor'
        : 'not required') + '</td></tr>' +
    '</table>' +
    (keys.length
      ? '<table><tr><th>Key</th><th>Role</th><th>Enrolled</th><th></th></tr>' +
        keys.map(function (one) {
          return '<tr><td>' + esc(one.label || 'security key') + '</td>' +
            '<td>' + esc(one.role) + '</td>' +
            '<td>' + esc(new Date(one.enrolledAt || 0).toISOString().slice(0, 10)) +
            '</td><td>' +
            '<form method="post" action="' + BASE + '/remove-key">' + csrf +
            '<input type="hidden" name="credentialId" value="' +
            esc(one.credentialId) + '">' +
            '<button class="danger">Remove</button></form></td></tr>';
        }).join('') + '</table>'
      : '') +
    '<p class="note">A security key is either your ONLY credential (you sign ' +
    'in with the key and no password) or a SECOND factor beside a password. ' +
    'This service supports no other second factor. You cannot remove your last ' +
    'way in — set another one first.</p>' +
    '</div>' +

    '<div class="card">' +
    '<h2>Change your password</h2>' +
    '<form method="post" action="' + BASE + '/password">' + csrf +
    '<label for="current">Your current password</label>' +
    '<input type="password" id="current" name="current" autocomplete="current-password">' +
    '<label for="next">New password</label>' +
    '<input type="password" id="next" name="next" autocomplete="new-password">' +
    '<label for="confirm">Confirm it</label>' +
    '<input type="password" id="confirm" name="confirm" autocomplete="new-password">' +
    '<button type="submit">Change password</button>' +
    '</form>' +
    '<p class="note">Your current password is required even though you are ' +
    'already signed in: a session somebody left open on a shared machine must ' +
    'not be enough to take the account over.</p>' +
    '</div>' +

    '<div class="card">' +
    '<h2>Sign out</h2>' +
    '<form method="post" action="/logout">' + csrf +
    '<button class="secondary">Sign out of everything</button></form>' +
    '<p class="note">Ends every session you hold here, in every protocol, and ' +
    'tells the applications that can be told.</p>' +
    '</div>');
}

app.get(BASE, function (req, res) {
  log.debug('Entering GET ' + BASE + '.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.READ);
  if (!session) {
    log.debug('Leaving GET ' + BASE + '. Not signed in, or not permitted.');
    return undefined;
  }
  const asked = validation.check(req, 'query', PORTAL_QUERY);
  if (!asked.ok) {
    return refuseShape(res, asked);
  }
  log.debug('Leaving GET ' + BASE + '. Drawn for ' + session.user.username + '.');
  return send(res, 200, portalPage(req, session,
    asked.value.done ? String(asked.value.done) : null, null));
});

// ---------------------------------------------------------------------------
// CHANGING A PASSWORD. Four controls in one handler, and each is a different
// item on the list.
//
//   CSRF          the token this session's forms carry            (A01/A08)
//   RATE LIMIT    so the current-password check is not an oracle  (A04/A07)
//   RE-AUTH       the current password, even though signed in     (A07)
//   SESSION       the identity from the session, never the body   (A01)
// ---------------------------------------------------------------------------
app.post(BASE + '/password', function (req, res) {
  log.debug('Entering POST ' + BASE + '/password.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.MANAGE_OWN);
  if (!session) return undefined;
  const username = session.user.username;
  const posted = validation.checkParsed(parseBody(req), 'body', PASSWORD_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;

  const csrf = websecurity.checkCsrf(session.id, body);
  if (!csrf.ok) {
    log.warn('portal: a password change for ' + username + ' was refused on ' +
             'CSRF (' + csrf.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.password.csrf',
      actor: username, outcome: 'failure',
      summary: 'a password change was refused: ' + csrf.reason,
      detail: { address: websecurity.addressOf(req) }
    });
    log.debug('Leaving POST ' + BASE + '/password. CSRF.');
    return send(res, 403, portalPage(req, session, null, csrf.detail));
  }

  const allowed = websecurity.attempt('password-change', req, username);
  if (!allowed.ok) {
    log.debug('Leaving POST ' + BASE + '/password. Rate limited.');
    return send(res, 429, portalPage(req, session, null, allowed.detail));
  }

  const current = String(body.current || '');
  const next = String(body.next || '');
  const confirm = String(body.confirm || '');

  // **RE-AUTHENTICATION.** A live session is not enough to change the
  // credential that session was created with — otherwise a browser left open
  // on a shared machine is an account takeover with no credential needed.
  //
  // In DEVELOPMENT mode `verify()` accepts anything, so this is a formality
  // there — which is correct: development checks no password anywhere, and a
  // portal that was the one exception would be a surprise rather than a
  // control.
  const checked = credentials.verify(username, current,
                                     { via: 'the portal password change' });
  if (!checked.ok) {
    log.info('portal: a password change for ' + username + ' was refused (' +
             checked.reason + ').');
    audit.record({
      category: 'authentication', action: 'portal.password.refused',
      actor: username, outcome: 'failure',
      summary: 'a password change was refused',
      detail: { reason: checked.reason, address: websecurity.addressOf(req) }
    });
    log.debug('Leaving POST ' + BASE + '/password. Wrong current password.');
    return send(res, 400, portalPage(req, session, null,
      'Your current password is not right.'));
  }
  if (!next || next !== confirm) {
    return send(res, 400, portalPage(req, session, null,
      next ? 'The two new passwords do not match.' : 'Give a new password.'));
  }
  const set = credentials.setPassword(username, next);
  if (!set.ok) {
    return send(res, 400, portalPage(req, session, null,
      (set.errors || ['The password could not be changed.'])[0]));
  }
  websecurity.succeeded('password-change', req, username);
  audit.record({
    category: 'authentication', action: 'portal.password.changed',
    actor: username, outcome: 'success',
    summary: username + ' changed their own password',
    detail: { address: websecurity.addressOf(req) }
  });
  log.info('portal: ' + username + ' changed their own password.');
  log.debug('Leaving POST ' + BASE + '/password. Changed.');
  res.status(303).set('Location', BASE + '?done=' +
    encodeURIComponent('Your password is changed.')).end();
  return undefined;
});

app.post(BASE + '/remove-key', function (req, res) {
  log.debug('Entering POST ' + BASE + '/remove-key.');
  const session = requireSignIn(req, res, BASE, accessGate.ACTION.MANAGE_OWN);
  if (!session) return undefined;
  const username = session.user.username;
  const posted = validation.checkParsed(parseBody(req), 'body', REMOVE_KEY_FORM);
  if (!posted.ok) {
    return refuseShape(res, posted);
  }
  const body = posted.value;

  const csrf = websecurity.checkCsrf(session.id, body);
  if (!csrf.ok) {
    log.debug('Leaving POST ' + BASE + '/remove-key. CSRF.');
    return send(res, 403, portalPage(req, session, null, csrf.detail));
  }
  // THE CREDENTIAL ID COMES FROM THE BODY AND THE USERNAME DOES NOT, which is
  // the distinction that keeps this safe: `removeKey()` looks the id up among
  // THIS PERSON'S keys, so an id belonging to somebody else matches nothing.
  // An implementation that took both from the request would be the A01
  // vulnerability this file exists to avoid.
  const removed = credentials.removeKey(username,
                                        String(body.credentialId || ''));
  if (!removed.ok) {
    log.debug('Leaving POST ' + BASE + '/remove-key. Refused.');
    return send(res, 400, portalPage(req, session, null,
      (removed.errors || ['The key could not be removed.'])[0]));
  }
  audit.record({
    category: 'authentication', action: 'portal.key.removed',
    actor: username, outcome: 'success',
    summary: username + ' removed one of their security keys',
    detail: { remaining: removed.remaining,
              address: websecurity.addressOf(req) }
  });
  log.debug('Leaving POST ' + BASE + '/remove-key. Removed.');
  res.status(303).set('Location', BASE + '?done=' +
    encodeURIComponent('That security key is removed.')).end();
  return undefined;
});

log.info('The User Portal is at ' + BASE + ': a person\'s own account — what ' +
         'this identity provider knows about them, their password and their ' +
         'security keys. ' + ACTIVATE + ' is the unauthenticated half, where ' +
         'somebody provisioned through /admin-api or SCIM spends a single-use ' +
         'activation link to set up a credential. Every form carries a CSRF ' +
         'token, every credential endpoint is rate limited, and no route here ' +
         'takes an identity from the request.');

module.exports = {
  BASE: BASE,
  ACTIVATE: ACTIVATE,
  // For sts_metadata.js and the tests.
  paths: function () { return [BASE, ACTIVATE, BASE + '/password',
                               BASE + '/remove-key']; }
};
