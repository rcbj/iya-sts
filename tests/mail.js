'use strict';
//
// File: mail.js
//
// ===========================================================================
// THE MAIL CHANNEL (#63, 2026-09-22), in process.
//
// `common/mail.ts`, `mail_transports.ts`, `mail_uses.ts` and
// `mail_templates.ts` argue the design. What is held here, in the order the
// issue's "Tests" section lists it and then the rest:
//
//   1. TEMPLATES: a value is HTML-escaped in the HTML part and loses its line
//      breaks in the subject and the text part; a realm's template that
//      writes an address, loads anything, runs anything, names an unknown
//      placeholder or leaves a link out of its text part is refused; a link
//      value is this service's origin and a path, and a caller's absolute
//      URL renders empty; the language order of RFC 2798's
//      preferredLanguage.
//   2. RECIPIENTS COME FROM THE DIRECTORY ONLY: an address in the request is
//      ignored; nobody, no address, a malformed address — each refused with
//      its code.
//   3. SECURITY NOTICES CANNOT BE DECLINED, and a declined optional category
//      is.
//   4. THE RATE CEILING, per recipient and per category, and duplicate
//      suppression.
//   5. THE OUTBOX CLAIM SENDS ONCE across two "nodes" (two instances over one
//      store and one claim table), a lapsed lease is taken over under the
//      same attempt number, and the outcome of a fenced-out sender is not
//      written.
//   6. RETRY, BACKOFF, DEAD LETTERS AND THE BODY: a transient failure is
//      retried and then dead-lettered; a permanent one is dead at once; a
//      dead letter is retried by hand; a sent message keeps no body and a
//      captured one keeps it.
//   7. THE MODE: capture in development, off in product; capture refused on
//      write (STS-MAIL-0003) and at start in product; a configured transport
//      that cannot be built stops a product service (STS-MAIL-0002); no
//      mailed link without global.publicBaseUrl in product.
//   8. THE CLOUD TRANSPORTS WITH STUBBED CLIENTS: SES v2's raw payload and
//      configuration set; Azure's structured payload, managed identity and
//      a Failed operation; the Gmail API's delegated JWT and base64url raw;
//      the retry classification of each; a missing SDK.
//   9. THE SMTP TRANSPORT AGAINST A REAL SMTP SERVER in this process
//      (smtp-server), over STARTTLS with a CA made here: delivered with SMTP
//      AUTH read from a secret file and a DKIM signature that verifies; a
//      server offering no STARTTLS is refused (nothing in the clear); an
//      untrusted certificate is refused; a 5xx is permanent and a 4xx is
//      retried.
//  10. DKIM against nodemailer's own independent signer: its signature
//      verifies with ours and the two body hashes agree; Ed25519.
//  11. THE USES: address verification end to end (a link, spent once, bound
//      to the address), the forgot-password request (the one answer
//      whatever happened, the verified-address rule, RISC
//      recovery-activated), an administrator's link mailed, and the notices
//      the account signals hand over.
//  12. REALMS: a realm's transport overrides the service's, and one realm's
//      outbox is not another's.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'mail',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// A directory of people for the channel's slot: username → attributes.
function stubDirectory(people) {
  log.debug('Entering stubDirectory().');
  const flags = {};
  log.debug('Leaving stubDirectory().');
  return {
    people: people,
    flags: flags,
    personEntry: function (u) {
      if (!people[u]) {
        return null;
      }
      return { dn: 'uid=' + u,
               attributes: Object.assign({}, people[u], flags[u] || {}) };
    },
    personByMail: function (address) {
      const wanted = String(address || '').toLowerCase();
      return Object.keys(people).filter(function (u) {
        return String((people[u].mail || [])[0] || '').toLowerCase() ===
               wanted;
      })[0] || '';
    },
    writeMailFlag: function (u, name, value) {
      flags[u] = flags[u] || {};
      if (value) {
        flags[u][name.toLowerCase()] = [String(value)];
      } else {
        delete flags[u][name.toLowerCase()];
      }
      return true;
    }
  };
}

// A transport factory whose `send()` does what `behave` says, counting.
function stubTransports(behave) {
  log.debug('Entering stubTransports().');
  const sent = [];
  log.debug('Leaving stubTransports().');
  return {
    sent: sent,
    build: function (cfg) {
      return Promise.resolve({
        name: cfg.transport === 'capture' ? 'capture' : 'stub',
        send: function (message) {
          sent.push(message);
          return Promise.resolve(behave ? behave(message, sent.length)
                                        : { providerId: 'p' + sent.length });
        },
        close: function () {
          return undefined;
        }
      });
    }
  };
}

function withRealm(t, realms, id, overrides, fn) {
  log.debug('Entering withRealm(). ' + id);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return Promise.resolve();
  }
  log.debug('Leaving withRealm().');
  return Promise.resolve(realms.run(made.realm, function () {
    return fn(made.realm);
  })).finally(function () {
    realms.remove(id);
  });
}

// A realm id that no other run of this file uses at the same moment.
function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + nodeCrypto.randomBytes(3).toString('hex');
}

// ---------------------------------------------------------------------------
// 1. TEMPLATES
// ---------------------------------------------------------------------------
function templates(t) {
  log.debug('Entering templates().');
  const MailTemplates = require('../common/mail_templates');
  const spec = MailTemplates.builtIn('password-reset');
  const out = MailTemplates.render(spec, {
    username: '<b>eve</b>\r\nBcc: victim@example.com',
    requestedBy: 'x', expiresMinutes: '60', service: 'svc',
    link: 'https://idp.example/portal/reset-password?user=a&token=b' });
  t.check(out.html.indexOf('&lt;b&gt;eve&lt;/b&gt;') >= 0 &&
          out.html.indexOf('<b>eve') < 0,
          '1a. a value is HTML-escaped in the HTML part', out.html);
  t.check(!/\r|\n/.test(out.subject) &&
          out.text.indexOf('\r\nBcc:') < 0 && out.text.indexOf('\nBcc:') < 0,
          '1b. a value loses its line breaks in the subject and the text ' +
          'part (no header injection)', out.text);
  t.check(out.html.indexOf('href="https://idp.example/portal/reset-password' +
                           '?user=a&amp;token=b"') >= 0,
          '1c. a link is escaped as an attribute value', out.html);
  const refused = [
    [{ subject: 's', text: 'go to https://evil.example {{link}}',
       html: '<a href="{{link}}">x</a>' }, 'an address of its own'],
    [{ subject: 's', text: 'x {{link}}',
       html: '<a href="{{link}}">x</a><img src="{{link}}">' }, 'an image'],
    [{ subject: 's', text: 'x {{link}}',
       html: '<p style="background:url(x)">{{link}}</p>' }, 'a CSS url'],
    [{ subject: 's', text: 'x {{link}}',
       html: '<a href="{{link}}" onclick="x()">x</a>' }, 'an event handler'],
    [{ subject: 's', text: 'x {{link}}', html: '<script>x</script>' },
     'a script'],
    [{ subject: 's', text: 'x {{link}} {{password}}',
       html: '<a href="{{link}}">x</a>' }, 'an unknown placeholder'],
    [{ subject: 's', text: 'no link here',
       html: '<a href="{{link}}">x</a>' }, 'no link in the text part'],
    [{ subject: 's', text: 'x {{link}}', html: '<a href="/elsewhere">x</a>' },
     'an href that is not a link placeholder'],
    [{ subject: 'two\nlines', text: 'x {{link}}',
       html: '<a href="{{link}}">x</a>' }, 'a two-line subject'],
    [{ subject: 's', text: 'x {{link}}',
       html: '<a href="javascript:alert(1)">{{link}}</a>' },
     'a javascript: URI']
  ];
  refused.forEach(function (one, i) {
    t.check(!!MailTemplates.problem(spec, one[0]),
            '1d' + i + '. a template with ' + one[1] + ' is refused',
            JSON.stringify(one[0]));
  });
  t.check(MailTemplates.problem(spec, { subject: 'Passwort',
    text: 'Link: {{link}} ({{expiresMinutes}})',
    html: '<p><a href="{{link}}">Neues Passwort</a></p>' }) === '',
          '1e. a template that keeps the rules is accepted');
  t.equal(MailTemplates.languageOrder('de-CH, fr;q=0.9, en;q=0.1', 'es')
            .join(','), 'de-ch,de,fr,en,es',
          '1f. preferredLanguage is read as an Accept-Language value, ' +
          'then the realm default, then en');
  log.debug('Leaving templates().');
}

// ---------------------------------------------------------------------------
// A Mail instance over a stub directory and stub transports, in the ambient
// realm, with the real outbox store.
// ---------------------------------------------------------------------------
function makeMail(overrides) {
  log.debug('Entering makeMail().');
  const mailModule = require('../common/mail');
  const deps = Object.assign(mailModule.Mail.defaultDeps(), overrides || {});
  log.debug('Leaving makeMail().');
  return new mailModule.Mail(deps);
}

async function recipients(t) {
  log.debug('Entering recipients().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  const dir = stubDirectory({
    alice: { mail: ['alice@example.com'] },
    bob: {},
    mal: { mail: ['a@b@c, evil@example.com'] }
  });
  mailModule.setDirectory(dir);
  await withRealm(t, realms, realmId('mail-rcpt'), {}, async function () {
    const transports = stubTransports();
    const m = makeMail({ transports: transports });
    const r = m.send({ username: 'alice', template: 'password-changed',
                       to: 'attacker@evil.example',
                       values: { how: 'x', to: 'attacker@evil.example' } });
    await r.delivered;
    t.check(r.ok && r.queued[0].to === 'alice@example.com' &&
            transports.sent[0].to === 'alice@example.com',
            '2a. an address in the request is ignored: the message goes to ' +
            'the entry\'s mail', JSON.stringify(r.queued[0]));
    const nobody = m.send({ username: 'carol', template: 'password-changed' });
    t.check(!nobody.ok && nobody.refused[0].code === 'STS-MAIL-0012',
            '2b. nobody in the directory: refused STS-MAIL-0012',
            JSON.stringify(nobody));
    const noMail = m.send({ username: 'bob', template: 'password-changed' });
    t.check(!noMail.ok && noMail.refused[0].code === 'STS-MAIL-0011',
            '2c. an entry with no mail: refused STS-MAIL-0011',
            JSON.stringify(noMail));
    const bad = m.send({ username: 'mal', template: 'password-changed' });
    t.check(!bad.ok && bad.refused[0].code === 'STS-MAIL-0023',
            '2d. a mail attribute that is two addresses: refused ' +
            'STS-MAIL-0023', JSON.stringify(bad));
    const unknown = m.send({ username: 'alice', template: 'no-such' });
    t.check(!unknown.ok && unknown.refused[0].code === 'STS-MAIL-0017',
            '2e. an unknown message: refused STS-MAIL-0017');
    // 3. SECURITY NOTICES CANNOT BE DECLINED.
    const declineSecurity = m.setDeclined('alice', 'security', true);
    t.check(!declineSecurity.ok &&
            require('../common/error_codes').codeOf(declineSecurity) ===
            'STS-MAIL-0034',
            '3a. declining security notices is refused (STS-MAIL-0034)',
            JSON.stringify(declineSecurity));
    const declineAccount = m.setDeclined('alice', 'account', true);
    t.check(!declineAccount.ok,
            '3b. declining requested links is refused');
    const declineNote = m.setDeclined('alice', 'notification', true);
    t.check(declineNote.ok && m.declined('alice').indexOf('notification') >= 0,
            '3c. declining notifications is recorded');
    const stillSent = m.send({ username: 'alice',
                               template: 'account-disabled' });
    t.check(stillSent.ok,
            '3d. a security notice still goes to a person who declined ' +
            'notifications');
    await stillSent.delivered;
  });
  log.debug('Leaving recipients().');
}

// ---------------------------------------------------------------------------
// 4. THE CEILING AND DUPLICATES
// ---------------------------------------------------------------------------
async function ceilings(t) {
  log.debug('Entering ceilings().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  mailModule.setDirectory(stubDirectory({
    dana: { mail: ['dana@example.com'] } }));
  await withRealm(t, realms, realmId('mail-rate'),
                  { 'mail.ratePerCategory': 3, 'mail.ratePerRecipient': 4 },
                  async function () {
    const m = makeMail({ transports: stubTransports() });
    const codes = [];
    for (let i = 0; i < 5; i++) {
      const r = m.send({ username: 'dana', template: 'password-changed' });
      codes.push(r.ok ? 'ok' : r.refused[0].code);
    }
    t.equal(codes.join(','),
            'ok,ok,ok,STS-MAIL-0010,STS-MAIL-0010',
            '4a. the per-category ceiling: three security messages, then ' +
            'refused STS-MAIL-0010');
    const other = m.send({ username: 'dana', template: 'test-message' });
    const over = m.send({ username: 'dana', template: 'test-message' });
    t.check(other.ok && !over.ok && over.refused[0].code === 'STS-MAIL-0010',
            '4b. the per-recipient ceiling counts every category (four in ' +
            'all)', JSON.stringify([other.ok, over.refused]));
  });
  await withRealm(t, realms, realmId('mail-dedup'), {}, async function () {
    const m = makeMail({ transports: stubTransports() });
    const first = m.send({ username: 'dana', template: 'sessions-ended',
                           dedupKey: 'act-1' });
    const again = m.send({ username: 'dana', template: 'sessions-ended',
                           dedupKey: 'act-1' });
    const different = m.send({ username: 'dana', template: 'sessions-ended',
                               dedupKey: 'act-2' });
    t.check(first.queued.length === 1 && again.queued.length === 0 &&
            again.duplicates.length === 1 && again.ok &&
            different.queued.length === 1,
            '4c. one message per act in mail.dedupWindowS; another act is ' +
            'another message');
  });
  log.debug('Leaving ceilings().');
}

// ---------------------------------------------------------------------------
// 5. ONCE ACROSS TWO NODES, AND A LAPSED LEASE
// ---------------------------------------------------------------------------
async function twoNodes(t) {
  log.debug('Entering twoNodes().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  mailModule.setDirectory(stubDirectory({
    erin: { mail: ['erin@example.com'] } }));
  await withRealm(t, realms, realmId('mail-nodes'),
                  { 'mail.transport': 'smtp' }, async function (realm) {
    const transports = stubTransports();
    // Queued by a node that does not attempt it (its attempt is swallowed
    // by a claim store that says "used"), then two nodes race.
    const quiet = makeMail({ transports: transports,
      claims: { claim: function () {
        return Promise.resolve({ ok: false, reason: 'used' });
      } } });
    const r = quiet.send({ username: 'erin', template: 'test-message' });
    await r.delivered;
    const id = r.queued[0].id;
    const a = makeMail({ transports: transports });
    const b = makeMail({ transports: transports });
    const results = await Promise.all([a.attempt(realm.id, id),
                                       b.attempt(realm.id, id)]);
    t.check(transports.sent.length === 1 &&
            results.sort().join(',') === 'claimed-elsewhere,sent',
            '5a. two nodes attempting one message: exactly one sends',
            JSON.stringify(results) + ' sent=' + transports.sent.length);
    // A LAPSED LEASE: a claim table with a clock of the test's own.
    let clock = Date.now();
    const table = {};
    const claims = { claim: function (o) {
      const key = o.scope + '|' + o.value;
      const held = table[key];
      if (held && held.until > clock) {
        return Promise.resolve({ ok: false, reason: 'used' });
      }
      table[key] = { until: clock + o.ttlMs };
      return Promise.resolve({ ok: true, claimedAt: clock });
    } };
    let release = null;
    const hanging = { build: function () {
      return Promise.resolve({ name: 'stub', close: function () {
        return undefined;
      }, send: function () {
        return new Promise(function (resolve) {
          release = resolve;
        });
      } });
    } };
    const counted = stubTransports();
    const now = function () {
      return clock;
    };
    const r2 = quiet.send({ username: 'erin', template: 'test-message' });
    await r2.delivered;
    const dying = makeMail({ transports: hanging, claims: claims, now: now });
    const heir = makeMail({ transports: counted, claims: claims, now: now });
    const stalled = dying.attempt(realm.id, r2.queued[0].id);
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
    t.equal(await heir.attempt(realm.id, r2.queued[0].id), 'not-due',
            '5b. while the lease holds, another node does not send');
    clock += dying.leaseMs() + 1000;
    const taken = await heir.attempt(realm.id, r2.queued[0].id);
    t.check(taken === 'sent' && counted.sent.length === 1,
            '5c. after the lease lapses, another node takes over the same ' +
            'attempt and sends', taken);
    release({ providerId: 'late' });
    t.equal(await stalled, 'claimed-elsewhere',
            '5d. the stalled node\'s late outcome is fenced out and not ' +
            'written');
    const row = heir.list({ q: r2.queued[0].id }).filter(function (x) {
      return x.id === r2.queued[0].id;
    })[0] || heir.list()[0];
    t.check(row && row.state === 'sent' && row.attempts === 1,
            '5e. the row records one attempt, sent', JSON.stringify(row));
  });
  log.debug('Leaving twoNodes().');
}

// ---------------------------------------------------------------------------
// 6. RETRY, DEAD LETTERS, BODIES
// ---------------------------------------------------------------------------
async function retries(t) {
  log.debug('Entering retries().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  const transportsModule = require('../common/mail_transports');
  mailModule.setDirectory(stubDirectory({
    fay: { mail: ['fay@example.com'] } }));
  await withRealm(t, realms, realmId('mail-retry'),
                  { 'mail.attempts': 2, 'mail.backoffS': 1,
                    'mail.transport': 'smtp' },
                  async function (realm) {
    let clock = Date.now();
    const now = function () {
      return clock;
    };
    let fail = true;
    const flaky = stubTransports(function () {
      if (fail) {
        throw transportsModule.sendError('the relay deferred it (421)',
                                         'STS-MAIL-0009', true);
      }
      return { providerId: 'ok' };
    });
    const m = makeMail({ transports: flaky, now: now });
    const r = m.send({ username: 'fay', template: 'test-message' });
    await r.delivered;
    const id = r.queued[0].id;
    let row = m.list().filter(function (x) {
      return x.id === id;
    })[0];
    t.check(row.state === 'pending' && row.errorCode === 'STS-MAIL-0009',
            '6a. a transient failure leaves the message pending, coded, ' +
            'with a backoff', JSON.stringify(row));
    clock += 1500;
    t.equal(await m.attempt(realm.id, id), 'dead',
            '6b. the last attempt that fails dead-letters it');
    fail = false;
    const refusedRetry = m.retry('nope', 'tester');
    t.check(!refusedRetry.ok, '6c. a retry of an unknown message is refused');
    const again = m.retry(id, 'tester');
    t.check(again.ok, '6d. a dead letter is retried by hand');
    await new Promise(function (resolve) {
      setTimeout(resolve, 20);
    });
    row = m.list().filter(function (x) {
      return x.id === id;
    })[0];
    t.check(row.state === 'sent' && row.generation === 2,
            '6e. the retry is a new generation, and sent',
            JSON.stringify(row));
    const kept = mailModule.message(id);
    t.check(kept && kept.text === undefined && kept.html === undefined,
            '6f. a sent message keeps no body');
    const permanent = stubTransports(function () {
      throw transportsModule.sendError('550 no such user', 'STS-MAIL-0008',
                                       false);
    });
    const p = makeMail({ transports: permanent, now: now });
    const r2 = p.send({ username: 'fay', template: 'test-message' });
    await r2.delivered;
    const dead = p.list().filter(function (x) {
      return x.id === r2.queued[0].id;
    })[0];
    t.check(dead.state === 'dead' && dead.attempts === 1 &&
            dead.errorCode === 'STS-MAIL-0008',
            '6g. a permanent refusal is dead at the first attempt',
            JSON.stringify(dead));
  });
  await withRealm(t, realms, realmId('mail-capture'), {},
                  async function () {
    const m = makeMail({ transports: stubTransports() });
    const r = m.send({ username: 'fay', template: 'test-message' });
    await r.delivered;
    const got = mailModule.message(r.queued[0].id);
    t.check(got && got.state === 'captured' && /test message/.test(got.text),
            '6h. development\'s default transport CAPTURES, keeping the body',
            JSON.stringify(got));
  });
  log.debug('Leaving retries().');
}

// ---------------------------------------------------------------------------
// 7. THE MODE
// ---------------------------------------------------------------------------
async function modes(t) {
  log.debug('Entering modes().');
  const realms = require('../common/realms');
  const config = require('../common/config');
  const mode = require('../common/mode');
  const mailModule = require('../common/mail');
  mailModule.setDirectory(stubDirectory({
    gus: { mail: ['gus@example.com'] } }));
  t.check(mode.capturesMail() && mode.mailsLinksFromListenerAddress(),
          '7a. development captures and may build a link on the listener');
  t.check(mode.report().requirements.some(function (r) {
    return r.id === 'mail';
  }), '7b. /admin/mode describes the mail requirement');
  await withRealm(t, realms, realmId('mail-prod'),
                  { 'global.mode': 'product' }, async function () {
    t.check(!mode.capturesMail() && !mode.mailsLinksFromListenerAddress(),
            '7c. product neither captures nor builds an unpinned link');
    const m = makeMail({ transports: stubTransports() });
    t.equal(m.effectiveTransport(), 'off', '7d. product\'s default is off');
    const off = m.send({ username: 'gus', template: 'test-message' });
    t.check(!off.ok && off.refused[0].code === 'STS-MAIL-0001',
            '7e. with no transport a message is refused STS-MAIL-0001');
    t.equal(config.checkWriteCode('mail.transport', 'capture'),
            'STS-MAIL-0003',
            '7f. capture is refused on write in product (STS-MAIL-0003)');
    t.equal(m.linkBase(), '', '7g. product has no link base without ' +
            'global.publicBaseUrl');
  });
  await withRealm(t, realms, realmId('mail-prod-smtp'),
                  { 'global.mode': 'product', 'mail.transport': 'smtp' },
                  async function (realm) {
    const m = makeMail({ transports: stubTransports() });
    const linkless = m.send({ username: 'gus', template: 'password-reset',
      links: { link: '/portal/reset-password?user=gus&token=t' } });
    t.check(!linkless.ok && linkless.refused[0].code === 'STS-MAIL-0015',
            '7h. a message with a link is refused STS-MAIL-0015 until ' +
            'global.publicBaseUrl is set', JSON.stringify(linkless));
    // THE STARTUP CHECK, with the real transports: SMTP with no host.
    const real = makeMail({});
    const problem = await real.startupProblem();
    t.check(/STS-MAIL-0002/.test(problem) && problem.indexOf(realm.id) >= 0,
            '7i. a product realm whose SMTP transport cannot be built stops ' +
            'the service (STS-MAIL-0002)', problem);
  });
  await withRealm(t, realms, realmId('mail-prod-pinned'),
                  { 'global.mode': 'product', 'mail.transport': 'smtp',
                    'global.publicBaseUrl': 'https://idp.example' },
                  async function (realm) {
    const transports = stubTransports();
    const m = makeMail({ transports: transports });
    const r = m.send({ username: 'gus', template: 'password-reset',
      links: { link: '/portal/reset-password?user=gus&token=t' },
      values: { username: 'gus', requestedBy: 'x', expiresMinutes: '1' } });
    await r.delivered;
    t.check(r.ok && transports.sent[0] && transports.sent[0].text.indexOf(
      'https://idp.example/realm/' + realm.id +
      '/portal/reset-password?user=gus&token=t') >= 0,
            '7j. a mailed link is global.publicBaseUrl, the realm\'s prefix ' +
            'and the path', transports.sent[0] && transports.sent[0].text);
    const hostile = m.send({ username: 'gus', template: 'password-reset',
      links: { link: 'https://evil.example/steal' },
      values: { username: 'gus', requestedBy: 'x', expiresMinutes: '1' } });
    await hostile.delivered;
    t.check(transports.sent[1] &&
            transports.sent[1].text.indexOf('evil.example') < 0,
            '7k. a caller\'s absolute URL is not a link: it renders empty');
  });
  log.debug('Leaving modes().');
}

// ---------------------------------------------------------------------------
// 8. THE CLOUD TRANSPORTS, STUBBED
// ---------------------------------------------------------------------------
async function cloud(t) {
  log.debug('Entering cloud().');
  const tm = require('../common/mail_transports');
  const errorCodes = require('../common/error_codes');
  const message = { from: 'no-reply@example.com', fromName: 'IdP',
    to: 'hal@example.com', subject: 'Hello', text: 'text part\n',
    html: '<p>html part</p>', messageId: '<m1@example.com>',
    date: new Date(), lang: 'en' };
  const calls = {};
  const sdks = {
    '@aws-sdk/client-sesv2': {
      SESv2Client: function (opts) {
        calls.sesClient = opts;
        this.send = function (cmd) {
          calls.ses = cmd.input;
          if (calls.sesThrow) {
            return Promise.reject(calls.sesThrow);
          }
          return Promise.resolve({ MessageId: 'ses-1' });
        };
      },
      SendEmailCommand: function (input) {
        this.input = input;
      }
    },
    '@azure/communication-email': {
      EmailClient: function (a, b) {
        calls.acsClient = [a, b];
        this.beginSend = function (payload) {
          calls.acs = payload;
          return Promise.resolve({ pollUntilDone: function () {
            return Promise.resolve(calls.acsResult ||
                                   { status: 'Succeeded', id: 'acs-1' });
          } });
        };
      }
    },
    '@azure/identity': {
      DefaultAzureCredential: function () {
        calls.azureCredential = true;
      }
    },
    '@googleapis/gmail': {
      auth: { JWT: function (o) {
        calls.gmailJwt = o;
      } },
      gmail: function (o) {
        calls.gmailOptions = o;
        return { users: { messages: { send: function (req) {
          calls.gmail = req;
          return Promise.resolve({ data: { id: 'g-1' } });
        } } } };
      }
    }
  };
  const secretValues = {};
  const transports = new tm.MailTransports(Object.assign(
    tm.MailTransports.defaultDeps(), {
      load: function (name) {
        if (sdks[name]) {
          return sdks[name];
        }
        return require(name);
      },
      readSecret: function (spec) {
        return Promise.resolve(secretValues[spec.id] || null);
      }
    }));
  const ses = await transports.build({ transport: 'ses', sesRegion: 'eu-west-1',
    sesConfigurationSet: 'idp-events', timeoutMs: 5000 });
  const sent = await ses.send(message);
  const raw = Buffer.from(calls.ses.Content.Raw.Data).toString('utf8');
  t.check(calls.sesClient.region === 'eu-west-1' &&
          calls.ses.FromEmailAddress === 'no-reply@example.com' &&
          calls.ses.Destination.ToAddresses[0] === 'hal@example.com' &&
          calls.ses.ConfigurationSetName === 'idp-events' &&
          /Subject: Hello/.test(raw) && /Auto-Submitted: auto-generated/
            .test(raw) && sent.providerId === 'ses-1',
          '8a. SES v2: the raw message, the region and the configuration set',
          JSON.stringify(calls.ses).slice(0, 400));
  calls.sesThrow = Object.assign(new Error('Rate exceeded'),
    { name: 'TooManyRequestsException', $metadata: { httpStatusCode: 429 } });
  let thrown = null;
  try {
    await ses.send(message);
  } catch (e) {
    thrown = e;
  }
  t.check(thrown && thrown.retry === true &&
          errorCodes.codeOf(thrown) === 'STS-MAIL-0009',
          '8b. SES throttling is retried (STS-MAIL-0009)');
  calls.sesThrow = Object.assign(new Error('Email address is not verified'),
    { name: 'MessageRejected', $metadata: { httpStatusCode: 400 } });
  thrown = null;
  try {
    await ses.send(message);
  } catch (e) {
    thrown = e;
  }
  t.check(thrown && thrown.retry === false &&
          errorCodes.codeOf(thrown) === 'STS-MAIL-0008',
          '8c. an SES rejection is permanent (STS-MAIL-0008)');
  let noEndpoint = null;
  try {
    await transports.build({ transport: 'acs', acsAuth: 'managed-identity',
                             acsEndpoint: '', timeoutMs: 5000 });
  } catch (e) {
    noEndpoint = e;
  }
  t.check(noEndpoint && errorCodes.codeOf(noEndpoint) === 'STS-MAIL-0004',
          '8d. Azure managed identity without an endpoint cannot be built');
  const acs = await transports.build({ transport: 'acs',
    acsAuth: 'managed-identity',
    acsEndpoint: 'https://idp.communication.azure.com', timeoutMs: 5000 });
  await acs.send(message);
  t.check(calls.azureCredential && calls.acsClient[0] ===
          'https://idp.communication.azure.com' &&
          calls.acs.senderAddress === 'no-reply@example.com' &&
          calls.acs.recipients.to[0].address === 'hal@example.com' &&
          calls.acs.content.plainText === 'text part\n' &&
          calls.acs.userEngagementTrackingDisabled === true,
          '8e. Azure: managed identity, the structured payload, tracking ' +
          'off', JSON.stringify(calls.acs));
  secretValues['mail-acs-connection-string'] =
    'endpoint=https://x.communication.azure.com/;accesskey=abc';
  const acs2 = await transports.build({ transport: 'acs',
    acsAuth: 'connection-string', timeoutMs: 5000 });
  calls.acsResult = { status: 'Failed', error: { message: 'bad sender' } };
  thrown = null;
  try {
    await acs2.send(message);
  } catch (e) {
    thrown = e;
  }
  t.check(calls.acsClient[0].indexOf('accesskey=abc') > 0 && thrown &&
          errorCodes.codeOf(thrown) === 'STS-MAIL-0008',
          '8f. Azure: the connection string from the secret store, and a ' +
          'Failed operation is permanent');
  secretValues['mail-gmail-key'] = JSON.stringify({
    client_email: 'sa@proj.iam.gserviceaccount.com',
    private_key: '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n'
  });
  const gmail = await transports.build({ transport: 'gmail',
    gmailSender: 'idp@example.com', from: 'no-reply@example.com',
    timeoutMs: 5000 });
  await gmail.send(message);
  const gmailRaw = Buffer.from(calls.gmail.requestBody.raw, 'base64url')
    .toString('utf8');
  t.check(calls.gmailJwt.subject === 'idp@example.com' &&
          calls.gmailJwt.scopes[0] ===
            'https://www.googleapis.com/auth/gmail.send' &&
          calls.gmail.userId === 'me' && /To: hal@example.com/.test(gmailRaw),
          '8g. Gmail API: domain-wide delegation to the sender, gmail.send ' +
          'only, the raw message base64url', JSON.stringify(calls.gmailJwt));
  const bare = new tm.MailTransports(Object.assign(
    tm.MailTransports.defaultDeps(), { load: function (name) {
      throw new Error('Cannot find module \'' + name + '\'');
    } }));
  thrown = null;
  try {
    await bare.build({ transport: 'ses', timeoutMs: 5000 });
  } catch (e) {
    thrown = e;
  }
  t.check(thrown && errorCodes.codeOf(thrown) === 'STS-MAIL-0005' &&
          /@aws-sdk\/client-sesv2/.test(thrown.message),
          '8h. a missing SDK is STS-MAIL-0005, naming the package');
  log.debug('Leaving cloud().');
}

// ---------------------------------------------------------------------------
// 9. SMTP AGAINST A REAL SERVER
// ---------------------------------------------------------------------------
async function smtp(t) {
  log.debug('Entering smtp().');
  let SMTPServer = null;
  try {
    SMTPServer = require('smtp-server').SMTPServer;
  } catch (e) {
    t.bad('9. smtp-server is a dependency of tests/package.json and is not ' +
          'installed', String(e && e.message));
    log.debug('Leaving smtp(). No smtp-server.');
    return;
  }
  const tm = require('../common/mail_transports');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const ca = require('./vendored/outbound_test_ca.js');
  const authority = await ca.makeCa();
  const leaf = await ca.listenerCertificate(authority, 'localhost');
  const stranger = await ca.listenerCertificate(await ca.makeCa(),
                                                'localhost');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mail-test-'));
  const caFile = path.join(dir, 'ca.pem');
  fs.writeFileSync(caFile, authority.certPem);
  const dkim = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const dkimPem = dkim.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const dkimPub = dkim.publicKey.export({ type: 'spki', format: 'pem' });
  const received = [];
  const start = function (opts) {
    log.debug('Entering start().');
    const server = new SMTPServer(Object.assign({
      key: leaf.key, cert: leaf.cert, authOptional: true,
      logger: false,
      onAuth: function (auth, session, cb) {
        received.push({ auth: { user: auth.username, pass: auth.password,
                                method: auth.method } });
        cb(null, { user: auth.username });
      },
      onData: function (stream, session, cb) {
        const chunks = [];
        stream.on('data', function (c) {
          chunks.push(c);
        });
        stream.on('end', function () {
          received.push({ secure: session.secure,
                          data: Buffer.concat(chunks).toString('binary'),
                          rcpt: session.envelope.rcptTo.map(function (r) {
                            return r.address;
                          }) });
          cb();
        });
      }
    }, opts || {}));
    log.debug('Leaving start().');
    return new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', function () {
        resolve({ server: server, port: server.server.address().port });
      });
    });
  };
  const message = { from: 'no-reply@example.com', fromName: '',
    to: 'ivy@example.com', subject: 'SMTP test', text: 'Hello Ivy\n',
    html: '<p>Hello Ivy</p>', messageId: '<s1@example.com>',
    date: new Date(), lang: 'en' };
  const secretFile = path.join(dir, 'smtp-password');
  fs.writeFileSync(secretFile, 's3cret-relay\n');
  const transports = new tm.MailTransports(Object.assign(
    tm.MailTransports.defaultDeps(), {
      readSecret: function (spec) {
        return Promise.resolve(spec.id === 'mail-smtp-password'
          ? fs.readFileSync(secretFile, 'utf8').trim()
          : spec.id === 'mail-dkim-key' ? dkimPem : null);
      }
    }));
  const base = { transport: 'smtp', smtpHost: 'localhost', smtpTls: 'starttls',
    smtpCaFile: caFile, smtpAuth: 'plain', smtpUser: 'relay-user',
    dkimDomain: 'example.com', dkimSelector: 'mail2026',
    dkimAlgorithm: 'rsa-sha256', timeoutMs: 8000 };
  const good = await start({});
  try {
    const transport = await transports.build(Object.assign({}, base,
      { smtpPort: good.port }));
    await transport.send(message);
    transport.close();
    const auth = received.filter(function (r) {
      return r.auth;
    })[0];
    const data = received.filter(function (r) {
      return r.data;
    })[0];
    t.check(data && data.secure === true && data.rcpt[0] === 'ivy@example.com',
            '9a. delivered over STARTTLS to the entry\'s address',
            JSON.stringify(data && { secure: data.secure, rcpt: data.rcpt }));
    t.check(auth && auth.auth.user === 'relay-user' &&
            auth.auth.pass === 's3cret-relay' && auth.auth.method === 'PLAIN',
            '9b. SMTP AUTH PLAIN, the password read from the secret, after ' +
            'TLS', JSON.stringify(auth));
    t.check(data && /^DKIM-Signature: v=1; a=rsa-sha256; c=relaxed\/relaxed; d=example\.com; s=mail2026;/.test(data.data) &&
            stsCrypto.dkimVerify(data.data, dkimPub).ok,
            '9c. the message carries a DKIM signature that verifies against ' +
            'the selector\'s key', data && data.data.slice(0, 300));
  } finally {
    good.server.close();
  }
  const plain = await start({ disabledCommands: ['STARTTLS'] });
  let refused = null;
  try {
    const transport = await transports.build(Object.assign({}, base,
      { smtpPort: plain.port, smtpAuth: 'none', dkimDomain: '' }));
    await transport.send(message);
  } catch (e) {
    refused = e;
  } finally {
    plain.server.close();
  }
  t.check(refused && errorCodes.codeOf(refused) === 'STS-MAIL-0014' &&
          refused.retry === false,
          '9d. a relay that offers no STARTTLS is refused and nothing goes ' +
          'in the clear (STS-MAIL-0014)', refused && refused.message);
  const untrusted = await start({ key: stranger.key, cert: stranger.cert });
  refused = null;
  try {
    const transport = await transports.build(Object.assign({}, base,
      { smtpPort: untrusted.port, smtpAuth: 'none', dkimDomain: '' }));
    await transport.send(message);
  } catch (e) {
    refused = e;
  } finally {
    untrusted.server.close();
  }
  t.check(refused && errorCodes.codeOf(refused) === 'STS-MAIL-0014',
          '9e. a relay certificate that does not chain to the trust anchor ' +
          'is refused (STS-MAIL-0014)', refused && refused.message);
  const picky = await start({ onRcptTo: function (address, session, cb) {
    const err = new Error(address.address.indexOf('later') === 0
      ? 'Try again later' : 'No such user');
    err.responseCode = address.address.indexOf('later') === 0 ? 451 : 550;
    cb(err);
  } });
  const answers = [];
  try {
    const transport = await transports.build(Object.assign({}, base,
      { smtpPort: picky.port, smtpAuth: 'none', dkimDomain: '' }));
    for (const to of ['nobody@example.com', 'later@example.com']) {
      try {
        await transport.send(Object.assign({}, message, { to: to }));
        answers.push('sent');
      } catch (e) {
        answers.push(errorCodes.codeOf(e) + ':' + e.retry);
      }
    }
  } finally {
    picky.server.close();
  }
  t.equal(answers.join(','), 'STS-MAIL-0008:false,STS-MAIL-0009:true',
          '9f. a 5xx is permanent (STS-MAIL-0008) and a 4xx is retried ' +
          '(STS-MAIL-0009)');
  let halfDkim = null;
  try {
    await new tm.MailTransports(Object.assign(tm.MailTransports.defaultDeps(),
      { readSecret: function () {
        return Promise.resolve(null);
      } })).build(Object.assign({}, base, { smtpPort: 1, smtpAuth: 'none' }));
  } catch (e) {
    halfDkim = e;
  }
  t.check(halfDkim && errorCodes.codeOf(halfDkim) === 'STS-MAIL-0022',
          '9g. a DKIM domain with no key cannot be built (STS-MAIL-0022)');
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug('Leaving smtp().');
}

// ---------------------------------------------------------------------------
// 10. DKIM AGAINST NODEMAILER'S OWN SIGNER
// ---------------------------------------------------------------------------
async function dkim(t) {
  log.debug('Entering dkim().');
  const stsCrypto = require('../common/crypto');
  const MailComposer = require('nodemailer/lib/mail-composer');
  const NodemailerDkim = require('nodemailer/lib/dkim');
  const { Readable } = require('stream');
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pub = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const raw = await new MailComposer({ from: 'a@example.com',
    to: 'b@example.com', subject: 'Hi   there', text: 'Hello   world  \n\n\n',
    html: '<p>x</p>', disableFileAccess: true, disableUrlAccess: true })
    .compile().build();
  const ours = stsCrypto.dkimSign(raw, { domain: 'example.com',
    selector: 's1', privateKeyPem: pem });
  t.check(stsCrypto.dkimVerify(ours + '\r\n' + raw.toString('binary'), pub).ok,
          '10a. our signature verifies');
  t.check(!stsCrypto.dkimVerify(ours + '\r\n' + raw.toString('binary')
    .replace('Hello', 'Jello'), pub).ok,
          '10b. a changed body does not');
  const theirs = new NodemailerDkim({ domainName: 'example.com',
    keySelector: 's1', privateKey: pem,
    headerFieldNames: 'from:to:subject:date:message-id' })
    .sign(Readable.from([raw]));
  const chunks = [];
  for await (const c of theirs) {
    chunks.push(c);
  }
  const signed = Buffer.concat(chunks).toString('binary');
  t.check(stsCrypto.dkimVerify(signed, pub).ok,
          '10c. nodemailer\'s independent signature verifies with our ' +
          'verifier (the canonicalizations agree)');
  const bhOurs = /bh=([^;]+)/.exec(ours)[1];
  const bhTheirs = /bh=([^;\s]+)/.exec(signed.replace(/\r\n[ \t]/g, ''))[1];
  t.equal(bhOurs, bhTheirs, '10d. the two body hashes agree');
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const edSig = stsCrypto.dkimSign(raw, { domain: 'example.com',
    selector: 'e1', algorithm: 'ed25519-sha256',
    privateKeyPem: ed.privateKey.export({ type: 'pkcs8', format: 'pem' }) });
  t.check(stsCrypto.dkimVerify(edSig + '\r\n' + raw.toString('binary'),
    ed.publicKey.export({ type: 'spki', format: 'pem' })).ok,
          '10e. ed25519-sha256 (RFC 8463)');
  let small = null;
  try {
    stsCrypto.dkimSign(raw, { domain: 'example.com', selector: 's1',
      privateKeyPem: nodeCrypto.generateKeyPairSync('rsa',
        { modulusLength: 1024 }).privateKey.export({ type: 'pkcs8',
                                                     format: 'pem' }) });
  } catch (e) {
    small = e;
  }
  t.check(!!small, '10f. an RSA key under 2048 bits is refused (RFC 8301)');
  log.debug('Leaving dkim().');
}

// ---------------------------------------------------------------------------
// 11. THE USES
// ---------------------------------------------------------------------------
async function uses(t) {
  log.debug('Entering uses().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  const usesModule = require('../common/mail_uses');
  const dir = stubDirectory({
    jan: { mail: ['jan@example.com'] },
    kim: { mail: ['kim@example.com'] },
    lee: {}
  });
  mailModule.setDirectory(dir);
  await withRealm(t, realms, realmId('mail-uses'),
                  { 'global.mode': 'product', 'mail.transport': 'smtp',
                    'global.publicBaseUrl': 'https://idp.example' },
                  async function () {
    const transports = stubTransports();
    const m = makeMail({ transports: transports });
    const signals = [];
    const issued = [];
    const creds = {
      accountDisabled: function (u) {
        return u === 'kim-disabled';
      },
      issuePasswordReset: function (u) {
        issued.push(u);
        return { ok: true, token: 'tok-' + u, expiresAt: 'soon' };
      }
    };
    const u = new usesModule.MailUses(Object.assign(
      usesModule.MailUses.defaultDeps(), {
        mail: {
          send: m.send.bind(m), available: m.available.bind(m),
          directory: function () {
            return dir;
          },
          recipient: m.recipient.bind(m),
          sendToFormerAddress: m.sendToFormerAddress.bind(m)
        },
        credentials: function () {
          return creds;
        },
        accountSignals: function () {
          return { recoveryActivated: function (n) {
            signals.push(n);
          } };
        }
      }));
    // ADDRESS VERIFICATION
    const started = u.startVerification('jan', 'the portal');
    t.check(started.ok, '11a. a verification link is sent to the entry\'s ' +
            'address', JSON.stringify(started));
    await new Promise(function (resolve) {
      setTimeout(resolve, 20);
    });
    const mailed = transports.sent.filter(function (x) {
      return /Confirm your address/.test(x.subject);
    })[0];
    const link = /(https:\/\/idp\.example\S+)/.exec(mailed.text)[1];
    const token = new URL(link).searchParams.get('token');
    t.check(link.indexOf('/portal/verify-email?user=jan&token=') > 0,
            '11b. the link is the pinned origin and /portal/verify-email',
            link);
    t.check(u.checkVerification('jan', 'wrong').ok === false &&
            u.checkVerification('jan', token).ok === true,
            '11c. only the token that was sent checks');
    t.check(u.completeVerification('jan', token).ok &&
            m.recipient('jan').verified &&
            !u.completeVerification('jan', token).ok,
            '11d. following it verifies the address, once');
    dir.people.jan.mail = ['jan.new@example.com'];
    t.check(!m.recipient('jan').verified,
            '11e. a changed address is unverified with nothing cleared');
    dir.people.jan.mail = ['jan@example.com'];
    // FORGOT PASSWORD
    const nobody = await u.requestReset('nobody', 'test');
    const unverified = await u.requestReset('kim', 'test');
    const byAddress = await u.requestReset('jan@example.com', 'test');
    t.check(nobody.message === unverified.message &&
            unverified.message === byAddress.message &&
            nobody.message === usesModule.RESET_ANSWER,
            '11f. the forgot-password answer is one sentence whatever ' +
            'happened');
    t.check(nobody.outcome === 'no such account' &&
            /not verified/.test(unverified.outcome) &&
            byAddress.outcome === 'mailed' && issued.join(',') === 'jan',
            '11g. only a verified address is sent a link ' +
            '(mail.resetRequiresVerifiedAddress), and it may be named by ' +
            'its address', JSON.stringify([nobody.outcome, unverified.outcome,
                                           byAddress.outcome, issued]));
    t.check(signals.length === 1 && signals[0].username === 'jan' &&
            signals[0].initiatingEntity === 'user',
            '11h. RISC recovery-activated, the person\'s own',
            JSON.stringify(signals));
    await new Promise(function (resolve) {
      setTimeout(resolve, 30);
    });
    const resetMail = transports.sent.filter(function (x) {
      return /Reset your/.test(x.subject);
    })[0];
    t.check(resetMail && resetMail.to === 'jan@example.com' &&
            resetMail.text.indexOf('https://idp.example/realm/') >= 0 &&
            resetMail.text.indexOf('/portal/reset-password?user=jan&token=' +
                                   'tok-jan') > 0,
            '11i. the reset link goes to the entry\'s address on the pinned ' +
            'origin', resetMail && resetMail.text);
    // AN ADMINISTRATOR'S LINK
    const adminLink = u.mailAdministratorLink('activation', 'kim', 'act-1',
                                              'admin', 'the console');
    t.check(adminLink.ok && adminLink.mailedTo === 'kim@example.com',
            '11j. an administrator\'s activation link is mailed to the ' +
            'person', JSON.stringify(adminLink));
    const noAddress = u.mailAdministratorLink('reset', 'lee', 'x', 'admin',
                                              'the console');
    t.check(!noAddress.ok, '11k. a person with no address: not mailed, so ' +
            'the console shows the link instead');
    // NOTICES
    await new Promise(function (resolve) {
      setTimeout(resolve, 30);
    });
    const before = transports.sent.length;
    u.fromAccountSignal('credentialChanged', { username: 'kim',
      credentialType: 'password', reasonUser: 'You chose a new password.' });
    u.fromAccountSignal('credentialChanged', { username: 'kim',
      credentialType: 'password', friendlyName: 'mail client' });
    u.fromAccountSignal('recoveryActivated', { username: 'kim',
                                               mailed: true });
    u.fromAccountSignal('credentialCompromised', { username: 'kim',
      credentialType: 'password', initiatingEntity: 'admin' });
    u.accountDisabled('kim', 'Too many failures.', false);
    u.sessionsEnded('kim', 2, 'an administrator');
    await new Promise(function (resolve) {
      setTimeout(resolve, 30);
    });
    const subjects = transports.sent.slice(before).map(function (x) {
      return x.subject;
    });
    t.check(subjects.length === 4 &&
            subjects.some(function (s) {
              return /password was changed/.test(s);
            }) && subjects.some(function (s) {
              return /marked compromised/.test(s);
            }) && subjects.some(function (s) {
              return /was disabled/.test(s);
            }) && subjects.some(function (s) {
              return /signed out/.test(s);
            }),
            '11l. the security notices: password changed, compromised, ' +
            'disabled, signed out — and none for an app password or a ' +
            'recovery whose link was itself mailed', JSON.stringify(subjects));
    const former = u.addressChanged('kim', 'kim.old@example.com',
                                    'kim@example.com');
    await former.delivered;
    const told = transports.sent[transports.sent.length - 1];
    t.check(former.ok && told.to === 'kim.old@example.com' &&
            /address of your/.test(told.subject),
            '11m. a changed address is told to the FORMER address',
            JSON.stringify(told && { to: told.to, subject: told.subject }));
  });
  log.debug('Leaving uses().');
}

// ---------------------------------------------------------------------------
// 12. REALMS
// ---------------------------------------------------------------------------
async function realmsSeparate(t) {
  log.debug('Entering realmsSeparate().');
  const realms = require('../common/realms');
  const mailModule = require('../common/mail');
  mailModule.setDirectory(stubDirectory({
    max: { mail: ['max@example.com'] } }));
  let firstId = '';
  const a = realmId('mail-realm-a');
  const b = realmId('mail-realm-b');
  await withRealm(t, realms, a, { 'mail.transport': 'smtp' },
                  async function () {
    const m = makeMail({ transports: stubTransports() });
    t.equal(m.effectiveTransport(), 'smtp',
            '12a. a realm\'s own transport overrides the service\'s');
    const r = m.send({ username: 'max', template: 'test-message' });
    await r.delivered;
    firstId = r.queued[0].id;
  });
  await withRealm(t, realms, b, {}, async function () {
    const m = makeMail({ transports: stubTransports() });
    t.equal(m.effectiveTransport(), 'capture',
            '12b. a realm without one uses the service\'s (development: ' +
            'capture)');
    t.check(!m.list().some(function (row) {
      return row.id === firstId;
    }) && !mailModule.message(firstId),
            '12c. one realm\'s outbox is not another\'s');
  });
  log.debug('Leaving realmsSeparate().');
}

module.exports = {
  name: 'mail',
  describe: 'The mail channel (#63): templates, directory-only recipients, ' +
            'opt-outs, ceilings, once-only delivery, retries and dead ' +
            'letters, the mode, the cloud transports stubbed, SMTP against a ' +
            'real server with DKIM, the uses, and realms',
  run: async function (t) {
    log.debug('Entering run().');
    process.env.STS_LOG_LEVEL = process.env.STS_LOG_LEVEL || 'fatal';
    templates(t);
    await recipients(t);
    await ceilings(t);
    await twoNodes(t);
    await retries(t);
    await modes(t);
    await cloud(t);
    await smtp(t);
    await dkim(t);
    await uses(t);
    await realmsSeparate(t);
    log.debug('Leaving run().');
  }
};
