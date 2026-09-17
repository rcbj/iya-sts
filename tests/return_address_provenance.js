'use strict';
//
// File: return_address_provenance.js
//
// ===========================================================================
// A RETURN ADDRESS DEVELOPMENT LEARNT IS NOT ONE PRODUCT BELIEVES (2026-09-12).
//
// Development mode writes the return address a request NAMED — a SAML ACS URL,
// a SAML 1.1 `shire`, a WS-Federation `wreply`, the callback the console and
// portal learn from a Host header — onto the attribute product mode checks a
// request against. A realm switched to product kept every one of them and
// believed them as if an operator had registered them. The fix records
// PROVENANCE on `appReturnAddressObserved` and puts the decision in ONE
// function, `applications.returnAddressesOf()`.
//
// Seven claims, and the first two are the ones the change is for:
//
//   A. a development sighting that ADDS an address marks it, and one that
//      repeats a registered address does not demote it;
//   B. in product the marked address is withheld, and the shared resolver
//      refuses it with STS-REG-0049 and a sentence saying how to confirm it;
//   C. confirm takes the mark off and keeps the address — product believes it;
//      a second confirm is refused by name;
//   D. discard takes both off; product then refuses it as ABSENT, not as
//      observed;
//   E. an explicit `add` confirms, a `remove` takes the mark with the value,
//      and a registration (RFC 7591/7592) confirms the redirect URIs it names;
//   F. the console's own client: a callback learnt in development is marked,
//      withheld from `clientConfigOf()` in product, refused there with
//      STS-REG-0049, and used once confirmed;
//   G. every return-address check ASKS the one function — read as source,
//      because four call sites each reading the attribute themselves would
//      pass every behavioural check above.
//
// WHY IN PROCESS: the claims are about what is WRITTEN on an entry and what a
// check believes in a mode, and the suite's stacks run in development with no
// way to put a realm's entry into product mid-flow without also closing the
// management API the job would read it back through. The vendored
// `sts_admin_api_operations.js` drives the two operations over HTTP.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'return_address_provenance',
  level: process.env.LOG_LEVEL || 'info' });

function withMode(config, value, fn) {
  log.debug("Entering withMode().");
  try {
    config.setOverride('global.mode', value);
    log.debug("Leaving withMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

function fakeReq(host) {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return {
    protocol: 'https',
    headers: { host: host },
    originalUrl: '/admin',
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return String(name).toLowerCase() === 'host' ? host : undefined;
    }
  };
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 0, location: '', ended: false };
  res.status = function (code) {
    log.debug("Entering status().");
    res.statusCode = code;
    log.debug("Leaving status().");
    return res;
  };
  res.set = function (name, value) {
    log.debug("Entering set().");
    if (String(name).toLowerCase() === 'location') {
      res.location = value;
    }
    log.debug("Leaving set().");
    return res;
  };
  res.end = function () {
    log.debug("Entering end().");
    res.ended = true;
    log.debug("Leaving end().");
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  // The registry's store is the directory; requiring it fills the slot and
  // seeds `sts-admin-console`. It binds no port.
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const returnAddress = require('../saml/return_address');
  const oidcRp = require('../common/oidc_rp');

  const ACS = 'samlAssertionConsumerService';
  const suffix = String(Date.now());
  const spId = 'urn:test:rap-sp-' + suffix;
  const REGISTERED = 'https://registered.rap.test/acs';
  const LEARNT = 'https://learnt.rap.test/acs';
  const SECOND = 'https://second.rap.test/acs';

  const entry = function () {
    log.debug("Entering entry().");
    log.debug("Leaving entry().");
    return applications.get(spId);
  };

  const acsValues = function () {
    log.debug("Entering acsValues().");
    log.debug("Leaving acsValues().");
    return [].concat(((entry() || {}).fields || {})[ACS] || []);
  };

  const marksOf = function () {
    log.debug("Entering marksOf().");
    log.debug("Leaving marksOf().");
    return applications.observedReturnAddresses(entry() || {})
                       .map(function (row) {
      return row.attribute + ' ' + row.value;
    });
  };

  const resolveFor = function (requested) {
    log.debug("Entering resolveFor().");
    const known = applications.returnAddressesOf(entry() || {}, ACS);
    log.debug("Leaving resolveFor().");
    return returnAddress.resolve({
      requested: requested, registered: known.registered,
      unconfirmed: known.unconfirmed,
      fallback: 'https://idp.test/saml2/sp', attribute: ACS,
      parameter: 'AssertionConsumerServiceURL', application: spId
    });
  };

  // -------------------------------------------------------------------------
  t.log.info('=== A. a development sighting marks what it ADDS ===');
  // -------------------------------------------------------------------------
  withMode(config, 'development', function () {
    const created = applications.createApplication({
      identifier: spId, kind: 'saml2-service-provider',
      fields: { samlEntityId: spId,
                samlAssertionConsumerService: [REGISTERED] } });
    t.check(created && created.ok, 'a fixture service provider was ' +
                                   'registered with one ACS URL',
            JSON.stringify((created && created.errors) || []));
    t.equal(JSON.stringify(marksOf()), '[]',
            'an address given at CREATE is registered and carries no mark');

    applications.seen({ identifier: spId, kind: 'saml2-service-provider',
                        counts: false,
                        fields: { samlAssertionConsumerService: LEARNT } });
    t.check(acsValues().indexOf(LEARNT) >= 0,
            'development still writes the ACS URL a request named',
            acsValues());
    t.check(marksOf().indexOf(ACS + ' ' + LEARNT) >= 0,
            'AND MARKS IT as observed on appReturnAddressObserved', marksOf());

    applications.seen({ identifier: spId, kind: 'saml2-service-provider',
                        counts: false,
                        fields: { samlAssertionConsumerService: REGISTERED } });
    t.check(marksOf().indexOf(ACS + ' ' + REGISTERED) < 0,
            'a sighting that repeats a REGISTERED address does not demote it',
            marksOf());

    const dev = applications.returnAddressesOf(entry(), ACS);
    t.check(dev.registered.indexOf(LEARNT) >= 0 && dev.unconfirmed.length === 0,
            'development believes every address, marked or not — its ' +
            'behaviour is unchanged',
            JSON.stringify(dev));
    t.equal(resolveFor(LEARNT).ok, true,
            'and the resolver delivers to the learnt address in development');
    const shown = (entry().returnAddressesObserved || []).filter(
        function (row) {
      return row.value === LEARNT;
    })[0];
    t.check(shown && shown.trusted === true && shown.held === true,
            'the application view lists it, trusted in development',
            JSON.stringify(shown));
    t.check(!applications.normaliseFields({ appReturnAddressObserved:
                                              'x y' }).ok,
            'the mark is DERIVED: a create may not assert one');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== B. product withholds a marked address ===');
  // -------------------------------------------------------------------------
  withMode(config, 'product', function () {
    const known = applications.returnAddressesOf(entry(), ACS);
    t.check(known.registered.indexOf(LEARNT) < 0 &&
            known.unconfirmed.indexOf(LEARNT) >= 0,
            'returnAddressesOf() withholds the marked address in product',
            JSON.stringify(known));
    t.check(known.registered.indexOf(REGISTERED) >= 0,
            'while the registered address is believed', JSON.stringify(known));
    const refused = resolveFor(LEARNT);
    t.equal(refused.ok, false, 'a request naming the observed address is ' +
                               'REFUSED in product');
    t.equal(errorCodes.codeOf(refused), 'STS-REG-0049', 'with STS-REG-0049');
    t.check(/confirm-address/.test(refused.why || '') &&
            /DEVELOPMENT/.test(refused.why || ''),
            'and a sentence saying it was learnt in development and how to ' +
            'confirm it',
            refused.why);
    t.equal(resolveFor(REGISTERED).ok, true, 'a registered address is still ' +
                                             'delivered to');
    t.equal(resolveFor('').url, REGISTERED,
            'a request naming none gets the last REGISTERED address, never ' +
            'the observed one');
    const shown = (entry().returnAddressesObserved || []).filter(
        function (row) {
      return row.value === LEARNT;
    })[0];
    t.check(shown && shown.trusted === false,
            'and the view says product does not trust it',
            JSON.stringify(shown));
  });
  // An entry whose ONLY address is an observed one, asked by a request that
  // names none: the refusal must still say the address is there and how to
  // confirm it, rather than "nothing is registered" about an entry the operator
  // can see an address on.
  const onlyId = spId + '-only';
  withMode(config, 'development', function () {
    applications.createApplication({ identifier: onlyId,
                                     kind: 'saml2-service-provider',
                                     fields: { samlEntityId: onlyId } });
    applications.seen({ identifier: onlyId, kind: 'saml2-service-provider',
                        counts: false,
                        fields: { samlAssertionConsumerService: LEARNT } });
  });
  withMode(config, 'product', function () {
    const known = applications.returnAddressesOf(applications.get(onlyId), ACS);
    const none = returnAddress.resolve({
      requested: '', registered: known.registered,
      unconfirmed: known.unconfirmed,
      fallback: '', attribute: ACS, parameter: 'AssertionConsumerServiceURL',
      application: onlyId });
    t.check(!none.ok && errorCodes.codeOf(none) === 'STS-REG-0049' &&
            /confirm-address/.test(none.why || ''),
            'an entry holding ONLY an observed address refuses a request ' +
            'naming none with STS-REG-0049 and the way to confirm ' +
            'it', JSON.stringify([none.why, errorCodes.codeOf(none)]));
  });
  applications.deleteApplication(onlyId);

  // -------------------------------------------------------------------------
  t.log.info('=== C. confirm ===');
  // -------------------------------------------------------------------------
  const refusedAbsent = applications.confirmReturnAddress(spId,
                                                          { attribute: ACS,
                                                            value:
                                                              REGISTERED });
  t.check(!refusedAbsent.ok &&
          errorCodes.codeOf(refusedAbsent) === 'STS-REG-0050',
          'confirming an address that is NOT marked is refused by name ' +
          '(STS-REG-0050)',
          JSON.stringify(refusedAbsent.errors));
  const refusedAttr = applications.confirmReturnAddress(spId,
    { attribute: 'oauthPostLogoutRedirectUri', value: LEARNT });
  t.equal(errorCodes.codeOf(refusedAttr), 'STS-REG-0051',
          'an attribute that is not a return address is refused ' +
          '(STS-REG-0051)');
  t.equal(errorCodes.codeOf(applications.confirmReturnAddress(spId,
                                                              { attribute:
                                                                  ACS })),
          'STS-REG-0052', 'a confirm naming no address is refused ' +
                          '(STS-REG-0052)');
  const confirmed = applications.confirmReturnAddress(spId,
                                                      { attribute: ACS,
                                                        value: LEARNT });
  t.check(confirmed.ok, 'confirm-address succeeds on a marked address',
          JSON.stringify(confirmed.errors));
  t.check(marksOf().indexOf(ACS + ' ' + LEARNT) < 0 &&
          acsValues().indexOf(LEARNT) >= 0,
          'the MARK is gone and the ADDRESS stays', JSON.stringify(
              [marksOf(), acsValues()]));
  withMode(config, 'product', function () {
    t.equal(resolveFor(LEARNT).ok, true, 'and product delivers to it now');
  });
  t.equal(errorCodes.codeOf(applications.confirmReturnAddress(spId,
            { attribute: ACS, value: LEARNT })), 'STS-REG-0050',
          'a second confirm is refused, not silently repeated');

  // -------------------------------------------------------------------------
  t.log.info('=== D. discard ===');
  // -------------------------------------------------------------------------
  withMode(config, 'development', function () {
    applications.seen({ identifier: spId, kind: 'saml2-service-provider',
                        counts: false,
                        fields: { samlAssertionConsumerService: SECOND } });
  });
  t.check(marksOf().indexOf(ACS + ' ' + SECOND) >= 0, 'a second sighting is ' +
                                                      'marked', marksOf());
  const discarded = applications.discardReturnAddress(spId,
                                                      { attribute: ACS,
                                                        value: SECOND });
  t.check(discarded.ok, 'discard-address succeeds',
          JSON.stringify(discarded.errors));
  t.check(marksOf().indexOf(ACS + ' ' + SECOND) < 0 &&
          acsValues().indexOf(SECOND) < 0,
          'BOTH the mark and the address are gone', JSON.stringify(
              [marksOf(), acsValues()]));
  withMode(config, 'product', function () {
    const gone = resolveFor(SECOND);
    t.check(!gone.ok && errorCodes.codeOf(gone) !== 'STS-REG-0049',
            'product refuses it as an address that is not on the entry, not ' +
            'as an observed one',
            gone.why);
  });
  t.check(!applications.discardReturnAddress(spId,
                                             { attribute: ACS,
                                               value: REGISTERED }).ok &&
          acsValues().indexOf(REGISTERED) >= 0,
          'discard will not remove a REGISTERED address — `remove` is that door', acsValues());

  // -------------------------------------------------------------------------
  t.log.info('=== E. explicit writes confirm ===');
  // -------------------------------------------------------------------------
  const THIRD = 'https://third.rap.test/acs';
  const FOURTH = 'https://fourth.rap.test/acs';
  withMode(config, 'development', function () {
    applications.seen({ identifier: spId, kind: 'saml2-service-provider',
                        counts: false,
                        fields: { samlAssertionConsumerService: [THIRD,
                                                                 FOURTH] } });
  });
  const added = applications.updateApplication(spId,
                                               { attribute: ACS, mode: 'add',
                                                 value: THIRD });
  t.check(added.ok && added.changed,
          'an explicit `add` of an address already there as observed is a ' +
          'CHANGE',
          JSON.stringify(added));
  t.check(marksOf().indexOf(ACS + ' ' + THIRD) < 0 &&
          acsValues().indexOf(THIRD) >= 0,
          'and it CONFIRMS the address', JSON.stringify(
              [marksOf(), acsValues()]));
  applications.updateApplication(spId,
                                 { attribute: ACS, mode: 'remove',
                                   value: FOURTH });
  t.check(marksOf().indexOf(ACS + ' ' + FOURTH) < 0 &&
          acsValues().indexOf(FOURTH) < 0,
          'a `remove` takes the mark with the value, so no mark names a ' +
          'missing address',
          JSON.stringify([marksOf(), acsValues()]));
  withMode(config, 'product', function () {
    const before = acsValues().slice(0);
    applications.updateApplication(spId,
      { attribute: ACS, mode: 'add', value: 'https://flagged.rap.test/acs',
        observed: true });
    t.check(marksOf().indexOf(ACS + ' https://flagged.rap.test/acs') < 0,
            'in product an `observed` flag can mark NOTHING — product learns ' +
            'no address',
            JSON.stringify([before, marksOf()]));
    applications.updateApplication(spId,
      { attribute: ACS, mode: 'remove',
        value: 'https://flagged.rap.test/acs' });
  });

  const clientId = 'rap-client-' + suffix;
  const CB = 'https://client.rap.test/cb';
  applications.register(clientId,
                        { redirect_uris: ['https://client.rap.test/first'],
                                    client_secret: 'rap-secret' });
  withMode(config, 'development', function () {
    applications.updateApplication(clientId,
      { attribute: 'oauthRedirectUri', mode: 'add', value: CB,
        observed: true });
  });
  t.check(applications.observedReturnAddresses(applications.get(clientId))
            .some(function (row) { return row.value === CB; }),
          'a redirect URI added with the observed flag in development is ' +
          'marked');
  applications.updateRegistration(clientId,
    { redirect_uris: ['https://client.rap.test/first', CB],
      client_secret: 'rap-secret' });
  t.check(!applications.observedReturnAddresses(applications.get(clientId))
             .some(function (row) { return row.value === CB; }),
          'and an RFC 7592 update naming it CONFIRMS it — a registration is ' +
          'explicit');
  applications.deleteApplication(clientId);

  // -------------------------------------------------------------------------
  t.log.info('=== F. the console\'s own client ===');
  // -------------------------------------------------------------------------
  const CLIENT = 'sts-admin-console';
  const host = 'rap-learnt-' + suffix + '.example:8443';
  const learntCb = 'https://' + host + '/admin/callback';
  const cleanup = function () {
    log.debug("Entering cleanup().");
    if ([].concat((applications.get(CLIENT) ||
                   { fields: {} }).fields.oauthRedirectUri || [])
          .indexOf(learntCb) >= 0) {
      applications.updateApplication(CLIENT,
                                     { attribute: 'oauthRedirectUri',
                                               mode: 'remove',
                                               value: learntCb,
                                               actor: 'tests/return_address_provenance.js' });
    }
    log.debug("Leaving cleanup().");
  };
  try {
    withMode(config, 'development', function () {
      const started = oidcRp.beginSignIn(fakeReq(host), fakeRes(), 'admin',
                                         { returnTo: '/admin' });
      t.check(started.ok, 'development learns the callback as it always did',
              started.why);
    });
    t.check(applications.observedReturnAddresses(applications.get(CLIENT))
              .some(function (row) { return row.value === learntCb; }),
            'and the LEARNT callback is marked observed on the entry');
    withMode(config, 'product', function () {
      const cfg = applications.clientConfigOf(CLIENT);
      t.check(cfg.redirect_uris.indexOf(learntCb) < 0 &&
              cfg.unconfirmed_redirect_uris.indexOf(learntCb) >= 0,
              'clientConfigOf() withholds it in product, so RFC 9700 mode ' +
              'does not believe it either',
              JSON.stringify(cfg.unconfirmed_redirect_uris));
      const refused = oidcRp.beginSignIn(fakeReq(host), fakeRes(), 'admin',
                                         { returnTo: '/admin' });
      t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-REG-0049',
              'a product sign-in at that address is refused with STS-REG-0049',
              JSON.stringify([refused.why, errorCodes.codeOf(refused)]));
      t.check(/confirm-address/.test(refused.why || ''),
              'naming how to confirm it', refused.why);
    });
    const ok = applications.confirmReturnAddress(CLIENT,
      { attribute: 'oauthRedirectUri', value: learntCb });
    t.check(ok.ok, 'the learnt callback can be confirmed',
            JSON.stringify(ok.errors));
    withMode(config, 'product', function () {
      const cfg = applications.clientConfigOf(CLIENT);
      const again = oidcRp.ensureRedirectUri(oidcRp.surfaceOf('admin'), cfg,
                                             learntCb);
      t.check(again.ok && !again.learnt,
              'and once confirmed product uses it without learning anything',
              JSON.stringify(again));
    });
  } finally {
    cleanup();
  }

  // -------------------------------------------------------------------------
  t.log.info('=== G. every check asks the one function ===');
  // -------------------------------------------------------------------------
  const read = function (rel) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  };
  const saml2 = read('saml/saml2_sso.ts');
  const saml11 = read('saml/saml11_sso.ts');
  const wsfed = read('ws-federation/wsfed.ts');
  const registry = read('common/applications.js');
  [['saml/saml2_sso.ts', saml2,
    /applications\.returnAddressesOf\(known,\s*'samlAssertionConsumerService'\)/],
   ['saml/saml11_sso.ts', saml11,
    /applications\.returnAddressesOf\(\s*early\.id/],
   ['ws-federation/wsfed.ts', wsfed,
    /applications\.returnAddressesOf\(realmEntry/]]
    .forEach(function (one) {
      t.check(one[2].test(one[1]), one[0] + ' asks ' +
                                            'applications.returnAddressesOf()');
    });
  t.check(!/registered:\s*known\.samlAssertionConsumerService/.test(saml2) &&
          !/registered:\s*early\.id \? fieldsOf\(early\.id\)\.samlAssertionConsumerService/.test(saml11) &&
          !/realmEntry\.fields\.wsfedReplyUrl\)/.test(wsfed),
          'and none of the three hands the resolver the raw attribute any ' +
          'more');
  t.check(/unconfirmed:\s*acsKnown\.unconfirmed/.test(saml2) &&
          /unconfirmed:\s*shireKnown\.unconfirmed/.test(saml11) &&
          /unconfirmed:\s*replyKnown\.unconfirmed/.test(wsfed),
          'each passes the withheld addresses on, so the refusal can name ' +
          'them');
  const cfgBlock = registry.slice(registry.indexOf('function clientConfigOf('),
                                  registry.indexOf('function clientConfigOf(') +
                                  3200);
  t.check(/returnAddressesOf\(fields, 'oauthRedirectUri'\)/.test(cfgBlock) &&
          /redirect_uris:\s*redirects\.registered/.test(cfgBlock),
          'clientConfigOf() builds redirect_uris from returnAddressesOf()');

  applications.deleteApplication(spId);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'return_address_provenance',
  describe: 'a return address a development sighting wrote is marked ' +
            'observed, withheld in product until confirmed or discarded, and ' +
            'every return-address check asks applications.returnAddressesOf()',
  run: run
};
