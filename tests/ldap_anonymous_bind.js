'use strict';
//
// File: ldap_anonymous_bind.js
//
// ===========================================================================
// AN ANONYMOUS LDAP BIND REACHES THE SERVICE'S BIND HANDLER (2026-09-18).
//
// node-ldapjs's Server answers a bind with an empty name and empty credentials
// ITSELF — `_getHandlerChain()` returns a no-op before any route is consulted
// — so `ldap/ldap_server.js`'s bind handler never saw one and product mode's
// documented refusal (48, inappropriateAuthentication, STS-LDAP-0070) never
// happened. `tests/vendored/sts_ldaps.js` found it against a product-mode
// deployment. The fix is the `routeAnonymousBinds` server option in the
// `rcbj/node-ldapjs` fork, and this file holds it:
//
//   1. THE CONTROL: a node-ldapjs server with a bind handler that refuses an
//      anonymous bind answers one with SUCCESS when created without the
//      option — the library's default, which the option exists to change.
//   2. WITH THE OPTION, the same server answers 48 from the handler, while a
//      NAMED bind still reaches it and succeeds — which is also the check that
//      the node-ldapjs installed here is the fork that has the option.
//   3. AS SOURCE, `ldap_server.js` creates both of its servers with the
//      option and asks each one afterwards whether it took.
//
// WHY IN PROCESS: the refusal differs from success only in product mode, and
// every stack the suite starts is development mode, where an anonymous bind
// is supposed to succeed — so no over-HTTP job run locally can see it. The
// servers here are this file's own, on loopback ports it chooses.
// ===========================================================================
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for; its level is LOG_LEVEL, which the harness's logger reads too.
const log = require('bunyan').createLogger({ name: 'ldap_anonymous_bind',
  level: process.env.LOG_LEVEL || 'info' });

function serverWith(ldapjs, routed) {
  log.debug("Entering serverWith().");
  const server = ldapjs.createServer(routed ? { routeAnonymousBinds: true }
                                            : {});
  // The handler the service's own stands in for: refuse the anonymous bind,
  // accept a named one.
  server.bind('', function (req, res, next) {
    if (!String(req.dn || '')) {
      return next(new ldapjs.InappropriateAuthenticationError(
        'anonymous binds are not accepted'));
    }
    res.end();
    return next();
  });
  log.debug("Leaving serverWith().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

function bindOnce(ldapjs, port, dn, password) {
  log.debug("Entering bindOnce(). dn=" + dn);
  log.debug("Leaving bindOnce().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: 'ldap://127.0.0.1:' + port,
                                         reconnect: false });
    client.on('error', function (e) {
      // ldapjs emits on the client as well as calling back; the bind callback
      // below reports it.
      log.debug('The LDAP client emitted an error: ' + e.message);
    });
    client.bind(dn, password, function (e) {
      client.unbind(function () {
        resolve(e ? e.code : 0);
      });
    });
  });
}

module.exports = {
  name: 'ldap_anonymous_bind',
  describe: 'an anonymous LDAP bind reaches the service\'s bind handler, ' +
            'which node-ldapjs would otherwise answer itself',
  run: async function run(t) {
    log.debug("Entering run().");
    const ldapjs = require('ldapjs');
    const plain = await serverWith(ldapjs, false);
    const plainPort = plain.address().port;
    t.equal(await bindOnce(ldapjs, plainPort, '', ''), 0,
            '1. CONTROL: node-ldapjs answers an anonymous bind with success ' +
            'itself, never asking the handler that would refuse it');
    plain.close();

    const wrapped = await serverWith(ldapjs, true);
    const wrappedPort = wrapped.address().port;
    t.equal(await bindOnce(ldapjs, wrappedPort, '', ''), 48,
            '2a. with routeAnonymousBinds, the handler answers it: 48, ' +
            'inappropriateAuthentication');
    t.equal(await bindOnce(ldapjs, wrappedPort, 'cn=someone', 'secret'), 0,
            '2b. and a NAMED bind still reaches the handler and succeeds');
    wrapped.close();

    const source = fs.readFileSync(path.join(ROOT, 'ldap', 'ldap_server.js'),
                                   'utf8');
    // Code, not prose: a comment names the option in backquotes.
    t.check((source.match(/routeAnonymousBinds: true(?!`)/g) || []).length ===
            2,
            '3a. ldap_server.js creates both of its servers with ' +
            'routeAnonymousBinds');
    t.check(/servers\.forEach\(anonymousBindsRouted\)/.test(source),
            '3b. and asks each one afterwards whether the option took');
    log.debug("Leaving run().");
  }
};
