'use strict';
//
// File: ldap_diagnostic_message.js
//
// ===========================================================================
// A REFUSAL'S TEXT REACHES AN LDAP CLIENT AS ITS diagnosticMessage (#261).
//
// node-ldapjs puts the message of an error a handler passes to `next()` in
// `res.errorMessage`, which `@ldapjs/messages` never encodes, so every result
// left with an EMPTY diagnosticMessage (RFC 4511 section 4.1.9): a client of
// this directory saw 53 for STS-LDAP-0111 and never the door the refusal
// names. The fix is the `encodeErrorMessage` server option in the
// `rcbj/node-ldapjs` fork, and this file holds it:
//
//   1. THE CONTROL: a node-ldapjs server without the option sends a refusal
//      with no diagnostic message — the library's default.
//   2. WITH THE OPTION, the refusal's message arrives, and an uncaught
//      exception in a handler arrives as `internal error` rather than as its
//      own message — which is also the check that the node-ldapjs installed
//      here is the fork that has the option.
//   3. AS SOURCE, `ldap_server.js` creates both of its servers with the
//      option and asks each one afterwards whether it took.
//
// The over-network half, against the service itself over LDAPS, is
// `tests/vendored/sts_credential_signals.js` section c.
// ===========================================================================
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for; its level is LOG_LEVEL, which the harness's logger reads too.
const log = require('bunyan').createLogger({ name: 'ldap_diagnostic_message',
  level: process.env.LOG_LEVEL || 'info' });

function serverWith(ldapjs, encoded) {
  log.debug("Entering serverWith().");
  const server = ldapjs.createServer(encoded ? { encodeErrorMessage: true }
                                             : {});
  // A refusal with a message, as `credentialWriteRefusal()` makes one.
  server.modify('dc=test', function (req, res, next) {
    return next(new ldapjs.UnwillingToPerformError(
      'stsTotpCredential is a credential; use /portal/mfa'));
  });
  // A handler that throws: its message describes the server, not the
  // request.
  server.del('dc=test', function () {
    throw new Error('an internal detail');
  });
  log.debug("Leaving serverWith().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

function refusalsFrom(ldapjs, port) {
  log.debug("Entering refusalsFrom().");
  log.debug("Leaving refusalsFrom().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: 'ldap://127.0.0.1:' + port,
                                         reconnect: false });
    client.on('error', function (e) {
      // ldapjs emits on the client as well as calling back; the callbacks
      // below report it.
      log.debug('The LDAP client emitted an error: ' + e.message);
    });
    const change = new ldapjs.Change({ operation: 'replace',
      modification: new ldapjs.Attribute({ type: 'cn', values: ['x'] }) });
    client.modify('dc=test', change, function (modified) {
      client.del('dc=test', function (deleted) {
        client.unbind(function () {
          resolve({
            modify: { code: modified ? modified.code : 0,
                      diagnostic: modified ? modified.diagnosticMessage : '' },
            del: { code: deleted ? deleted.code : 0,
                   diagnostic: deleted ? deleted.diagnosticMessage : '' }
          });
        });
      });
    });
  });
}

module.exports = {
  name: 'ldap_diagnostic_message',
  describe: 'an LDAP refusal\'s text reaches the client as its ' +
            'diagnosticMessage, which node-ldapjs would otherwise leave empty',
  run: async function run(t) {
    log.debug("Entering run().");
    const ldapjs = require('ldapjs');
    const plain = await serverWith(ldapjs, false);
    const control = await refusalsFrom(ldapjs, plain.address().port);
    plain.close();
    t.equal(control.modify.code, 53, '1a. CONTROL: the refusal is 53');
    t.equal(control.modify.diagnostic, '',
            '1b. and node-ldapjs sends it with no diagnostic message');

    const encoded = await serverWith(ldapjs, true);
    const answered = await refusalsFrom(ldapjs, encoded.address().port);
    encoded.close();
    t.equal(answered.modify.code, 53,
            '2a. with encodeErrorMessage, the refusal is still 53');
    t.equal(answered.modify.diagnostic,
            'stsTotpCredential is a credential; use /portal/mfa',
            '2b. and its message is the diagnostic message');
    t.equal(answered.del.code, 1,
            '2c. an uncaught exception in a handler is operationsError');
    t.equal(answered.del.diagnostic, 'internal error',
            '2d. sent as "internal error", not as its own message');

    const source = fs.readFileSync(path.join(ROOT, 'ldap', 'ldap_server.js'),
                                   'utf8');
    // Code, not prose: a comment names the option in backquotes.
    t.check((source.match(/encodeErrorMessage: true(?!`)/g) || []).length ===
            2,
            '3a. ldap_server.js creates both of its servers with ' +
            'encodeErrorMessage');
    t.check(/servers\.forEach\(diagnosticMessagesEncoded\)/.test(source),
            '3b. and asks each one afterwards whether the option took');
    log.debug("Leaving run().");
  }
};
