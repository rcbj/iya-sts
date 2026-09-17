'use strict';
//
// File: application_form_roles.js
//
// ---------------------------------------------------------------------------
// EVERY ROLE THE APPLICATION REGISTRY DECLARES HAS A SECTION ON THE CREATE
// FORM.
//
// `applications.declarationAttributes()` walks the PROTOCOLS table and gives
// every family attribute a ROLE — identifier, redirect, logout, secret,
// delivery, events. Three readers take that one list: `createApplication()`'s
// accepted fields, `GET /admin-api/applications/new`, and the console form at
// `/admin/applications/new`. The first two take every row whatever its role;
// the form draws a section PER ROLE, by name, in `admin-ui/admin.ts`.
//
// **SO A NEW ROLE REACHES THE API AND SILENTLY NOT THE FORM**, and that is not
// hypothetical: `delivery` (`ssfDeliveryEndpoint`) was accepted by the API from
// the day it was added and drawn by nothing until 2026-09-12. No request fails
// and no page errors — a field simply is not there — which is why this is a
// check on the SOURCE rather than something an HTTP job would notice.
//
// In process, reading `admin-ui/admin.ts` as text: requiring the console would
// register every /admin route on the shared app in `run.js`'s one process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const applications = require('../common/applications');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'application_form_roles',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  const roles = [];
  applications.declarationAttributes().forEach(function (row) {
    if (roles.indexOf(row.role) < 0) {
      roles.push(row.role);
    }
  });
  t.check(roles.length >= 6, 'the registry declares at least the six roles ' +
                             'it had on 2026-09-12',
          roles.join(', '));
  const source = fs.readFileSync(path.join(__dirname, '..', 'admin-ui',
                                           'admin.ts'), 'utf8');
  const drawn = [];
  const re = /declarationFieldsSection\(\s*'([a-z-]+)'/g;
  let m = re.exec(source);
  while (m) {
    drawn.push(m[1]);
    m = re.exec(source);
  }
  roles.forEach(function (role) {
    const attributes = applications.declarationAttributes()
                                   .filter(function (row) {
      return row.role === role;
    }).map(function (row) { return row.attribute; });
    t.check(drawn.indexOf(role) >= 0,
            'the create form draws a section for the "' + role + '" role (' +
            attributes.join(', ') + ')',
            'admin-ui/admin.ts calls declarationFieldsSection() for: ' +
            drawn.join(', '));
  });
  drawn.forEach(function (role) {
    t.check(roles.indexOf(role) >= 0,
            'the form\'s "' + role + '" section names a role the registry ' +
                                     'still declares',
            'declared roles: ' + roles.join(', '));
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application_form_roles',
  describe: 'every role applications.declarationAttributes() declares has a ' +
            'section on /admin/applications/new',
  run: run
};
