// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/tools/cross_realm_grants.js
//
// ===========================================================================
// ADMITTING A PARTNER REALM'S PRINCIPALS TO A REALM'S SERVICES, FOR THE
// CROSS-REALM KERBEROS TESTS (#430).
//
// rcbj's decision of 2026-10-19: a principal that arrived through a Kerberos
// trust holds NO built-in role — EVERYBODY and ALL_AUTHENTICATED_USERS mean
// "authenticated in THIS realm" — and only the roles granted to its name or
// to one of its filtered SIDs (`common/roles.js`). An application requiring
// only EVERYBODY, the default, therefore admits nobody from another realm,
// and every test that carries a person or a service across a trust has to
// do what an operator would: grant a role to the partner's principals and
// narrow the services they reach to require it.
//
// This does it the way Active Directory's selective authentication is
// usually set up: one role, `trust-partners`, granted to each partner
// domain's Domain Users (RID 513) and Domain Computers (RID 515) — SIDs a
// PAC's group list carries and SID filtering never removes — and each named
// service's entry requiring EVERYBODY or that role, so the realm's own
// people are admitted exactly as before.
//
// A SERVICE IS NARROWED UNDER BOTH OF ITS NAMES. The issuance gate at the
// TGS names the application by the bare SPN (`HTTP/web.beta.test`), and the
// delegation policy by the SPN with its realm (`HTTP/web.beta.test@BETA.TEST`,
// the seeded entries' identifier); an entry is made for whichever does not
// exist. INVENTED FIXTURES: the role name, and the bare-named entries.
// ===========================================================================
const realms = require('../../common/realms');
const roles = require('../../common/roles');
const applications = require('../../common/applications');

const log = require('bunyan').createLogger({
  name: 'cross_realm_grants', level: process.env.LOG_LEVEL || 'info' });

/**
 * The role the partners' principals are granted.
 */
const ROLE = 'trust-partners';

/**
 * Grants `trust-partners` to the partners' Domain Users and Domain
 * Computers, and narrows each service to EVERYBODY or that role, in one
 * trust realm.
 *
 * @param realm - the trust realm (a realms.get() row)
 * @param partnerSids - the partner domains' SIDs, `S-1-5-21-X-Y-Z`
 * @param services - the services' SPNs without a realm, `HTTP/web.beta.test`
 * @param krbRealm - the realm's Kerberos realm name
 * @returns the errors met, empty when every write succeeded
 */
function admitPartners(realm, partnerSids, services, krbRealm) {
  log.debug("Entering admitPartners(). " + krbRealm);
  const errors = [];
  realms.run(realm, function () {
    require('../../kerberos/krb5_delegation').ensureSeeded();
    const groups = [];
    partnerSids.forEach(function (sid) {
      groups.push(sid + '-513', sid + '-515');
    });
    const wrote = roles.write(ROLE, {
      description: 'Principals of the partner realms (' + __filename + ')',
      groups: groups });
    if (!wrote || !wrote.ok) {
      errors.push('role: ' + JSON.stringify((wrote && wrote.errors) || []));
    }
    services.forEach(function (spn) {
      [spn, spn + '@' + krbRealm].forEach(function (id) {
        if (!applications.get(id)) {
          const made = applications.createApplication({
            identifier: id, kind: 'kerberos-service', protocols: ['krb5'],
            fields: { appRequiredRole: ['EVERYBODY', ROLE] },
            actor: __filename });
          if (!made || !made.ok) {
            errors.push(id + ': ' +
                        JSON.stringify((made && made.errors) || []));
          }
          return;
        }
        ['EVERYBODY', ROLE].forEach(function (value) {
          const set = applications.updateApplication(id, {
            attribute: 'appRequiredRole', mode: 'add', value: value,
            actor: __filename });
          if (!set || !set.ok) {
            errors.push(id + ' ' + value + ': ' +
                        JSON.stringify((set && set.errors) || []));
          }
        });
      });
    });
  });
  log.debug("Leaving admitPartners(). " + errors.length + " error(s).");
  return errors;
}

module.exports = { ROLE: ROLE, admitPartners: admitPartners };
