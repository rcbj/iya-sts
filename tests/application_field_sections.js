// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_field_sections.js
//
// ---------------------------------------------------------------------------
// THE DELEGATION / IMPERSONATION SECTION OF THE EVERY PROTOCOL SUB-TAB (#463).
//
// rcbj: the seven delegation fields of an application's Configuration tab
// move into a headed section inside Every protocol, saved by that sub-tab's
// one Save; `krb5TrustedForDelegation` stays on the Kerberos sub-tab. What is
// held:
//
//   1. the seven field rows name the section, in the Every protocol group,
//      and no other row does — the Kerberos flag included;
//   2. the shared grid renderer (`WebKit.fieldGridOf()`, the application's
//      page and the new-application form alike) draws them under the
//      section's heading, after the group's other fields and inside the same
//      group, so one form and one Save hold both.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const WebKit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({
  name: 'application_field_sections',
  level: process.env.LOG_LEVEL || 'info' });

const SEVEN = ['appAllowedToDelegateTo', 'appAllowedToActOnBehalfOf',
               'appNotDelegated', 'appDelegationSemantics',
               'appDefaultDelegationSemantics', 'appDelegationSubjectGroup',
               'appMayAct'];

function run(t) {
  log.debug("Entering run().");
  const rows = applications.applicationFields();
  const sectioned = rows.filter(function (row) {
    return row.section === 'delegation';
  });
  t.check(JSON.stringify(sectioned.map(function (row) {
    return row.attribute;
  }).sort()) === JSON.stringify(SEVEN.slice().sort()) &&
          sectioned.every(function (row) {
            return row.group === 'every' &&
                   row.sectionLabel === 'Delegation / Impersonation';
          }),
          '1. the seven delegation fields name the section, on Every protocol',
          JSON.stringify(sectioned.map(function (row) {
            return [row.attribute, row.group];
          })));
  const krb = rows.filter(function (row) {
    return row.attribute === 'krb5TrustedForDelegation';
  })[0];
  t.check(!krb || (!krb.section && krb.group === 'krb5'),
          '1. and krb5TrustedForDelegation stays on the Kerberos sub-tab ' +
          'with no section', JSON.stringify(krb && [krb.group, krb.section]));

  const every = rows.filter(function (row) {
    return row.group === 'every';
  });
  const html = WebKit.fieldGridOf(every, applications.FIELD_GROUPS, {},
                                  { redraw: '/admin/applications/edit',
                                    showSet: true, protocols: [] });
  const heading = html.indexOf('<h4>Delegation / Impersonation</h4>');
  const firstSectioned = Math.min.apply(null, SEVEN.map(function (name) {
    return html.indexOf('id="fgc-' + name + '"');
  }));
  const plain = every.filter(function (row) {
    return !row.section;
  }).map(function (row) {
    return html.indexOf('id="fgc-' + row.attribute + '"');
  });
  t.check(heading > 0 && firstSectioned > heading &&
          plain.every(function (at) { return at > 0 && at < heading; }) &&
          (html.match(/class="fg-group/g) || []).length === 1,
          '2. the grid draws them under the section heading, after the ' +
          'other Every protocol fields, inside the one group',
          JSON.stringify({ heading: heading, firstSectioned: firstSectioned,
                           plainLast: Math.max.apply(null, plain) }));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application field sections',
  describe: 'the Delegation / Impersonation section of an application\'s ' +
            'Every protocol sub-tab (#463)',
  run: run
};
