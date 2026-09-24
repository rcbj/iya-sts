'use strict';
//
// File: ida_claims_registration.js
//
// ===========================================================================
// OPENID CONNECT FOR IDENTITY ASSURANCE CLAIMS REGISTRATION 1.0 (#128,
// 2026-09-23). rcbj's answers: the job title is `job_title` and `title` the
// honorific; `nationality` is replaced by `nationalities`; the birth names,
// `also_known_as`, `salutation` and the place of birth are this service's own
// attribute types, carried by the directory, SCIM's extension and the portal
// account page.
//
// Held here, in process (development mode, so the persona fills what no
// entry holds):
//
//   1. the ISO 3166-1 and ICAO tables — Germany is ICAO `D`;
//   2. the catalogue: every section 4.1 claim, `job_title`, the section 4.2
//      `address.country_code`, and the conversions (alpha-3, E.164 digits);
//   3. a claims request answering each by name and `address` whole, with
//      `country_code` beside `country`;
//   4. a directory entry's several citizenships as one array;
//   5. federation's inbound names: `title` is the honorific, `job_title` the
//      job, `place_of_birth` by dotted member, the address untouched;
//   6. SCIM: the honorific as `name.honorificPrefix`, the rest in this
//      service's extension, SCIM's own `title` still the job;
//   7. the portal account page's fourth group.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'ida_claims_registration',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  const codes = require('../common/country_codes');
  const vcClaims = require('../oid4vc/vc_claims');
  const claimAttributes = require('../common/claim_attributes');
  const federationMap = require('../federation/federation_map');
  const scimMap = require('../scim/scim_map');
  const inetOrgPerson = require('../common/inetorgperson');

  t.log.info('=== 1. country codes ===');
  t.equal(codes.COUNTRY_COUNT, 249, '1a. all 249 assigned ISO 3166-1 codes');
  t.check(codes.alpha3('us') === 'USA' && codes.alpha3('DE') === 'DEU' &&
          codes.icaoNationality('DE') === 'D' &&
          codes.icaoNationality('NL') === 'NLD' &&
          codes.alpha3('XYZ') === 'XYZ',
          '1b. alpha-3 by ISO, the ICAO nationality code differing for ' +
          'Germany alone, and anything unknown passed through');

  t.log.info('=== 2. the catalogue ===');
  const byClaim = {};
  vcClaims.VC_ATTRIBUTES.forEach(function (row) {
    byClaim[row.claim.join('.')] = row;
  });
  ['place_of_birth.country', 'place_of_birth.region',
   'place_of_birth.locality', 'nationalities', 'birth_family_name',
   'birth_given_name', 'birth_middle_name', 'salutation', 'title',
   'msisdn', 'also_known_as'].forEach(function (claim) {
    t.check(!!byClaim[claim], '2a. the catalogue carries ' + claim);
  });
  t.check(byClaim.title.ldap === 'schacPersonalTitle' &&
          byClaim.job_title && byClaim.job_title.ldap === 'title',
          '2b. `title` is the honorific and the job title is `job_title`');
  t.check(!byClaim.nationality && !byClaim.mobile_phone_number,
          '2c. the replaced names are gone (no back-compat)');
  t.equal(byClaim.msisdn.toClaim('+1-555-0142'), '15550142',
          '2d. msisdn is E.164 digits with no plus');
  const cRow = byClaim['address.country'];
  t.check(cRow.also && cRow.also.claim.join('.') === 'address.country_code' &&
          cRow.also.toClaim('GB') === 'GBR',
          '2e. `c` also becomes address.country_code, alpha-3');

  t.log.info('=== 3. a claims request ===');
  const answered = claimAttributes.requestedClaimsFor('ida-claims-alice',
    ['nationalities', 'address', 'address.country_code', 'title',
     'job_title', 'msisdn', 'place_of_birth', 'salutation']);
  const c = answered.claims;
  t.check(Array.isArray(c.nationalities) && c.nationalities.length === 1 &&
          /^([A-Z]{3}|D)$/.test(c.nationalities[0]),
          '3a. nationalities is an array of ICAO codes',
          JSON.stringify(c.nationalities));
  t.check(c.address && /^[A-Z]{2}$/.test(c.address.country) &&
          c.address.country_code === codes.alpha3(c.address.country),
          '3b. the whole address carries country_code beside country',
          JSON.stringify(c.address));
  t.check(typeof c.title === 'string' && /^(Dr|Prof|Prof Dr)$/.test(c.title) &&
          typeof c.job_title === 'string' && c.job_title !== c.title,
          '3c. title is an honorific, job_title the job',
          c.title + ' / ' + c.job_title);
  t.check(/^[0-9]+$/.test(c.msisdn), '3d. msisdn is digits', c.msisdn);
  t.check(c.place_of_birth && /^[A-Z]{3}$/.test(c.place_of_birth.country) &&
          c.place_of_birth.locality,
          '3e. place_of_birth is an object, its country alpha-3',
          JSON.stringify(c.place_of_birth));
  t.check(answered.unknown.indexOf('address.country_code') < 0 &&
          answered.unknown.indexOf('salutation') < 0,
          '3f. every name resolved', JSON.stringify(answered.unknown));
  const requestable = claimAttributes.requestableClaims().map(function (r) {
    return r.claim;
  });
  t.check(requestable.indexOf('address.country_code') >= 0 &&
          requestable.indexOf('nationalities') >= 0,
          '3g. and both are listed as requestable');

  t.log.info('=== 4. several citizenships ===');
  const row = byClaim.nationalities;
  t.check(row.multi === true && row.toClaim('SE') === 'SWE',
          '4a. the row is multi-valued and converts each value');

  t.log.info('=== 5. federation\'s inbound names ===');
  const incoming = {};
  federationMap.DEFAULT_MAP.forEach(function (one) {
    incoming[one.incoming.toLowerCase()] = one.ldap;
  });
  t.check(incoming.title === 'schacPersonalTitle' &&
          incoming.job_title === 'title' &&
          incoming['place_of_birth.country'] === 'placeOfBirthCountry' &&
          incoming.country === 'c' && incoming.locality === 'l' &&
          incoming.msisdn === 'mobile',
          '5a. title, job_title, place_of_birth.* and msisdn map to their ' +
          'attributes, and the address names still to the address',
          JSON.stringify({ title: incoming.title, job: incoming.job_title,
                           pob: incoming['place_of_birth.country'],
                           country: incoming.country }));
  const flat = federationMap.flatten({ place_of_birth: { country: 'SE',
    locality: 'Malmö' }, address: { country: 'NL' } });
  t.check(flat['place_of_birth.country'][0] === 'SE' &&
          flat.country[0] === 'NL' && !flat['place_of_birth'],
          '5b. flatten() names place_of_birth\'s members by their dotted ' +
          'name, and leaves the address\'s bare', JSON.stringify(flat));

  t.log.info('=== 6. SCIM ===');
  const resource = scimMap.toScimUser({
    dn: 'uid=ida,ou=users,dc=example,dc=com',
    attributes: { uid: ['ida'], cn: ['Ida Example'], sn: ['Example'],
                  title: ['Staff Researcher'], schacPersonalTitle: ['Dr'],
                  salutation: ['Ms'], birthFamilyName: ['Born'],
                  placeOfBirthLocality: ['Malmö'] } });
  // Extension members come back flat, at `<urn>:<member>`, until the SCIM
  // handler nests them; either form is read.
  const ext = function (member) {
    const nested = resource[scimMap.IYA_STS_USER_SCHEMA] || {};
    const flatKey = resource[scimMap.IYA_STS_USER_SCHEMA + ':' + member];
    return flatKey !== undefined ? flatKey : nested[member];
  };
  t.check(resource.title === 'Staff Researcher' &&
          resource.name && resource.name.honorificPrefix === 'Dr' &&
          ext('salutation') === 'Ms' && ext('birthFamilyName') === 'Born' &&
          ext('placeOfBirthLocality') === 'Malmö',
          '6a. SCIM\'s title is the job, the honorific is ' +
          'name.honorificPrefix, and the rest are in this service\'s ' +
          'extension', JSON.stringify(resource).slice(0, 400));

  t.log.info('=== 7. the portal account page ===');
  const classes = inetOrgPerson.classes();
  const group = classes[classes.length - 1];
  t.check(group.id === 'identityClaims' &&
          group.attributes.map(function (a) { return a.ldap; })
            .indexOf('birthFamilyName') >= 0,
          '7a. the account page draws the Identity Assurance claims as a ' +
          'group of their own');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ida claims registration',
  describe: 'OpenID Connect for Identity Assurance Claims Registration 1.0 ' +
            '(#128): the catalogue, the conversions, federation, SCIM and ' +
            'the account page',
  run: run
};
