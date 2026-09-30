// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: admin_paging_directory.js
//
// ===========================================================================
// PAGE BEFORE PER-ROW WORK, OVER THE DIRECTORY (#352, part "dir").
//
// On testidp (29,267 people) the console's lists built and decorated the
// whole population to show one page. This file seeds a realm much larger than
// a page — three thousand people, a hundred and fifty applications, forty
// groups — and asserts, for each list #352's "dir" part changed, that the
// EXPENSIVE work is bounded by the page or constant per request, not by the
// population:
//
//   * the application registry: one parse of ou=applications per version,
//     however many lookups a page makes (`allApplications()` counted), and no
//     `keystore.open` for a row nobody reads the key of;
//   * the people: `persons()`, `allPersons()` and the roster's candidates
//     read the kept, sorted keys — no walk of the realm once they are kept;
//   * the groups: one walk for the list and one for the memberOf index,
//     however many groups (the walk of the realm counted);
//   * /admin/ldap/directory: attributes copied for the shown rows only
//     (`withheldValues()` counted);
//   * Kerberos principals: only the page described;
//   * the cells page: a keyset page reading `limit` entries;
//   * devices: one read of the register for a list and its total;
//   * a federation relationship's links: only the page parsed.
//
// And that each answer is the one the old code gave: every one is checked
// against the old algorithm, rebuilt here from public functions.
//
// COUNTS, NOT CLOCKS. The timings logged are information only.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const realms = require('../common/realms');
const config = require('../common/config');
const keystore = require('../common/keystore');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const consent = require('../common/consent');
const devices = require('../common/devices');
const credentials = require('../common/credentials');
const krb5PersonKeys = require('../kerberos/krb5_person_keys');
const federation = require('../federation/federation');
const fedLinks = require('../federation/federation_links');
const adminViews = require('../admin-core/admin_views');
const delegationPolicy = require('../common/delegation_policy');
const rbac = require('../admin-ui/admin_rbac');
const app = require('../common/app');
// /admin/ldap/directory's view is registered with the console's routes.
require('../admin-ui/admin').registerRoutes(app);

const log = require('bunyan').createLogger({ name: 'admin_paging_directory',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'pgd' + crypto.randomBytes(3).toString('hex');
const PEOPLE = 3000;
const APPS = 150;
const GROUPS = 40;
const REL = TAG + '-rel';
const ISSUER = 'https://' + TAG + '.example.com';

// Count calls to `holder[name]`, for the length of `fn`.
function counting(holder, name, fn) {
  log.debug("Entering counting(). " + name);
  const original = holder[name];
  const seen = { calls: 0, rows: 0 };
  holder[name] = function () {
    seen.calls++;
    if (Array.isArray(arguments[0])) {
      seen.rows += arguments[0].length;
    }
    return original.apply(this, arguments);
  };
  try {
    seen.answer = fn();
  } finally {
    holder[name] = original;
  }
  log.debug("Leaving counting().");
  return seen;
}

function timed(t, what, fn) {
  log.debug("Entering timed().");
  const started = process.hrtime.bigint();
  const out = fn();
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  t.log.info('    (information only) ' + what + ': ' + ms.toFixed(1) + ' ms');
  log.debug("Leaving timed().");
  return out;
}

function req(query) {
  log.debug("Entering req().");
  log.debug("Leaving req().");
  return { query: query || {}, headers: {}, protocol: 'http',
           get: function () {
             return '127.0.0.1';
           } };
}

function personName(i) {
  log.debug("Entering personName().");
  log.debug("Leaving personName().");
  return TAG + '-p' + String(i).padStart(5, '0');
}

// ---------------------------------------------------------------------------
// THE POPULATION.
// ---------------------------------------------------------------------------
function seed(t) {
  log.debug("Entering seed().");
  const first = ldap.createUser(personName(0), { invent: false });
  if (!first.ok) {
    t.bad('the first person could not be created',
          JSON.stringify(first.errors || first));
    log.debug("Leaving seed(). Refused.");
    return false;
  }
  const groupsDn = ldap.groupsDn();
  const created = ldap.createGroup(TAG + '-g0', { members: [] });
  if (!created.ok) {
    t.bad('the first group could not be created', JSON.stringify(created));
    log.debug("Leaving seed(). Refused.");
    return false;
  }
  for (let g = 1; g < GROUPS; g++) {
    ldap.createGroup(TAG + '-g' + g, { members: [] });
  }
  const usersDn = ldap.usersDn();
  let written = 0;
  for (let i = 1; i < PEOPLE; i++) {
    const name = personName(i);
    const attributes = {
      objectclass: ['inetOrgPerson'], uid: [name], cn: [name], sn: [name],
      mail: [name + '@example.com'],
      stskrb5keyinfo: [JSON.stringify({ kvno: 2, etypes: [18],
                                        stamp: 'x', derivedAt: '',
                                        event: 'set' })]
    };
    // Every fiftieth person claims a group their group does not list.
    if (i % 50 === 0) {
      attributes.memberof = ['cn=' + TAG + '-g' + (i % GROUPS) + ',' +
                             groupsDn];
    }
    // Every other person is linked through the relationship.
    if (i % 2 === 0) {
      attributes.federationlink = [REL + ' ' + ISSUER + ' sub-' + i];
    }
    // A handful carry a delegation flag.
    if (i % 500 === 0) {
      attributes.stsnotdelegated = ['TRUE'];
    }
    const out = ldap.writePerson('uid=' + name + ',' + usersDn, attributes);
    if (out.ok) {
      written++;
    }
  }
  // And a few group members that the groups do list.
  for (let g = 0; g < GROUPS; g++) {
    for (let m = 1; m <= 5; m++) {
      ldap.addGroupMember(TAG + '-g' + g, personName(g * 5 + m));
    }
  }
  for (let a = 0; a < APPS; a++) {
    const id = TAG + '-app' + String(a).padStart(3, '0');
    const fields = { oauthClientId: id + '-client',
                     oauthAudience: 'https://' + id + '.example.com',
                     oauthPermissionBaseUri: 'https://' + id +
                                             '.example.com/',
                     oauthPermission: ['read', 'write'] };
    if (a % 10 === 0) {
      fields.appRequiredRole = ['staff'];
    }
    if (a % 15 === 0) {
      fields.appAllowedToDelegateTo = ['https://' + TAG + '-app' +
                                       String((a + 1) % APPS).padStart(3, '0') +
                                       '.example.com'];
    }
    applications.createApplication({ identifier: id, protocols: ['oauth2'],
                                     fields: fields });
    // A key "sealed at rest" on every third, so the listing has sealed
    // members it must not open.
    if (a % 3 === 0) {
      applications.updateApplication(id, {
        attribute: 'oauthAssertionPrivateKey', mode: 'set',
        value: '$aesgcm$' + TAG + '-' + a });
    }
    consent.grantGlobal(id, 'https://' + TAG + '-app000.example.com/read',
                        'admin_paging_directory');
  }
  t.check(written === PEOPLE - 1 && applications.list().length >= APPS,
          'the realm holds ' + PEOPLE + ' people, ' + GROUPS + ' groups and ' +
          APPS + ' applications',
          written + ' people written, ' + applications.list().length +
          ' application(s)');
  log.debug("Leaving seed().");
  return true;
}

// ---------------------------------------------------------------------------
// THE APPLICATION REGISTRY.
// ---------------------------------------------------------------------------
function checkApplications(t) {
  log.debug("Entering checkApplications().");
  t.log.info('=== the application registry: one parse per version ===');
  const backing = applications.directoryInstalled();
  const ids = applications.list().map(function (row) {
    return row.identifier;
  }).filter(function (id) {
    return id.indexOf(TAG) === 0;
  });
  // The old answers, by the old algorithm: a filter over the whole list.
  const oldFind = function (attribute, value) {
    log.debug("Entering oldFind().");
    log.debug("Leaving oldFind().");
    return applications.list().filter(function (row) {
      const v = row.fields[attribute];
      return (Array.isArray(v) ? v : (v ? [v] : [])).map(String)
        .indexOf(value) >= 0;
    })[0] || null;
  };
  let opens = 0;
  const open = keystore.open;
  keystore.open = function () {
    opens++;
    return 'OPENED';
  };
  let reads;
  try {
    reads = counting(backing, 'allApplications', function () {
      let same = true;
      ids.forEach(function (id) {
        const client = applications.forClientId(id + '-client');
        const aud = applications.forAudience('https://' + id +
                                             '.example.com');
        const perm = applications.forPermission('https://' + id +
                                                '.example.com/read');
        if (!client || client.identifier !== id ||
            !aud || aud.identifier !== id ||
            !perm || perm.identifier !== id) {
          same = false;
        }
      });
      return same;
    });
    t.check(reads.answer,
            'forClientId, forAudience and forPermission find every ' +
            'application by its own values', String(ids.length));
    t.check(reads.calls <= 1,
            'and ' + (3 * ids.length) + ' lookups read ou=applications at ' +
            'most ONCE — they were a whole list() each',
            reads.calls + ' read(s)');
    t.check(opens === 0,
            'no sealed key was opened by any of them — nothing read one',
            opens + ' open(s)');
    const listed = applications.list();
    t.check(opens === 0, 'nor by list() of every application',
            opens + ' open(s)');
    const sealed = listed.filter(function (row) {
      return Object.prototype.hasOwnProperty.call(row.fields,
                                                  'oauthAssertionPrivateKey');
    });
    const page = JSON.parse(JSON.stringify(sealed.slice(0, 25)));
    t.check(opens === Math.min(25, sealed.length) &&
            page.every(function (row) {
              return row.fields.oauthAssertionPrivateKey === 'OPENED';
            }),
            'serialising a page opens the keys ON that page, and they read ' +
            'as the opened value, as before',
            opens + ' open(s) for ' + page.length + ' row(s)');
    // A caller's copy is its own.
    listed[0].fields.oauthClientId = 'changed-by-a-caller';
    listed[0].kinds.push('changed');
    const again = applications.list()[0];
    t.check(again.fields.oauthClientId !== 'changed-by-a-caller' &&
            again.kinds.indexOf('changed') < 0,
            'a caller that changes what list() handed it changes nothing ' +
            'the next caller sees', JSON.stringify(again.fields.oauthClientId));
    // And the answers are the old ones.
    const probe = ids[7];
    const old = oldFind('oauthClientId', probe + '-client');
    const now = applications.forClientId(probe + '-client');
    t.check(JSON.stringify(old) === JSON.stringify(now),
            'forClientId answers exactly what a filter over list() found');
  } finally {
    keystore.open = open;
  }
  // A write moves the version, and the next lookup sees it.
  applications.updateApplication(ids[3], { attribute: 'oauthClientId',
                                           mode: 'add',
                                           value: TAG + '-added' });
  const found = applications.forClientId(TAG + '-added');
  t.check(!!found && found.identifier === ids[3],
          'a value written a moment ago is found by the next lookup',
          found ? found.identifier : 'nothing');
  log.debug("Leaving checkApplications().");
}

// ---------------------------------------------------------------------------
// THE REGISTERS BUILT OVER THE APPLICATIONS: roles, consent, delegation.
// ---------------------------------------------------------------------------
function checkRegisters(t) {
  log.debug("Entering checkRegisters().");
  t.log.info('=== roles, consent and the delegation policy ===');
  const backing = applications.directoryInstalled();
  // A lookup first, so the listing is current before counting.
  applications.list();
  const roles = counting(backing, 'allApplications', function () {
    return counting(backing, 'readApplication', function () {
      return timed(t, 'rolesRegister()', function () {
        return adminViews.rolesRegister();
      });
    });
  });
  t.check(roles.calls === 0 && roles.answer.calls === 0,
          '/admin/roles over ' + APPS + ' applications reads no application ' +
          'entry and parses nothing — it was two reads per application and ' +
          'a list() per permission',
          roles.calls + ' list read(s), ' + roles.answer.calls +
          ' entry read(s)');
  const register = roles.answer.answer;
  const mine = register.requiring.filter(function (one) {
    return one.application.indexOf(TAG) === 0;
  });
  t.check(mine.length === APPS / 10 &&
          register.permissions.filter(function (one) {
            return one.application.indexOf(TAG) === 0;
          }).length === APPS * 2,
          'and it lists what the old one did: the narrowed applications ' +
          'and every permission', mine.length + ' narrowed');
  const consented = counting(backing, 'allApplications', function () {
    return counting(backing, 'readApplication', function () {
      return timed(t, 'consentPageView()', function () {
        return adminViews.consentPageView({});
      });
    });
  });
  t.check(consented.calls === 0 && consented.answer.calls <= APPS,
          '/admin/consent over ' + APPS + ' applications parses nothing and ' +
          'reads at most one entry per global consent (holdsPermission()\'s ' +
          'fallback by identifier) — it was a list() per scope',
          consented.calls + ' list read(s), ' + consented.answer.calls +
          ' entry read(s)');
  const globals = consented.answer.answer.register.globals.filter(
    function (one) {
      return one.client.indexOf(TAG) === 0;
    });
  t.check(globals.length === APPS && globals.every(function (one) {
    return one.permission === 'read';
  }), 'and every global consent names the permission it is', String(
    globals.length));
  const policy = counting(backing, 'allApplications', function () {
    return timed(t, 'delegationPolicy.list()', function () {
      return delegationPolicy.list();
    });
  });
  const pairs = policy.answer.pairs.filter(function (one) {
    return String(one.intermediary).indexOf(TAG) === 0;
  });
  t.check(policy.calls === 0 && pairs.length === APPS / 15 &&
          pairs.every(function (one) {
            return one.targetKnown;
          }),
          'the delegation policy resolves every target through the kept ' +
          'lookups, with no read of the registry',
          policy.calls + ' list read(s), ' + pairs.length + ' pair(s)');
  log.debug("Leaving checkRegisters().");
}

// ---------------------------------------------------------------------------
// THE PEOPLE.
// ---------------------------------------------------------------------------
function checkPeople(t) {
  log.debug("Entering checkPeople().");
  t.log.info('=== the people: sorted keys, kept ===');
  const all = timed(t, 'allPersons() (first)', function () {
    return ldap.allPersons();
  });
  const keys = all.map(function (entry) {
    return ldap.normalizeDn(entry.dn);
  });
  const sorted = keys.slice(0).sort(function (a, b) {
    return a < b ? -1 : 1;
  });
  t.check(all.length >= PEOPLE &&
          JSON.stringify(keys) === JSON.stringify(sorted),
          'allPersons() lists every person in normalised-DN order, as before',
          all.length + ' people');
  const oldNames = all.map(function (entry) {
    return ldap.usernameOfEntry(entry);
  }).filter(function (name) {
    return !!name;
  });
  const walks = counting(ldap.entries, 'forEach', function () {
    return timed(t, 'personNames() (kept)', function () {
      return ldap.personNames();
    });
  });
  t.check(walks.calls === 0 &&
          JSON.stringify(walks.answer) === JSON.stringify(oldNames),
          'personNames() answers the old persons() list without walking the ' +
          'realm once the keys are kept',
          walks.calls + ' walk(s), ' + walks.answer.length + ' name(s)');
  const candidates = counting(ldap.entries, 'forEach', function () {
    return rbac.candidates([], realms.currentId());
  });
  const oldCandidates = {};
  all.forEach(function (entry) {
    const rdn = String(entry.dn).split(',')[0];
    const eq = rdn.indexOf('=');
    const name = eq > 0 ? rdn.slice(eq + 1) : '';
    if (name && ldap.nameUsableInDn(name)) {
      oldCandidates[name.toLowerCase()] = true;
    }
  });
  t.check(candidates.calls === 0 &&
          candidates.answer.length === Object.keys(oldCandidates).length,
          'the roster\'s candidates come from the kept DNs, the same names',
          candidates.calls + ' walk(s), ' + candidates.answer.length);
  // A write moves the clock, and the next read sees the person.
  const late = ldap.createUser(TAG + '-late', { invent: false });
  t.check(late.ok && ldap.personNames().indexOf(TAG + '-late') >= 0,
          'a person created a moment ago is in the next list');
  log.debug("Leaving checkPeople().");
}

// ---------------------------------------------------------------------------
// THE CELLS PAGE'S KEYSET.
// ---------------------------------------------------------------------------
function checkResidents(t) {
  log.debug("Entering checkResidents().");
  t.log.info('=== a cell\'s residents, a page at a time ===');
  // The old algorithm, over allPersons().
  const old = function (after, limit) {
    log.debug("Entering old().");
    const page = ldap.allPersons().filter(function (entry) {
      return String(entry.origin || '').indexOf('projection') !== 0;
    }).map(function (entry) {
      const a = entry.attributes || {};
      // A HOT PATH: per attribute per person, so no Entering/Leaving pair —
      // it would drown the log.
      const one = function (k) {
        const key = Object.keys(a).filter(function (n) {
          return n.toLowerCase() === k;
        })[0];
        const v = key ? a[key] : '';
        return String(Array.isArray(v) ? v[0] || '' : v || '');
      };
      return { name: one('uid').toLowerCase(), uuid: one('entryuuid'),
               displayName: one('displayname') || one('cn') };
    }).filter(function (p) {
      return p.name && p.name > after;
    }).sort(function (x, y) {
      return x.name < y.name ? -1 : (x.name > y.name ? 1 : 0);
    });
    const out = page.slice(0, limit);
    log.debug("Leaving old().");
    return { people: out,
             next: page.length > limit ? out[out.length - 1].name : '' };
  };
  ldap.residentsPage('', 1);
  const after = personName(1500).toLowerCase();
  const reads = counting(ldap.entries, 'get', function () {
    return counting(ldap.entries, 'forEach', function () {
      return timed(t, 'AFTER: residentsPage()', function () {
        return ldap.residentsPage(after, 50);
      });
    });
  });
  const got = reads.answer.answer;
  const expected = timed(t, 'BEFORE: the old filter-sort-slice over ' +
                            'allPersons()', function () {
    return old(after, 50);
  });
  t.check(JSON.stringify(got.people) === JSON.stringify(expected.people) &&
          (got.more ? got.people[got.people.length - 1].name : '') ===
            expected.next,
          'residentsPage() answers the page the old filter-sort-slice did',
          got.people.length + ' people, next ' + expected.next);
  t.check(reads.answer.calls === 0 && reads.calls <= 50,
          'reading at most one entry per row shown and walking nothing',
          reads.answer.calls + ' walk(s), ' + reads.calls + ' entry read(s)');
  log.debug("Leaving checkResidents().");
}

// ---------------------------------------------------------------------------
// THE GROUPS AND THE ROSTER.
// ---------------------------------------------------------------------------
function checkGroups(t) {
  log.debug("Entering checkGroups().");
  t.log.info('=== the groups: one walk, not one per group ===');
  const walks = counting(ldap.entries, 'forEach', function () {
    return timed(t, 'groupsFor(\'\')', function () {
      return ldap.groupsFor('');
    });
  });
  const mine = walks.answer.groups.filter(function (g) {
    return String(g.cn).indexOf(TAG) === 0;
  });
  t.check(walks.calls <= 2 && mine.length === GROUPS,
          'the list of ' + walks.answer.groups.length + ' groups walks the ' +
          'realm at most twice — the list and the memberOf index — where it ' +
          'walked once per group', walks.calls + ' walk(s)');
  // The old claimed count, rebuilt: people whose memberOf names the group
  // and whom it does not list.
  const people = ldap.allPersons();
  const wrong = mine.filter(function (g) {
    const detail = ldap.groupsFor(g.dn).group;
    const listed = {};
    detail.members.forEach(function (m) {
      listed[ldap.normalizeDn(m.dn)] = true;
    });
    const claimed = people.filter(function (p) {
      const values = (p.attributes.memberOf || []).map(ldap.normalizeDn);
      return values.indexOf(ldap.normalizeDn(g.dn)) >= 0 &&
             !listed[ldap.normalizeDn(p.dn)];
    });
    return claimed.length !== g.claimedCount ||
           claimed.length !== detail.claimed.length ||
           g.memberCount !== detail.memberCount ||
           g.presentCount !== detail.presentCount ||
           g.danglingCount !== detail.danglingCount;
  });
  t.check(wrong.length === 0,
          'every group\'s counts and claimants are what resolving each ' +
          'member and walking for claims gave',
          wrong.map(function (g) {
            return g.cn;
          }).join(', ') || 'all ' + mine.length);
  const again = counting(ldap.entries, 'forEach', function () {
    return mine.map(function (g) {
      return ldap.groupsFor(g.dn).group.claimed.length;
    });
  });
  t.check(again.calls <= mine.length,
          'and a group\'s own page walks once for the list, not again for ' +
          'its claimants', again.calls + ' walk(s) for ' + mine.length +
          ' page(s)');
  log.debug("Leaving checkGroups().");
}

// ---------------------------------------------------------------------------
// /admin/ldap/directory.
// ---------------------------------------------------------------------------
function checkDirectoryView(t) {
  log.debug("Entering checkDirectoryView().");
  t.log.info('=== /admin/ldap/directory: copied for the shown rows only ===');
  const view = counting(krb5PersonKeys, 'withheldValues', function () {
    return timed(t, '/admin/ldap/directory page 3', function () {
      return ldap.ldapDirectoryView(req({ page: '3', per: '25' }));
    });
  });
  const json = view.answer.json;
  const attributesShown = json.entries.reduce(function (n, entry) {
    return n + Object.keys(entry.attributes).length;
  }, 0);
  t.check(json.shown === 25 && json.count >= PEOPLE,
          'a page of 25 of every entry in the realm',
          json.shown + ' of ' + json.count);
  t.check(view.calls === attributesShown,
          'and only the shown rows\' attributes were copied and withheld — ' +
          'it was every attribute of every entry', view.calls +
          ' attribute(s) transformed for ' + attributesShown + ' shown');
  // The old order: every DN, localeCompare.
  const dns = [];
  ldap.entries.forEach(function (stored) {
    dns.push(stored.dn);
  });
  dns.sort(function (a, b) {
    return a.localeCompare(b);
  });
  t.check(JSON.stringify(json.entries.map(function (e) {
    return e.dn;
  })) === JSON.stringify(dns.slice(50, 75)) && json.count === dns.length,
  'and the rows are the ones the old localeCompare sort put on page 3');
  const searched = ldap.ldapDirectoryView(req({ q: 'sub-1234' })).json;
  t.check(searched.matched === 1 && searched.entries.length === 1 &&
          searched.entries[0].dn.indexOf(personName(1234)) >= 0,
          'a q that only a VALUE matches still finds its entry',
          searched.matched + ' matched');
  log.debug("Leaving checkDirectoryView().");
}

// ---------------------------------------------------------------------------
// KERBEROS PRINCIPALS.
// ---------------------------------------------------------------------------
function checkKerberos(t) {
  log.debug("Entering checkKerberos().");
  t.log.info('=== Kerberos principals: only the page described ===');
  const described = counting(krb5PersonKeys, 'describePeople', function () {
    return timed(t, 'kerberosPrincipalsJson() page 2', function () {
      return adminViews.kerberosPrincipalsJson(req({ peoplePage: '2',
                                                     per: '25' }));
    });
  });
  const json = described.answer;
  const whole = krb5PersonKeys.listPeople();
  t.check(json.peopleTotal === whole.length && whole.length >= PEOPLE - 1,
          'the total is every person holding keys', String(json.peopleTotal));
  t.check(described.rows === json.people.length && json.people.length === 25,
          'and only the 25 on the page were parsed and stamped',
          described.rows + ' described');
  t.check(JSON.stringify(json.people.map(function (p) {
    return p.username;
  })) === JSON.stringify(whole.slice(25, 50).map(function (p) {
    return p.username;
  })) && JSON.stringify(json.people) === JSON.stringify(whole.slice(25, 50)),
  'and they are the rows the old description of everybody put there');
  log.debug("Leaving checkKerberos().");
}

// ---------------------------------------------------------------------------
// DEVICES.
// ---------------------------------------------------------------------------
function checkDevices(t) {
  log.debug("Entering checkDevices().");
  t.log.info('=== devices: one read for the list and its total ===');
  for (let i = 0; i < 40; i++) {
    devices.create({ owner: personName(i + 1), label: TAG + '-d' + i },
                   'admin_paging_directory');
  }
  const devicesAdmin = require('../admin-ui/devices_admin');
  const ops = [];
  const store = credentials.deviceStore;
  credentials.deviceStore = function (operation) {
    ops.push(operation);
    return store.apply(this, arguments);
  };
  let view;
  try {
    view = devicesAdmin.listView(req({}), {});
  } finally {
    credentials.deviceStore = store;
  }
  const reads = ops.filter(function (one) {
    return one === 'listDeviceEntries';
  }).length;
  t.check(view.total === devices.all().length && view.total >= 40,
          'the total is every device in the realm', String(view.total));
  t.check(reads === 1,
          'and the register was read once, for the list, where the total ' +
          'read it again', reads + ' read(s): ' + ops.join(','));
  log.debug("Leaving checkDevices().");
}

// ---------------------------------------------------------------------------
// A RELATIONSHIP'S LINKS.
// ---------------------------------------------------------------------------
function checkFederationLinks(t) {
  log.debug("Entering checkFederationLinks().");
  t.log.info('=== a relationship\'s links: only the page parsed ===');
  const made = federation.create({ fedId: REL, fedRole: 'service-provider',
                                   fedProtocol: 'oidc' });
  if (!made.ok) {
    t.bad('the relationship could not be created', JSON.stringify(made));
    log.debug("Leaving checkFederationLinks().");
    return;
  }
  const parsed = counting(fedLinks, 'parse', function () {
    return timed(t, 'federationDetailJson() links page 3', function () {
      return adminViews.federationDetailJson(req({ linksPage: '3',
                                                   per: '25' }), REL);
    });
  });
  const json = parsed.answer.json;
  const through = federation.linkedThrough(REL);
  t.check(json.linksPaging && json.linksPaging.total === through.length &&
          through.length >= (PEOPLE / 2) - 1,
          'the links total is every link through the relationship',
          json.linksPaging ? String(json.linksPaging.total) : 'no paging');
  t.check(parsed.calls === 25,
          'and only the 25 on the page were taken apart', parsed.calls +
          ' parse(s)');
  const expected = through.slice(50, 75).map(function (one) {
    const parts = fedLinks.parse(one.value) || {};
    return { username: one.username, dn: one.dn, link: one.value,
             issuer: parts.issuer, subject: parts.subject };
  });
  t.check(JSON.stringify(json.links) === JSON.stringify(expected),
          'and they are the rows parsing every link put on that page');
  log.debug("Leaving checkFederationLinks().");
}

async function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: TAG, name: TAG,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + TAG + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      config.setOverride('ldap.maxEntries', '100000');
      const started = Date.now();
      if (!seed(t)) {
        return;
      }
      t.log.info('    (information only) seeding took ' +
                 (Date.now() - started) + ' ms');
      checkApplications(t);
      checkRegisters(t);
      checkPeople(t);
      checkResidents(t);
      checkGroups(t);
      checkDirectoryView(t);
      checkKerberos(t);
      checkDevices(t);
      checkFederationLinks(t);
    });
  } finally {
    realms.remove(TAG);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_paging_directory',
  describe: 'the directory\'s console lists page before per-row work (#352): ' +
            'counted over a realm of three thousand people',
  run: run
};
