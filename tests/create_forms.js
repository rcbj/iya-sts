// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: create_forms.js
//
// ===========================================================================
// EVERY DIRECTORY CREATE PAGE CALLS OUT WHAT ITS CREATE REQUIRES, AND WHAT
// IT CALLS OUT IS WHAT THE CREATE REFUSES WITHOUT (#1132).
//
// rcbj on #1132: every directory object has a create page, and each calls
// out its required fields the way New user does; a field is required when
// the server refuses the create without it today, and everything else is
// optional. `admin-core/create_forms.ts` is the table each
// `GET /admin-api/<object>/new` answers as `createFields`; this file holds
// the table to the doors it describes, by calling them:
//
//   A. Each object's create succeeds with its required fields alone (and
//      the minimum a value needs to be valid), and is REFUSED with each
//      required field taken away — so a field the table calls required is
//      one the create refuses without, and the required set is enough.
//   B. A secret destination's provider-specific fields (`requiredWhen`):
//      an aws destination without its region, and without its credential,
//      is refused; the same fields are not required of a vault one where
//      the table says so. The drawn form marks each the way it marks an
//      always-required field while the selected provider needs it, and
//      not while another is selected.
//   C. Each create page's answer carries the table's fields: New group,
//      New role and Register a device from their views.
//   D. A named policy (#1132's sixth object): `GET /admin-api/policies/new`
//      answers every kind with named policies, and for the password policy
//      the name and every field the save refuses without, while a field the
//      save keeps the value in force for (`hashAlgorithm`) is optional — and
//      the save agrees: refused without a required field, saved without the
//      optional one, and refused with no name at all ("A name is required.")
//      without writing the default.
//   E. The drawn pages: a required field is outlined, starred and says
//      "required" (`fg-required`), an optional one is not, and the HTML
//      `required` attribute is on exactly the required fields. A field
//      required for the selected choice is one of those.
//
// IN A THROWAWAY REALM, removed at the end.
// ===========================================================================
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const CreateForms = require('../admin-core/create_forms');
const destinations = require('../common/secret_destinations');
const attributeSources = require('../attribute-sources/attribute_sources');
const passwordPolicy = require('../common/password_policy');
const WebAnswers = require('../admin-ui/web_answers');
const PoliciesPage = require('../admin-ui/web_policies');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const SecretDestinationsPage =
  require('../admin-ui/web_secret_destinations');

const log = require('bunyan').createLogger({ name: 'create_forms',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const CTX = { actor: 'create-forms-test', via: 'test' };

function without(body, name) {
  log.debug("Entering without(). " + name);
  const out = Object.assign({}, body);
  delete out[name];
  log.debug("Leaving without().");
  return out;
}

// One create door per object, and a body holding its required fields and
// nothing else (bar `action`), each a fresh name so the creates do not
// collide with each other.
function doors(owner) {
  log.debug("Entering doors().");
  const devicesAdmin = require('../admin-ui/devices_admin');
  let n = 0;
  const fresh = function (stem) {
    n += 1;
    return 'cf-' + stem + '-' + RUN + '-' + n;
  };
  const out = {
    users: { act: function (body) {
               return adminActions.usersAction(Object.assign(
                 { action: 'create', credential: 'none' }, body), CTX);
             },
             body: function () {
               return { username: fresh('u') };
             } },
    applications: { act: function (body) {
                      return applications.createApplication(body);
                    },
                    body: function () {
                      return { identifier: fresh('app') };
                    } },
    groups: { act: function (body) {
                return adminActions.groupsAction(Object.assign(
                  { action: 'create' }, body), CTX);
              },
              body: function () {
                return { group: fresh('g') };
              } },
    roles: { act: function (body) {
               return adminActions.rolesAction(Object.assign(
                 { action: 'create-role' }, body), CTX);
             },
             body: function () {
               return { role: fresh('r') };
             } },
    devices: { act: function (body) {
                 return devicesAdmin.action(Object.assign(
                   { action: 'create' }, body), 'test', 'create_forms');
               },
               body: function () {
                 return { owner: owner };
               } },
    attributeSources: { act: function (body) {
                          return attributeSources.act(Object.assign(
                            { action: 'add-source' }, body), CTX);
                        },
                        body: function () {
                          return { id: fresh('src'), host: 'db.example.com',
                                   database: 'hr', user: 'reader',
                                   table: 'people', keyColumn: 'login',
                                   columns: { cost_center: 'costCenter' } };
                        } },
    secretDestinations: { act: function (body) {
                            return destinations.act(Object.assign(
                              { action: 'add-destination' }, body), CTX);
                          },
                          // aws: the provider needing a region and a
                          // credential (`requiredWhen`), both given.
                          body: function () {
                            return { identifier: fresh('dest'),
                                     provider: 'aws', region: 'us-east-1',
                                     credential: JSON.stringify({
                                       accessKeyId: 'AKIA' + RUN,
                                       secretAccessKey: 'x' + RUN }) };
                          } }
  };
  log.debug("Leaving doors().");
  return out;
}

async function requiredHolds(t, table) {
  log.debug("Entering requiredHolds().");
  const owner = 'cf-owner-' + RUN;
  const made = adminActions.usersAction({ action: 'create', username: owner,
                                          credential: 'none' }, CTX);
  t.check(!!(made && made.ok), 'A0. the device owner is created',
          JSON.stringify(made && made.errors));
  const all = doors(owner);
  t.check(Object.keys(all).sort().join(',') ===
          CreateForms.objects().sort().join(','),
          'A0. the table describes every create door here, and only those',
          CreateForms.objects().join(','));
  for (const object of Object.keys(all)) {
    const door = all[object];
    const required = CreateForms.requiredOf(object);
    const whole = await Promise.resolve(door.act(door.body()));
    t.check(!!(whole && whole.ok),
            'A1. ' + object + ': the create succeeds with its required ' +
            'fields alone (' + required.join(', ') + ')',
            JSON.stringify(whole && (whole.errors || whole.why)));
    for (const name of required) {
      const refused = await Promise.resolve(
        door.act(without(door.body(), name)));
      t.check(!!refused && refused.ok === false,
              'A2. ' + object + ': refused without `' + name + '`',
              JSON.stringify(refused));
    }
  }
  log.debug("Leaving requiredHolds().");
  return table;
}

async function requiredWhen(t) {
  log.debug("Entering requiredWhen().");
  const kit = require('../admin-ui/web_kit');
  const rows = CreateForms.fieldsOf('secretDestinations');
  const when = function (name) {
    const row = rows.filter(function (one) {
      return one.name === name;
    })[0];
    return row && row.requiredWhen;
  };
  t.check(when('region').values.join(',') === 'aws' &&
          when('credential').values.indexOf('file') < 0 &&
          when('endpoint').values.join(',') === 'azure,vault',
          'B1. the provider-specific fields say which providers need them');
  const base = { action: 'add-destination', provider: 'aws',
                 region: 'us-east-1',
                 credential: JSON.stringify({ accessKeyId: 'AKIA' + RUN,
                                              secretAccessKey: 'y' + RUN }) };
  const noRegion = await destinations.act(Object.assign(
    without(base, 'region'), { identifier: 'cf-nr-' + RUN }), CTX);
  const noCredential = await destinations.act(Object.assign(
    without(base, 'credential'), { identifier: 'cf-nc-' + RUN }), CTX);
  t.check(noRegion.ok === false && noCredential.ok === false,
          'B2. aws refuses a destination without its region, and without ' +
          'its credential');
  const drawn = function (draft) {
    return SecretDestinationsPage.newBody({
      providers: ['aws', 'gcp', 'azure', 'vault', 'file'],
      payloads: ['password'], fileAllowed: true,
      createFields: rows,
      state: draft ? { draft: draft } : undefined
    }, kit.context());
  };
  const cellOf = function (html, name) {
    const at = html.indexOf('id="fgc-new-' + name + '"');
    return at < 0 ? '' : html.slice(at, html.indexOf('</div>', at));
  };
  const marked = function (cell) {
    return /class="fg-cell fg-required"/.test(cell);
  };
  const labelOf = function (cell) {
    const found = /data-label="([^"]*)"/.exec(cell);
    return found ? found[1] : '';
  };
  const listed = function (html) {
    const found = /data-required-list>([^<]*)</.exec(html);
    return found ? found[1] : '';
  };
  const saysWhen = function (cell, values) {
    return cell.indexOf('data-required-when-field="provider"') >= 0 &&
      cell.indexOf('data-required-when-values="' + values + '"') >= 0;
  };
  const awsPage = drawn();
  const regionCell = cellOf(awsPage, 'region');
  const endpointCell = cellOf(awsPage, 'endpoint');
  const directoryCell = cellOf(awsPage, 'directory');
  const credentialCell = cellOf(awsPage, 'credential');
  const awsList = listed(awsPage);
  t.check(saysWhen(regionCell, 'aws') && marked(regionCell) &&
          regionCell.indexOf('class="fg-req-word"') >= 0 &&
          regionCell.indexOf('class="fg-req-word" hidden') < 0 &&
          saysWhen(endpointCell, 'azure vault') && !marked(endpointCell) &&
          endpointCell.indexOf('fg-required') < 0 &&
          endpointCell.indexOf('class="fg-req-when"') >= 0 &&
          endpointCell.indexOf('class="fg-req-when" hidden') < 0 &&
          saysWhen(directoryCell, 'file') && !marked(directoryCell) &&
          saysWhen(credentialCell, 'aws gcp azure vault') &&
          marked(credentialCell) &&
          awsList.indexOf(labelOf(regionCell)) >= 0 &&
          awsList.indexOf(labelOf(credentialCell)) >= 0 &&
          awsList.indexOf(labelOf(endpointCell)) < 0 &&
          awsList.indexOf(labelOf(directoryCell)) < 0,
          'B3. aws outlines its region and write credential, and the ' +
          'others say which provider needs them');
  const vaultPage = drawn({ provider: 'vault' });
  const vaultList = listed(vaultPage);
  t.check(marked(cellOf(vaultPage, 'endpoint')) &&
          marked(cellOf(vaultPage, 'credential')) &&
          !marked(cellOf(vaultPage, 'region')) &&
          !marked(cellOf(vaultPage, 'directory')) &&
          vaultList.indexOf(labelOf(cellOf(vaultPage, 'endpoint'))) >= 0 &&
          vaultList.indexOf(labelOf(cellOf(vaultPage, 'region'))) < 0,
          'B3. a refused vault create outlines its endpoint instead');
  const filePage = drawn({ provider: 'file' });
  const fileList = listed(filePage);
  t.check(marked(cellOf(filePage, 'directory')) &&
          !marked(cellOf(filePage, 'credential')) &&
          !marked(cellOf(filePage, 'region')) &&
          !marked(cellOf(filePage, 'endpoint')) &&
          fileList.indexOf(labelOf(cellOf(filePage, 'directory'))) >= 0 &&
          fileList.indexOf(labelOf(cellOf(filePage, 'credential'))) < 0,
          'B3. a file destination outlines its directory and not a ' +
          'credential');
  const provider = {
    value: 'aws',
    addEventListener: function (name, handler) {
      this.changed = handler;
    }
  };
  const classes = {};
  const regionInput = { type: 'text', required: false, attrs: {} };
  const endpointInput = { type: 'text', required: false, attrs: {} };
  [regionInput, endpointInput].forEach(function (input) {
    input.setAttribute = function (name, value) {
      input.attrs[name] = value;
    };
    input.removeAttribute = function (name) { delete input.attrs[name]; };
  });
  const requiredCell = function (values, input, label) {
    const names = {};
    const word = { hidden: null, classList: { contains: function (name) {
      return name === 'fg-req-word';
    } } };
    const when = { hidden: null, classList: { contains: function (name) {
      return name === 'fg-req-when';
    } } };
    return {
      word: word, when: when,
      getAttribute: function (name) {
        if (name === 'data-required-when-field') {
          return 'provider';
        }
        if (name === 'data-required-when-values') {
          return values;
        }
        if (name === 'data-label') {
          return label;
        }
        return '';
      },
      classList: {
        add: function (name) {
          classes[values + name] = true;
          names[name] = true;
        },
        remove: function (name) {
          delete classes[values + name];
          delete names[name];
        },
        contains: function (name) { return !!names[name]; }
      },
      querySelectorAll: function (selector) {
        const asked = String(selector || '');
        if (asked.indexOf('fg-req-word') >= 0) {
          return [word];
        }
        if (asked.indexOf('fg-req-when') >= 0) {
          return [when];
        }
        if (asked.indexOf('input') >= 0) {
          return [input];
        }
        return [];
      }
    };
  };
  const region = requiredCell('aws', regionInput, 'Region (aws)');
  const endpoint = requiredCell('azure vault', endpointInput,
                                'Vault URL (azure, vault)');
  const cells = [region, endpoint];
  const listNode = { textContent: '' };
  const form = {
    elements: { namedItem: function () { return provider; } },
    querySelector: function (selector) {
      return String(selector).indexOf('data-required-list') >= 0
        ? listNode : null;
    },
    querySelectorAll: function (selector) {
      if (String(selector).indexOf('fg-cell') >= 0) {
        return cells.filter(function (cell) {
          return cell.classList.contains('fg-required');
        });
      }
      return cells;
    }
  };
  const runtime = new ConsoleRuntime({
    location: { pathname: '/admin' },
    document: { querySelectorAll: function () { return [form]; } }
  });
  runtime.wireConditionalRequirements();
  const awsOutlined = classes['awsfg-required'] && regionInput.required &&
    !classes['azure vaultfg-required'] && !endpointInput.required &&
    region.word.hidden === false && region.when.hidden === true &&
    endpoint.word.hidden === true && endpoint.when.hidden === false &&
    listNode.textContent === 'Region (aws)' &&
    regionInput.attrs['aria-required'] === 'true' &&
    !endpointInput.attrs['aria-required'];
  provider.value = 'vault';
  provider.changed();
  t.check(awsOutlined && !classes['awsfg-required'] &&
          !regionInput.required &&
          classes['azure vaultfg-required'] && endpointInput.required &&
          region.word.hidden === true && endpoint.word.hidden === false &&
          listNode.textContent === 'Vault URL (azure, vault)' &&
          endpointInput.attrs['aria-required'] === 'true' &&
          !regionInput.attrs['aria-required'],
          'B4. the browser marks only fields required for the selected ' +
          'provider, including the word and the note');
  provider.value = '';
  provider.options = [{ value: 'aws' }, { value: 'vault' }];
  provider.changed();
  t.check(!!classes['awsfg-required'] && !classes['azure vaultfg-required'],
          'B4. an unset provider select follows its first choice');
  const editJson = {
    providers: ['aws', 'gcp', 'azure', 'vault', 'file'],
    payloads: ['password'], fileAllowed: true, credentialShapes: {}
  };
  const edit = function (over) {
    return SecretDestinationsPage.row(kit.context().t, editJson,
      Object.assign({
        id: 'dest-1', name: 'Prod', identifier: 'dest-1',
        provider: 'aws', payload: 'password',
        location: { region: 'us-east-1' },
        credentialSet: true, usable: true, problems: []
      }, over), { write: true });
  };
  const editCell = function (html, name) {
    const at = html.indexOf('id="fgc-dest-1-' + name + '"');
    return at < 0 ? '' : html.slice(at, html.indexOf('</div>', at));
  };
  const credTag = function (html) {
    const found = /<input[^>]*name="credential"[^>]*>/.exec(html);
    return found ? found[0] : '';
  };
  const kept = edit({});
  t.check(marked(editCell(kept, 'region')) &&
          !marked(editCell(kept, 'endpoint')) &&
          editCell(kept, 'directory') !== '' &&
          !marked(editCell(kept, 'directory')) &&
          credTag(kept).indexOf('required') < 0,
          'B5. an aws edit outlines its region, and a credential already ' +
          'set stays optional');
  const open = edit({ credentialSet: false });
  t.check(marked(editCell(open, 'credential')) &&
          / required[ >]/.test(credTag(open)),
          'B5. a missing write credential is required for aws');
  const fileRow = edit({ credentialSet: false, provider: 'file',
                         location: { directory: '/tmp/secrets' } });
  t.check(marked(editCell(fileRow, 'directory')) &&
          !marked(editCell(fileRow, 'region')) &&
          !marked(editCell(fileRow, 'credential')) &&
          !/ required[ >]/.test(credTag(fileRow)),
          'B5. a file edit requires its directory and not a credential');
  log.debug("Leaving requiredWhen().");
}

function answersCarryTheTable(t) {
  log.debug("Entering answersCarryTheTable().");
  const devicesAdmin = require('../admin-ui/devices_admin');
  const same = function (answer, object) {
    return JSON.stringify(answer.createFields) ===
           JSON.stringify(CreateForms.fieldsOf(object));
  };
  t.check(same(adminViews.newGroupJson(), 'groups') &&
          same(adminViews.newRoleJson(), 'roles') &&
          same(devicesAdmin.newView(), 'devices'),
          'C1. New group, New role and Register a device answer the ' +
          'table\'s fields');
  t.check(same(adminViews.newUserJson({ query: {} }), 'users'),
          'C2. New user answers its username as required');
  log.debug("Leaving answersCarryTheTable().");
}

async function namedPolicy(t) {
  log.debug("Entering namedPolicy().");
  const none = adminViews.newPolicyJson({});
  t.check(none.kind === null && none.createFields.length === 0 &&
          none.kinds.map(function (one) {
            return one.id;
          }).indexOf('password') >= 0,
          'D1. without a kind, the kinds and no fields');
  const answer = adminViews.newPolicyJson({ kind: 'password' });
  const required = answer.createFields.filter(function (one) {
    return one.required;
  }).map(function (one) {
    return one.name;
  });
  t.check(required.indexOf('profile') >= 0 &&
          required.indexOf('minLength') >= 0 &&
          required.indexOf('hashAlgorithm') < 0 &&
          required.indexOf('precedence') < 0,
          'D2. the password policy: the name and minLength required, the ' +
          'hash algorithm and the precedence not', required.join(','));
  const body = Object.assign({}, passwordPolicy.DEFAULTS,
    { action: 'save-password-policy', profile: 'cf-pw-' + RUN,
      newProfile: '1' });
  const saved = await Promise.resolve(adminActions.policiesAction(
    without(Object.assign({}, body, { profile: 'cf-pw2-' + RUN }),
            'hashAlgorithm'), CTX));
  t.check(!!(saved && saved.ok),
          'D3. a named password policy saves without the optional field',
          JSON.stringify(saved && saved.errors));
  const refused = await Promise.resolve(adminActions.policiesAction(
    without(body, 'minLength'), CTX));
  t.check(!!refused && refused.ok === false,
          'D4. and is refused without a required one',
          JSON.stringify(refused));
  const beforeDefault = passwordPolicy.read('default');
  const unnamed = await Promise.resolve(adminActions.policiesAction({
    action: 'save-password-policy', newProfile: '1', profile: '   '
  }, CTX));
  const omitted = await Promise.resolve(adminActions.policiesAction({
    action: 'save-password-policy', minLength: 21
  }, CTX));
  const spaces = await Promise.resolve(adminActions.policiesAction({
    action: 'save-password-policy', profile: '   ', minLength: 22
  }, CTX));
  const nulled = await Promise.resolve(adminActions.policiesAction({
    action: 'save-password-policy', profile: null, minLength: 30
  }, CTX));
  const afterBlank = passwordPolicy.read('default');
  const saysName = function (answer) {
    return !!answer && answer.ok === false &&
      (answer.errors || []).indexOf('A name is required.') >= 0;
  };
  t.check(saysName(unnamed) && saysName(omitted) && saysName(spaces) &&
          saysName(nulled) &&
          afterBlank.minLength === beforeDefault.minLength &&
          afterBlank.stored === beforeDefault.stored,
          'D5. a save with no name is refused and the default is unchanged',
          JSON.stringify({ unnamed: unnamed && unnamed.errors,
                           omitted: omitted && omitted.errors,
                           spaces: spaces && spaces.errors,
                           nulled: nulled && nulled.errors,
                           before: beforeDefault.minLength,
                           after: afterBlank.minLength,
                           stored: afterBlank.stored }));
  const trimmed = await Promise.resolve(adminActions.policiesAction(
    Object.assign({}, passwordPolicy.DEFAULTS, {
      action: 'save-password-policy', profile: ' default ' }), CTX));
  const wrote = passwordPolicy.read('default');
  t.check(!!(trimmed && trimmed.ok) && wrote.name === 'default' &&
          wrote.stored === true,
          'D5b. a name that trims to default still saves the default',
          JSON.stringify(trimmed && trimmed.errors));
  const blankAuthn = await Promise.resolve(adminActions.policiesAction({
    action: 'save-named-authn-policy', name: '   '
  }, CTX));
  const missingAuthn = await Promise.resolve(adminActions.policiesAction({
    action: 'save-named-authn-policy'
  }, CTX));
  t.check(saysName(blankAuthn) && saysName(missingAuthn),
          'D5c. a named authentication policy with no name is refused',
          JSON.stringify({ blank: blankAuthn && blankAuthn.errors,
                           missing: missingAuthn && missingAuthn.errors }));
  const malformed = await Promise.resolve(adminActions.policiesAction({
    action: 'save-named-authn-policy', name: 'Not A Name'
  }, CTX));
  t.check(!!malformed && malformed.ok === false &&
          (malformed.errors || []).indexOf('A name is required.') < 0,
          'D5d. a present malformed name is the kind\'s own refusal',
          JSON.stringify(malformed && malformed.errors));
  const authnFields = {
    newProfile: '1', name: 'typed-authn', description: 'typed description',
    precedence: '17', mechanisms: ['', 'password'],
    secondFactors: ['', 'totp']
  };
  const authnRefusal = WebAnswers.redraw(
    '/admin/policies', 'save-named-authn-policy', authnFields,
    { ok: false, errors: ['The policy was refused.'] }, {});
  const authnHtml = PoliciesPage.newPolicyBody(require('../admin-ui/web_kit')
    .context(), {
      policies: {
        kinds: [{ id: 'authn', label: 'Authentication',
                  governs: 'authentication' }],
        authn: { named: [], vocabulary: {
          mechanisms: ['password'], secondFactors: ['totp'] } }
      },
      kind: 'authn',
      state: authnRefusal.json.state
    });
  t.check(authnRefusal.json.state.policyDrafts['authn-new'].name ===
            'typed-authn' &&
          /value="typed-authn"/.test(authnHtml) &&
          /value="typed description"/.test(authnHtml) &&
          /name="precedence"[^>]*value="17"/.test(authnHtml) &&
          /name="mechanisms" value="password"[^>]* checked/.test(authnHtml) &&
          /name="secondFactors" value="totp"[^>]* checked/.test(authnHtml) &&
          /The policy was refused\./.test(authnHtml),
          'D6. a refused authentication-policy create keeps its fields and ' +
          'shows the refusal');
  log.debug("Leaving namedPolicy().");
}

function policyNameBubble(t) {
  log.debug("Entering policyNameBubble().");
  const hits = { text: [], hidden: [], stored: [] };
  const text = {
    name: 'profile', type: 'text', value: '   ',
    setCustomValidity: function (message) { hits.text.push(message); },
    addEventListener: function (event, handler) { this[event] = handler; }
  };
  const hidden = {
    name: 'profile', type: 'hidden', value: '',
    setCustomValidity: function (message) { hits.hidden.push(message); },
    addEventListener: function () { hits.hidden.push('listened'); }
  };
  const createForm = {
    elements: { namedItem: function (name) {
      return name === 'newProfile' ? { value: '1' } : null;
    } },
    querySelectorAll: function () { return [hidden, text]; }
  };
  const storedInput = {
    name: 'profile', type: 'hidden', value: 'default',
    setCustomValidity: function (message) { hits.stored.push(message); },
    addEventListener: function () { hits.stored.push('listened'); }
  };
  const storedForm = {
    elements: { namedItem: function () { return null; } },
    querySelectorAll: function () { return [storedInput]; }
  };
  const runtime = new ConsoleRuntime({
    location: { pathname: '/admin/policies/new' },
    document: { querySelectorAll: function () {
      return [createForm, storedForm];
    } }
  });
  runtime.wirePolicyNames();
  text.value = ' contractors ';
  text.input();
  const cleared = hits.text[hits.text.length - 1];
  text.value = '  ';
  text.invalid();
  t.check(hits.text[0] === 'A name is required.' && cleared === '' &&
          hits.text[hits.text.length - 1] === 'A name is required.' &&
          hits.hidden.length === 0 && hits.stored.length === 0,
          'D7. a blank new-policy name says a name is required, and a ' +
          'stored profile does not');
  log.debug("Leaving policyNameBubble().");
}

function drawn(t) {
  log.debug("Entering drawn().");
  const kit = require('../admin-ui/web_kit');
  const groupsPage = require('../admin-ui/web_groups');
  const html = groupsPage.newGroupBody(kit.context(),
                                       adminViews.newGroupJson());
  const cell = function (name) {
    const at = html.indexOf('id="fgc-new-' + name + '"');
    return at < 0 ? '' : html.slice(at, html.indexOf('</div>', at));
  };
  t.check(/class="fg-cell fg-required"/.test(cell('group')) &&
          / required /.test(cell('group')) &&
          cell('group').indexOf('required') > 0,
          'E1. New group outlines its cn, says "required" and refuses it ' +
          'empty in the browser');
  t.check(['note', 'mail', 'members'].every(function (name) {
    return cell(name) && cell(name).indexOf('fg-required') < 0 &&
           !/ required[ >]/.test(cell(name));
  }), 'E2. its optional fields are drawn and not marked');
  const box = { name: 'enabled', label: 'Enabled', type: 'checkbox',
                required: true, checkedValue: 'yes', boxLabel: 'Enabled' };
  const boxHtml = kit.createFields([box], {}, kit.context().t);
  t.check(boxHtml.indexOf('fg-required') < 0 &&
          !/ required(?:[ >]|=)/.test(boxHtml) &&
          kit.requiredNote([box], kit.context().t).indexOf('Enabled') < 0,
          'E3. an unchecked box is never marked required');
  log.debug("Leaving drawn().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'cf-' + RUN,
                                name: 'create forms ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      await requiredHolds(t);
      await requiredWhen(t);
      answersCarryTheTable(t);
      await namedPolicy(t);
      policyNameBubble(t);
      drawn(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'create_forms',
  describe: 'every directory create page calls out its required fields, ' +
            'and a field it calls required is one its create refuses ' +
            'without (#1132)',
  run: run
};
