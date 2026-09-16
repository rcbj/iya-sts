'use strict';
//
// File: password_policy.js
//
// ---------------------------------------------------------------------------
// THE PASSWORD POLICY (2026-09-12): WHAT A PASSWORD HERE MUST LOOK LIKE, WHICH
// OF A PERSON'S OLD ONES IT MAY NOT BE, AND HOW ONE IS MADE UP.
//
// Asked for by rcbj as the first policy on a Directory > Policies page:
// a minimum length, a number of password generations that may not repeat, a
// number of symbols, an uppercase letter and a digit — with reasonable
// defaults, called the DEFAULT PROFILE, ENFORCED IN PRODUCT MODE, and applied
// on the first password a person sets as well as on every later one.
//
// **IT REPLACED A ONE-RULE POLICY THAT WAS HOURS OLD.** `credentials.js` had a
// minimum length read from `security.passwordMinLength`, whose comment argued
// — correctly, as a reading of NIST SP 800-63B section 5.1.1.2 — that a
// verifier SHOULD NOT impose composition rules. The composition rules here
// are the deployment's choice rather than this file's advice, each of them
// can be turned off (a symbol count of 0, the two booleans false), and the
// history rule is one NIST does not argue against at all. What survives from
// that rule is the part that was right: ONE place decides, and every door
// that sets a password asks it.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES: A DIRECTORY ENTRY, `cn=default,ou=passwordPolicies`.
//
// rcbj chose a directory entry over a settings group, and the reasons are the
// ones every other register here was put in the directory for: it is per
// realm because the directory is, it persists and replicates with the
// directory, an `ldapsearch` finds it, and a container holds more than one
// profile the day a profile can be ASSIGNED to somebody.
//
// **THE ATTRIBUTE NAMES FOLLOW draft-behera-ldap-password-policy WHERE IT HAS
// ONE**, which is the schema OpenLDAP's ppolicy overlay and 389 Directory
// Server read: `pwdAttribute`, `pwdMinLength`, `pwdInHistory` on the policy,
// and `pwdHistory` and `pwdChangedTime` on the person. An LDAP administrator
// who has met a password policy entry before recognises this one. The draft
// defines no composition rule — it delegates "quality" to the server — so the
// three composition attributes, and the length of a generated password, are
// this service's own and are spelt `stsPwd*` so that nobody mistakes them for
// the draft's.
//
// **`pwdInHistory` MEANS WHAT THE DRAFT SAYS IT MEANS**: the number of PREVIOUS
// passwords kept. A new password may be neither the current one nor any of
// those, so a value of 5 refuses six passwords — which is how OpenLDAP reads
// the same attribute. 0 turns the rule off entirely, the current password
// included, again as the draft says.
//
// **THE ENTRY IS NOT SEEDED.** An absent `cn=default` means the BUILT-IN
// defaults below are in force, and the console says so; the entry is written
// the first time an operator saves the profile. That is `role-issuance`'s
// argument in `xacml/xacml_role_pep.js` made again: a seed written into the
// directory at startup is written into ONE realm, a realm created later has
// none, and a policy that silently did not exist in some realms is the defect
// that argument was written about. A computed default exists in every realm
// by construction.
//
// ---------------------------------------------------------------------------
// ENFORCED WHERE A PASSWORD IS VERIFIED, WHICH IS PRODUCT MODE.
//
// `mode.verifiesCredentials()`, for the reason the length rule gave: a
// development-mode service checks no password at any door, so refusing one
// there would be a policy about a credential nothing reads — and it would
// break every fixture that sets one. The HISTORY is RECORDED in both modes,
// though, because recording costs nothing (it is the previous hash moving,
// never a new hash) and a realm switched to product mode should not start
// with an empty history for everybody.
//
// A GENERATED password satisfies the profile in BOTH modes, because it is
// made by drawing until it does — there is no mode in which this service
// hands somebody a password its own policy would refuse.
//
// ---------------------------------------------------------------------------
// THE GENERATOR IS `generate-password`, AND ITS ONE JOB HERE IS THE DRAW.
//
// Chosen after reading it rather than for its download count: it draws from
// `crypto.randomBytes` and REJECTS a byte that would bias the modulus (a byte
// at or above `256 - 256 % poolSize` is thrown away and another drawn), so
// every character of the pool is equally likely. It has no dependencies.
//
// What it does NOT do is count symbols — its `strict` option asks for at
// least one of each pool and no more. So this file draws with all four pools
// on and `strict` set, and REJECTS WHOLE PASSWORDS that fail the profile until
// one passes. Rejection at the password level keeps the result uniform over
// the passwords that pass, where "patch in another symbol" would not.
//
// Every pool is on whatever the profile requires: a profile not REQUIRING an
// uppercase letter is not a profile forbidding one, and a smaller alphabet is
// a weaker password for nothing. Two characters are left out of the symbols —
// the double quote and the backtick — because a generated password is shown
// once and then pasted, frequently into a shell or a JSON body, and those two
// are the ones that silently end or change the string there.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND A LEAF. It requires `helpers.js`, `mode.js`,
// `error_codes.js` and an npm package, registers no route, and reaches the
// directory through a slot `ldap/ldap_server.js` fills — `common/roles.js`'s
// arrangement exactly, and for its reason: that module is required at 21, so a
// require from here would drag every `/ldap` route to the front of the router.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const mode = require('./mode');
const generator = require('generate-password');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here. A refusal this module RETURNS carries its code non-enumerably,
// under the Symbol `mark()` uses, so a caller reads it with `codeOf()` and
// nothing that serialises the answer can send it anywhere.
const errorCodes = require('./error_codes');

const DEFAULT_PROFILE = 'default';

// The two characters the generator leaves out of its symbol pool. See the
// header.
const GENERATOR_EXCLUDES = '"`';

// Drawing stops here rather than looping forever. With the limits below —
// a generated length of at least twice the symbol count plus two — the chance
// of a single draw passing is well above one in ten, so a thousand failures
// in a row is not bad luck, it is a profile this function cannot satisfy, and
// saying so beats a request that never returns.
const MAX_DRAWS = 1000;

// ---------------------------------------------------------------------------
// THE FIELDS. ONE TABLE, AND EVERYTHING ELSE IS READ FROM IT: the schema this
// container publishes, the form on /admin/policies, the request body
// `/admin-api/policies/save` documents, the validation of a save, and the
// parse of an entry. Five readers of one list is the shape that keeps a new
// rule from being added to four of them.
// ---------------------------------------------------------------------------
const FIELDS = [
  { key: 'minLength', attribute: 'pwdMinLength', type: 'int',
    dflt: 12, min: 1, max: 1024,
    label: 'Minimum length',
    unit: 'characters',
    what: 'The shortest password this service will set, counted in ' +
          'characters (Unicode code points, so an emoji is one). The ' +
          'attribute is draft-behera-ldap-password-policy\'s. Twelve is the ' +
          'default; NIST SP 800-63B asks for at least 8, and 15 where a ' +
          'password is the only factor.' },
  { key: 'history', attribute: 'pwdInHistory', type: 'int',
    dflt: 5, min: 0, max: 24,
    label: 'Previous passwords that may not be reused',
    unit: 'passwords',
    what: 'How many of a person\'s PREVIOUS passwords are remembered and ' +
          'refused. The current password is always refused as well while ' +
          'this is above 0, so 5 means a new password may be none of the ' +
          'last six. 0 turns the rule off. The draft\'s attribute, with the ' +
          'draft\'s meaning. Each remembered password is kept as the scrypt ' +
          'hash it was already stored as, in pwdHistory on the person\'s own ' +
          'entry, and checking a new password costs one hash comparison per ' +
          'one remembered.' },
  { key: 'minSymbols', attribute: 'stsPwdMinSymbols', type: 'int',
    dflt: 1, min: 0, max: 16,
    label: 'Minimum number of symbols',
    unit: 'symbols',
    what: 'How many characters that are neither a letter, a digit nor ' +
          'whitespace a password must contain. 0 turns the rule off.' },
  { key: 'requireUppercase', attribute: 'stsPwdRequireUppercase', type: 'bool',
    dflt: true,
    label: 'Require an uppercase letter',
    what: 'Whether a password must contain at least one uppercase letter, in ' +
          'any script.' },
  { key: 'requireDigit', attribute: 'stsPwdRequireDigit', type: 'bool',
    dflt: true,
    label: 'Require a number',
    what: 'Whether a password must contain at least one decimal digit.' },
  { key: 'generatedLength', attribute: 'stsPwdGeneratedLength', type: 'int',
    dflt: 20, min: 12, max: 128,
    label: 'Length of a generated password',
    unit: 'characters',
    what: 'How long a password this service MAKES UP is — for a new user ' +
          'created from the console or /admin-api, an operator\'s Generate, ' +
          'and the product-mode bootstrap account. It must be at least the ' +
          'minimum length and at least twice the symbol count plus two. ' +
          'Twenty characters from a 90-character alphabet is about 130 bits.' }
];

const FIELD_BY_KEY = {};
FIELDS.forEach(function (field) {
  FIELD_BY_KEY[field.key] = field;
});

const DEFAULTS = Object.freeze(FIELDS.reduce(function (out, field) {
  out[field.key] = field.dflt;
  return out;
}, {}));

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on /admin/policies the way every container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes has to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  container: 'ou=passwordPolicies',
  objectClasses: [
    { name: 'pwdPolicy',
      what: 'draft-behera-ldap-password-policy\'s class for a password ' +
            'policy entry. `pwdAttribute` names the attribute the policy ' +
            'governs, and here that is always `userPassword`.' },
    { name: 'stsPasswordPolicy',
      what: 'This service\'s own class, carrying the composition rules and ' +
            'the generated length the draft has no attribute for. The entry ' +
            'is named by the PROFILE (`cn=default`).' }
  ],
  attributes: [
    { name: 'pwdAttribute',
      what: 'The attribute this policy governs: `userPassword`.' }
  ].concat(FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  })).concat([
    { name: 'description',
      what: 'What the profile is for, for the next person.' }
  ]),
  // THE TWO THAT GO ON A PERSON rather than on the policy. Listed here
  // because this module is what gives them their meaning, and in
  // `ldap/ldap_server.js`'s own list because that is where an attribute a
  // person's entry carries is named.
  personAttributes: [
    { name: 'pwdHistory',
      what: 'One value per remembered previous password, in the draft\'s ' +
            'form `time#syntaxOID#length#data` — the data being the scrypt ' +
            'hash that password was stored under, never the password. ' +
            'Maintained by this service and refused on an LDAP add or ' +
            'modify, because a history anybody can edit is a history ' +
            'anybody can empty.' },
    { name: 'pwdChangedTime',
      what: 'When the password was last set, as a GeneralizedTime. ' +
            'Maintained by this service.' }
  ]
};

// The syntax OID the draft's pwdHistory form names for the data half: Octet
// String, RFC 4517 section 3.3.25.
const OCTET_STRING_OID = '1.3.6.1.4.1.1466.115.121.1.40';

// ---------------------------------------------------------------------------
// THE SLOT.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  directory = hooks || null;
  log.debug('Leaving setDirectory(). The password policy register ' +
            (directory ? 'has its container.' : 'has none.'));
}

function directoryInstalled() {
  log.debug("Entering directoryInstalled().");
  log.debug("Leaving directoryInstalled().");
  return directory;
}

function haveDirectory() {
  log.debug("Entering haveDirectory().");
  if (directory && typeof directory.allPasswordPolicies === 'function') {
    log.debug("Leaving haveDirectory().");
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('password_policy: the embedded directory was never loaded, so ' +
             'there is no ou=passwordPolicies. The BUILT-IN default profile ' +
             'is in force and cannot be edited in this process — which is ' +
             'the policy an unedited service has anyway, so nothing is ' +
             'weaker than it would be.');
  }
  log.debug("Leaving haveDirectory().");
  return false;
}

// ---------------------------------------------------------------------------
// READING.
// ---------------------------------------------------------------------------
function firstValue(attributes, name) {
  log.debug("Entering firstValue().");
  const found = attributes[name] !== undefined ? attributes[name]
    : attributes[name.toLowerCase()];
  log.debug("Leaving firstValue().");
  return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
    : (found === undefined || found === null ? '' : found);
}

// One field's value out of whatever an entry or a request body carried.
// Answers `{ value }` or `{ problem }`, never throws, and never guesses: an
// integer with a fraction or a boolean spelt `yes` is a problem, because the
// value will be compared against a password and a policy that read `12.5` as
// 12 is a policy nobody wrote.
function parseField(field, raw) {
  log.debug("Entering parseField().");
  const text = String(raw === undefined || raw === null ? '' : raw).trim();
  if (field.type === 'bool') {
    const lower = text.toLowerCase();
    // LDAP's Boolean syntax is TRUE and FALSE (RFC 4517 section 3.3.3); a
    // form posts `on` for a ticked checkbox and nothing for an unticked one,
    // and a JSON body sends true and false. All three spellings are one
    // question.
    if (['true', 'on', '1'].indexOf(lower) >= 0) {
      log.debug("Leaving parseField().");
      return { value: true };
    }
    if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
      log.debug("Leaving parseField().");
      return { value: false };
    }
    log.debug("Leaving parseField().");
    return { problem: field.label + ' is a yes-or-no setting, and "' +
                      text.slice(0, 40) + '" is neither.' };
  }
  if (!/^\d+$/.test(text)) {
    log.debug("Leaving parseField().");
    return { problem: field.label + ' must be a whole number between ' +
                      field.min + ' and ' + field.max + '; "' +
                      text.slice(0, 40) + '" is not one.' };
  }
  const value = Number(text);
  if (value < field.min || value > field.max) {
    log.debug("Leaving parseField().");
    return { problem: field.label + ' must be between ' + field.min + ' and ' +
                      field.max + '; ' + value + ' is not.' };
  }
  log.debug("Leaving parseField().");
  return { value: value };
}

// The rules that relate two fields, which no one field can check.
function crossFieldProblems(values) {
  log.debug("Entering crossFieldProblems().");
  const out = [];
  if (values.generatedLength < values.minLength) {
    out.push('A generated password would be ' + values.generatedLength +
             ' characters, which is shorter than the minimum length of ' +
             values.minLength + ' — this service would make up passwords its ' +
             'own policy refuses. Raise the generated length to at least ' +
             values.minLength + '.');
  }
  if (values.generatedLength < values.minSymbols * 2 + 2) {
    out.push('A generated password of ' + values.generatedLength +
             ' characters cannot reliably carry ' + values.minSymbols +
             ' symbols; it must be at least ' + (values.minSymbols * 2 + 2) +
             ' (twice the symbol count plus two).');
  }
  log.debug("Leaving crossFieldProblems().");
  return out;
}

function entryFor(name) {
  log.debug("Entering entryFor().");
  if (!haveDirectory()) {
    log.debug("Leaving entryFor().");
    return null;
  }
  const wanted = String(name).toLowerCase();
  log.debug("Leaving entryFor().");
  return directory.allPasswordPolicies().filter(function (entry) {
    return String(entry.name || '').toLowerCase() === wanted;
  })[0] || null;
}

// THE PROFILE IN FORCE. Always answers — a stored entry parsed field by field,
// with the built-in default standing in for any value that is absent or
// unreadable, and a `problems` list naming each one that was.
//
// An unreadable value falls back to the DEFAULT rather than to "no rule",
// which is the direction that matters: somebody who `ldapmodify`s
// `pwdMinLength: twelve` has broken one attribute, and the answer to that must
// not be a policy with no minimum length.
function read(name) {
  log.debug('Entering read(). name=' + name);
  const profile = String(name || DEFAULT_PROFILE);
  const entry = entryFor(profile);
  const values = Object.assign({}, DEFAULTS);
  const problems = [];
  const sources = {};
  FIELDS.forEach(function (field) {
    sources[field.key] = 'built-in';
  });
  if (entry) {
    const at = entry.attributes || {};
    FIELDS.forEach(function (field) {
      const raw = firstValue(at, field.attribute);
      if (raw === '') {
        return;
      }
      const parsed = parseField(field, raw);
      if (parsed.problem) {
        problems.push(field.attribute + ' on ' + entry.dn + ' is unreadable ' +
                      '(' + parsed.problem + ') and the built-in default of ' +
                      field.dflt + ' is in force instead.');
        return;
      }
      values[field.key] = parsed.value;
      sources[field.key] = 'directory';
    });
    crossFieldProblems(values).forEach(function (problem) {
      problems.push(problem);
    });
  }
  const out = Object.assign({
    name: profile,
    stored: !!entry,
    dn: entry ? entry.dn : '',
    description: entry ? String(firstValue(entry.attributes || {},
                                           'description')) : '',
    sources: sources,
    problems: problems,
    enforced: mode.verifiesCredentials()
  }, values);
  log.debug('Leaving read(). ' + (entry ? 'Stored.' : 'Built-in defaults.'));
  return out;
}

// The profile that applies to a password being set. ONE today, and the
// function exists so that assigning profiles later changes this body and no
// caller — the username is accepted now for exactly that reason.
function profileFor(username) {
  log.debug("Entering profileFor().");
  void username;
  log.debug("Leaving profileFor().");
  return read(DEFAULT_PROFILE);
}

// Every profile. One today; paged by the caller like every list this console
// draws.
function list() {
  log.debug('Entering list().');
  const rows = [read(DEFAULT_PROFILE)];
  log.debug('Leaving list(). ' + rows.length + ' profile(s).');
  return rows;
}

// ---------------------------------------------------------------------------
// WRITING.
// ---------------------------------------------------------------------------

// Only `default`, and saying why is the whole of this check. A second profile
// could be written perfectly well — the container holds any number — but
// nothing ASSIGNS one to anybody yet, so it would be an entry that decides
// nothing while looking exactly like one that does.
function checkProfileName(name) {
  log.debug("Entering checkProfileName().");
  const text = String(name || DEFAULT_PROFILE).trim();
  if (text.toLowerCase() !== DEFAULT_PROFILE) {
    log.debug("Leaving checkProfileName().");
    return 'There is one password policy profile, "' + DEFAULT_PROFILE +
           '", and it applies to everybody in this realm. "' +
           text.slice(0, 64) + '" cannot be created: nothing assigns a ' +
           'profile to a person yet, so a second one would decide nothing ' +
           'while looking exactly like one that does.';
  }
  log.debug("Leaving checkProfileName().");
  return null;
}

// A save carries EVERY field. A field left out is a problem rather than a
// default, because the entry is REPLACED and a save that silently reset the
// three fields a caller did not mention would be the one mistake here that is
// invisible and loosens the policy.
function validate(given) {
  log.debug('Entering validate().');
  const body = given || {};
  const values = {};
  const problems = [];
  FIELDS.forEach(function (field) {
    let raw = body[field.key];
    if (raw === undefined && field.type === 'bool' && body.form === 'console') {
      // AN UNTICKED CHECKBOX POSTS NOTHING, so on the console's own form an
      // absent boolean IS the answer "no". Only there — an API caller that
      // left one out gets told, for the reason above.
      raw = 'false';
    }
    if (raw === undefined) {
      problems.push('`' + field.key + '` (' + field.label + ') is required. ' +
                    'A save replaces the whole profile, so every field is ' +
                    'sent.');
      return;
    }
    if (typeof raw === 'boolean' || typeof raw === 'number') {
      raw = String(raw);
    }
    const parsed = parseField(field, raw);
    if (parsed.problem) {
      problems.push(parsed.problem);
      return;
    }
    values[field.key] = parsed.value;
  });
  if (!problems.length) {
    crossFieldProblems(values).forEach(function (problem) {
      problems.push(problem);
    });
  }
  log.debug('Leaving validate(). ' + problems.length + ' problem(s).');
  return { values: values, problems: problems };
}

function save(name, given) {
  log.debug('Entering save(). name=' + name);
  const refused = checkProfileName(name);
  if (refused) {
    log.debug('Leaving save(). Not a profile that can exist.');
    return errorCodes.mark({ ok: false, errors: [refused] }, 'STS-AUTHN-0107');
  }
  const checked = validate(given);
  if (checked.problems.length) {
    log.debug('Leaving save(). The values were refused.');
    return errorCodes.mark({ ok: false, errors: checked.problems },
                           'STS-AUTHN-0108');
  }
  if (!haveDirectory()) {
    log.debug('Leaving save(). No directory.');
    return errorCodes.mark({ ok: false,
             errors: ['There is no embedded directory in this process, so ' +
                      'there is nowhere to keep a password policy. ' +
                      'ou=passwordPolicies IS the register.'] },
                           'STS-AUTHN-0109');
  }
  const attributes = {
    objectClass: ['top', 'pwdPolicy', 'stsPasswordPolicy'],
    pwdAttribute: 'userPassword',
    description: String((given && given.description) || '').slice(0, 1024)
  };
  FIELDS.forEach(function (field) {
    const value = checked.values[field.key];
    attributes[field.attribute] = field.type === 'bool'
      ? (value ? 'TRUE' : 'FALSE') : String(value);
  });
  if (!attributes.description) {
    delete attributes.description;
  }
  const written = directory.writePasswordPolicy(DEFAULT_PROFILE, attributes);
  if (!written) {
    log.debug('Leaving save(). The directory refused.');
    return errorCodes.mark({ ok: false,
             errors: ['The directory would not store the profile — it is at ' +
                      'its maximum number of entries.'] }, 'STS-AUTHN-0110');
  }
  log.debug('Leaving save(). Stored.');
  return { ok: true, profile: read(DEFAULT_PROFILE) };
}

// Deleting the entry, which puts the BUILT-IN defaults back in force. It is
// the one way to say "whatever this release thinks is reasonable" rather than
// writing today's numbers down and keeping them forever.
function reset(name) {
  log.debug('Entering reset(). name=' + name);
  const refused = checkProfileName(name);
  if (refused) {
    log.debug('Leaving reset(). Not a profile that can exist.');
    return errorCodes.mark({ ok: false, errors: [refused] }, 'STS-AUTHN-0107');
  }
  if (!haveDirectory()) {
    log.debug('Leaving reset(). No directory.');
    return { ok: true, removed: false, profile: read(DEFAULT_PROFILE) };
  }
  const removed = !!directory.deletePasswordPolicy(DEFAULT_PROFILE);
  log.debug('Leaving reset(). ' + (removed ? 'Removed.' : 'Nothing stored.'));
  return { ok: true, removed: removed, profile: read(DEFAULT_PROFILE) };
}

// ---------------------------------------------------------------------------
// CHECKING A PASSWORD.
// ---------------------------------------------------------------------------
function countMatching(password, pattern) {
  log.debug("Entering countMatching().");
  log.debug("Leaving countMatching().");
  return Array.from(password).filter(function (ch) {
    return pattern.test(ch);
  }).length;
}

// What is wrong with this password under this profile — every rule it breaks,
// not the first, so that a person fixes it once. INDEPENDENT OF THE MODE:
// whether to ASK is the caller's decision (`credentials.js` asks in product
// mode), and the generator below asks in both.
//
// The character classes are Unicode's rather than ASCII's. A person whose
// password is in Greek has uppercase letters, and a rule that only saw A to Z
// would refuse them for not having what they plainly have.
function problemsWith(password, profile) {
  log.debug("Entering problemsWith().");
  const rules = profile || read(DEFAULT_PROFILE);
  const text = String(password === undefined || password === null ? '' :
                      password);
  const out = [];
  const length = Array.from(text).length;
  if (length < rules.minLength) {
    out.push('at least ' + rules.minLength + ' characters (it has ' + length +
             ')');
  }
  if (rules.minSymbols > 0) {
    const symbols = countMatching(text, /[^\p{L}\p{N}\s]/u);
    if (symbols < rules.minSymbols) {
      out.push('at least ' + rules.minSymbols + ' symbol' +
               (rules.minSymbols === 1 ? '' : 's') + ' (it has ' + symbols +
               ')');
    }
  }
  if (rules.requireUppercase && countMatching(text, /\p{Lu}/u) === 0) {
    out.push('an uppercase letter');
  }
  if (rules.requireDigit && countMatching(text, /\p{Nd}/u) === 0) {
    out.push('a number');
  }
  log.debug("Leaving problemsWith().");
  return out;
}

// The rules as a person reads them, for the forms that ask for a password.
function describe(profile) {
  log.debug("Entering describe().");
  const rules = profile || read(DEFAULT_PROFILE);
  const out = ['at least ' + rules.minLength + ' characters'];
  if (rules.minSymbols > 0) {
    out.push('at least ' + rules.minSymbols + ' symbol' +
             (rules.minSymbols === 1 ? '' : 's') +
             ' (a character that is not a letter, a number or a space)');
  }
  if (rules.requireUppercase) {
    out.push('an uppercase letter');
  }
  if (rules.requireDigit) {
    out.push('a number');
  }
  if (rules.history > 0) {
    out.push('not your current password or any of the ' + rules.history +
             ' before it');
  }
  log.debug("Leaving describe().");
  return out;
}

// ---------------------------------------------------------------------------
// THE HISTORY'S STORED FORM. Built and read here, because this is the module
// that gives the draft's format its meaning; `ldap_server.js` stores strings
// and `credentials.js` decides what goes in them.
// ---------------------------------------------------------------------------
function generalizedTime(when) {
  log.debug("Entering generalizedTime().");
  const d = when instanceof Date ? when : new Date(when || Date.now());
  log.debug("Leaving generalizedTime().");
  return d.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function historyValue(hash, when) {
  log.debug("Entering historyValue().");
  const data = String(hash);
  log.debug("Leaving historyValue().");
  return generalizedTime(when) + '#' + OCTET_STRING_OID + '#' +
         Buffer.byteLength(data, 'utf8') + '#' + data;
}

// The hash out of one stored value, or '' for one that is not in the form.
// The DATA may itself contain `#`, so it is everything after the THIRD one.
function hashOfHistoryValue(value) {
  log.debug("Entering hashOfHistoryValue().");
  const text = String(value || '');
  const parts = text.split('#');
  if (parts.length < 4) {
    log.debug("Leaving hashOfHistoryValue().");
    return '';
  }
  log.debug("Leaving hashOfHistoryValue().");
  return parts.slice(3).join('#');
}

// ---------------------------------------------------------------------------
// MAKING ONE UP.
// ---------------------------------------------------------------------------
function generate(profile) {
  log.debug('Entering generate().');
  const rules = profile || read(DEFAULT_PROFILE);
  const length = Math.max(rules.generatedLength, rules.minLength,
                          rules.minSymbols * 2 + 2);
  for (let draw = 1; draw <= MAX_DRAWS; draw++) {
    const candidate = generator.generate({
      length: length,
      lowercase: true,
      uppercase: true,
      numbers: true,
      symbols: true,
      strict: true,
      exclude: GENERATOR_EXCLUDES
    });
    if (problemsWith(candidate, rules).length === 0) {
      log.debug('Leaving generate(). Drew a passing password on draw ' +
                draw + '.');
      return candidate;
    }
  }
  // Unreachable with the limits `crossFieldProblems()` enforces on a save;
  // reachable only through a hand-edited entry, which `read()` has already
  // reported. Thrown rather than answered with a weaker password, because the
  // alternative is this service handing out a credential its own policy
  // refuses.
  log.error(errorCodes.tag('STS-AUTHN-0111') +
            'password_policy: ' + MAX_DRAWS + ' draws of ' + length +
            ' characters produced no password satisfying the profile. The ' +
            'profile cannot be satisfied by a generated password.');
  log.debug('Leaving generate(). Gave up.');
  throw errorCodes.mark(new Error('No generated password of ' + length + ' ' +
                  'characters satisfied the password policy ' +
                  'in ' + MAX_DRAWS + ' draws. ' +
                  'Raise the generated length or lower the symbol count on ' +
                  '/admin/policies.'), 'STS-AUTHN-0111');
}

module.exports = {
  DEFAULT_PROFILE: DEFAULT_PROFILE,
  DEFAULTS: DEFAULTS,
  FIELDS: FIELDS,
  FIELD_BY_KEY: FIELD_BY_KEY,
  SCHEMA: SCHEMA,
  OCTET_STRING_OID: OCTET_STRING_OID,
  setDirectory: setDirectory,
  directoryInstalled: directoryInstalled,
  read: read,
  list: list,
  profileFor: profileFor,
  validate: validate,
  save: save,
  reset: reset,
  problemsWith: problemsWith,
  describe: describe,
  generate: generate,
  historyValue: historyValue,
  hashOfHistoryValue: hashOfHistoryValue,
  generalizedTime: generalizedTime,
  enforced: function () {
    log.debug("Entering enforced().");
    log.debug("Leaving enforced().");
    return mode.verifiesCredentials();
  }
};
