// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: refusal_sentences.js
//
// ===========================================================================
// A REFUSAL IS DRAWN IN THE PAGE'S LANGUAGE (#2006, rcbj 2026-11-23).
//
// `common/sentence.ts` carries a refusal as a `refusals.*` catalog key whose
// English is what every text reader sees, and `common/web_said.ts` draws it
// in the page's language from the `messages` an answer carries beside its
// English `errors`. Held here:
//
//   A. A sentence's English is its English catalog message, formatted, and
//      it is that English wherever it is treated as text: `String()`,
//      concatenation, `JSON.stringify()`, `join()`.
//   B. `messagesOf()`: nothing for a list of text alone, one entry per
//      sentence otherwise (`null` for text), a parameter that is a sentence
//      carried as its own message.
//   C. The browser draws a message in the page's language, and the English
//      it was sent with where the catalogs lack its key or a parameter's —
//      never a key's name.
//   D. No refusal door in the sign-in surface is handed an English literal:
//      every sentence a refusal function is given directly is a `Sentence`.
//   E. Every `refusals` key is named by some source, so a sentence whose
//      last use was deleted does not linger in every catalog.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const i18n = require('../common/i18n');
const Sentence = require('../common/sentence');
const WebSaid = require('../common/web_said');
const webMessages = require('../common/web_messages');

const log = require('bunyan').createLogger({ name: 'refusal_sentences',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The refusal doors whose sentence argument D holds, and the index of that
// argument among the call's arguments.
const DOORS = [
  { name: 'this.screenRefused', arg: 2 },
  { name: 'this.stepRefused', arg: 1 },
  { name: 'this.refuseAtScreen', arg: 2 },
  { name: 'authn.refuseAtScreen', arg: 2 },
  { name: 'this.accountsRefused', arg: 3 },
  { name: 'this.passwordChangeRefused', arg: 1 },
  { name: 'this.passkeyRefused', arg: 5 }
];

// The files D reads.
const DOOR_FILES = ['authn/authn.ts', 'authn/email_factor.ts'];

/**
 * The top-level arguments of every call to `name` in a source, as text.
 *
 * @param body - the source
 * @param name - the callee, `this.stepRefused`
 * @returns `{ line, args }` for each call
 */
function callsOf(body, name) {
  log.debug("Entering callsOf(). " + name);
  const out = [];
  let from = 0;
  for (;;) {
    const at = body.indexOf(name + '(', from);
    if (at < 0) {
      break;
    }
    from = at + name.length + 1;
    // A declaration or a doc comment's mention is not a call.
    const before = body.slice(Math.max(0, at - 1), at);
    if (/[A-Za-z0-9_.]/.test(before)) {
      continue;
    }
    const args = [];
    let depth = 1;
    let quote = null;
    let current = '';
    let i = from;
    for (; i < body.length && depth > 0; i++) {
      const c = body[i];
      if (quote) {
        current += c;
        if (c === '\\') {
          current += body[i + 1];
          i++;
        } else if (c === quote) {
          quote = null;
        }
        continue;
      }
      if (c === '\'' || c === '"' || c === '`') {
        quote = c;
        current += c;
        continue;
      }
      if (c === '(' || c === '[' || c === '{') {
        depth++;
      } else if (c === ')' || c === ']' || c === '}') {
        depth--;
        if (depth === 0) {
          break;
        }
      } else if (c === ',' && depth === 1) {
        args.push(current.trim());
        current = '';
        continue;
      }
      current += c;
    }
    args.push(current.trim());
    out.push({ line: body.slice(0, at).split('\n').length, args: args });
    from = i;
  }
  log.debug("Leaving callsOf(). " + out.length);
  return out;
}

/**
 * Every `.ts` and `.js` this repository owns, as `sourceFiles()` in
 * `tests/i18n_catalogs.js` reads them.
 *
 * @returns the paths
 */
function sourceFiles() {
  log.debug("Entering sourceFiles().");
  const out = [];
  const skip = ['node_modules', 'tests', 'node-ldapjs', '.git', 'docs',
                'vendored', 'embedded', 'rust', 'deploy', '.claude'];
  const walk = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      if (skip.indexOf(entry.name) >= 0) {
        return;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.(ts|js)$/.test(entry.name) &&
                 !/\.d\.ts$/.test(entry.name)) {
        out.push(full);
      }
    });
  };
  walk(ROOT);
  log.debug("Leaving sourceFiles(). " + out.length);
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const english = i18n.messagesOf('refusals', 'en');

  // A.
  const failed = Sentence.say('refusals.authn.failedFor',
                              { username: 'alice' });
  t.check(english['authn.failedFor'] === 'Authentication failed for ' +
          '{username}.', 'A. the English catalog holds the sentence',
          english['authn.failedFor']);
  t.check(String(failed) === 'Authentication failed for alice.' &&
          failed.text === String(failed) &&
          'x ' + failed === 'x Authentication failed for alice.' &&
          JSON.stringify({ why: failed }) ===
            '{"why":"Authentication failed for alice."}' &&
          [failed, 'more.'].join(' ') ===
            'Authentication failed for alice. more.',
          'A. a sentence is its English wherever it is treated as text',
          String(failed));

  // B.
  t.check(Sentence.messagesOf(['plain', 'text']) === undefined,
          'B. a list of text carries no messages');
  const nested = Sentence.say('refusals.authn.browserNoPasskey',
    { error: Sentence.say('refusals.authn.failed') });
  const messages = Sentence.messagesOf(['plain', failed, nested]);
  t.check(Array.isArray(messages) && messages.length === 3 &&
          messages[0] === null &&
          messages[1].key === 'refusals.authn.failedFor' &&
          messages[1].params.username === 'alice' &&
          messages[2].params.error.key === 'refusals.authn.failed',
          'B. one message per sentence, null for text, a sentence ' +
          'parameter carried as its own message', JSON.stringify(messages));
  t.check(String(nested) === 'Your browser did not use a passkey ' +
          '(Authentication failed.).',
          'B. a sentence parameter is placed in English', String(nested));

  // C.
  const t9 = webMessages.WebTranslator.fromData({
    negotiated: { locale: 'xx', chain: ['xx', 'en'], catalog: 'xx',
                  direction: 'ltr', matched: true },
    catalogs: {
      xx: { 'refusals.authn.failedFor': 'XX {username} XX',
            'refusals.authn.browserNoPasskey': 'XX ({error})' },
      en: {}
    }
  });
  const answer = { errors: ['plain English.', String(failed),
                            String(nested)],
                   messages: messages };
  t.check(WebSaid.saidWith(t9, answer) ===
          'plain English. XX alice XX Your browser did not use a passkey ' +
          '(Authentication failed.).',
          'C. a message is drawn in the page\'s language, and text and a ' +
          'message whose parameter the catalogs lack are drawn in English',
          WebSaid.saidWith(t9, answer));
  t.check(WebSaid.saidWith(t9, { errors: ['English only.'] }) ===
          'English only.' && WebSaid.saidWith(t9, {}) === '',
          'C. an answer with no messages is drawn as it was sent');
  const fr = i18n.translator(['fr']);
  const drawn = WebSaid.saidWith(fr, { errors: [String(failed)],
                                       messages: [failed.message()] });
  t.check(drawn && drawn !== String(failed) && drawn.indexOf('alice') >= 0,
          'C. the French catalog draws a refusal in French', drawn);

  // D.
  const problems = [];
  DOOR_FILES.forEach(function (file) {
    const body = fs.readFileSync(path.join(ROOT, file), 'utf8');
    DOORS.forEach(function (door) {
      callsOf(body, door.name).forEach(function (call) {
        const arg = String(call.args[door.arg] || '');
        if (/^['"`]/.test(arg)) {
          problems.push(file + ':' + call.line + ' ' + door.name +
                        ' is handed ' + arg.slice(0, 60));
        }
      });
    });
  });
  t.check(problems.length === 0, 'D. no refusal door is handed an English ' +
          'literal', problems.slice(0, 40).join('\n'));

  // E.
  const named = new RegExp('(?:\\bt\\.(?:html|text)|\\bSentence\\.say|' +
    '\\.refusal)\\(\\s*\'refusals\\.([a-zA-Z0-9_.-]+)\'', 'g');
  const used = {};
  sourceFiles().forEach(function (file) {
    const body = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = named.exec(body)) !== null) {
      used[m[1]] = true;
    }
  });
  const unused = Object.keys(english).filter(function (key) {
    return !used[key];
  });
  t.check(unused.length === 0, 'E. every refusals key is named by a source',
          unused.slice(0, 40).join('\n'));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'refusal_sentences',
  describe: 'a refusal is a catalog sentence whose English every text ' +
            'reader sees, carried beside errors as messages and drawn in ' +
            'the page\'s language with its English as the fallback (#2006)',
  run: run
};
