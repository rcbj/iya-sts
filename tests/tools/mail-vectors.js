// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: mail-vectors.js
//
// ---------------------------------------------------------------------------
// THE MAIL CHANNEL'S VECTORS (#444, phase 4): `auditmail-node.json`'s `mail`,
// which `rust/crates/sts-mail/tests/node_vectors.rs` replays.
//
// Built in a CHILD process (`--child`), because the channel's stores, the
// directory slot and the settings are module state, and because the child
// freezes `Date.now()` — every row's instants, every message's Date header
// and every DKIM signature's `t=` come from it. What a run cannot fix — the
// outbox row's random id and nodemailer's random boundary — is recorded, and
// Rust is handed it.
//
//   templates  common/mail_templates.ts: the language chain, the language
//              order, placeholders, plain(), problem() over every built-in
//              translation and a set of refused templates, and every
//              message rendered and wrapped in its layout in every language
//   channel    common/mail.ts and common/mail_transports.ts: every message
//              in every recipient language sent through the real SMTP
//              transport (nodemailer's transport replaced by a recorder),
//              DKIM-signed — the message the transport was handed, the raw
//              bytes and the audit rows; and every refusal and its code
//   transports addressProblem() and the SMTP and cloud failure classifiers
//   uses       common/mail_uses.ts: the request each use hands the channel
//
// The other direction (`fromRust()`): `mail-rust.json` — raw messages Rust
// composed and signed — verified with Node's DKIM verifier.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'mail_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const T0 = 1763100000000;

/**
 * Runs the child and returns what it wrote.
 *
 * @param {string} root - the repository root
 * @param {string} out - the vectors directory
 * @returns {Promise<any>} the mail vectors
 */
async function build(root, out) {
  log.debug("Entering build().");
  const childProcess = require('child_process');
  const answer = path.join(out, 'mail-answer.json');
  childProcess.execFileSync(process.execPath,
    [__filename, '--child', root, answer],
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  const built = JSON.parse(fs.readFileSync(answer, 'utf8'));
  fs.unlinkSync(answer);
  log.debug("Leaving build().");
  return built;
}

let NOW = T0;

// Every resolveValues() the channel made, in order.
const RESOLUTIONS = [];

// THE SCRIPT the channel part ran, in order — every setting written, every
// clock move, every send and every other act (a `mark` Rust performs the
// same way) — so Rust replays the same sequence.
const SCRIPT = [];

/**
 * Moves the frozen clock on, and says so in the script.
 *
 * @param {number} ms - how far
 */
function tick(ms) {
  log.debug("Entering tick().");
  NOW += ms;
  SCRIPT.push({ op: 'now', at: NOW });
  log.debug("Leaving tick().");
}

/**
 * Notes an act in the script.
 *
 * @param {string} name - the act
 */
function mark(name) {
  log.debug("Entering mark(). " + name);
  SCRIPT.push({ op: 'mark', name: name });
  log.debug("Leaving mark().");
}

/**
 * Sets a setting, throwing when it is refused.
 *
 * @param {any} config - config.js
 * @param {string} key - the key
 * @param {any} value - the value
 */
function setting(config, key, value) {
  log.debug("Entering setting(). " + key);
  const result = config.setOverride(key, value);
  SCRIPT.push({ op: 'set', key: key, value: value });
  if (!result || !result.ok) {
    throw new Error('setting ' + key + ' refused: ' + JSON.stringify(result));
  }
  log.debug("Leaving setting().");
}

// The language tags the chain and the order are asked about.
const TAGS = ['en', 'EN-us', 'fr', 'fr-FR', 'fr-CA', 'fr-ca', 'fr-BE',
  'es', 'es-ES', 'es-MX', 'es-419', 'zh', 'zh-CN', 'zh-SG', 'zh-TW',
  'zh-HK', 'zh-MO', 'zh-Hans', 'zh-Hant', 'zh-Hant-HK', 'zh-hant-tw',
  'fil', 'fil-PH', 'tl', 'sv', 'sv-FI', 'de', 'de-CH', 'ja', 'pt-BR', 'x',
  '', '*', 'not a tag', 'i-klingon', 'en-GB-oxendict'];

// The recipients: one per language a message may be chosen in.
const PEOPLE = [
  ['ann', ''], ['fred', 'fr'], ['claire', 'fr-CA, fr;q=0.8'],
  ['bea', 'fr-BE'], ['elena', 'es'], ['pilar', 'es-ES'],
  ['mateo', 'es-MX;q=0.9, en;q=0.1'], ['li', 'zh-CN'], ['wei', 'zh-TW'],
  ['kit', 'zh-HK'], ['sam', 'zh-Hant-HK'], ['maria', 'fil-PH'],
  ['sven', 'sv'], ['hans', 'de-CH, de;q=0.5'], ['q0', 'fr;q=0, sv']
];

const CATALOG_LANGS = ['en', 'fr', 'fr-CA', 'es', 'es-ES', 'zh-Hans',
  'zh-Hant', 'zh-Hant-HK', 'fil', 'sv', 'de'];

/**
 * A value for each placeholder of a template, with what a renderer must
 * escape and strip.
 *
 * @param {any} spec - the built-in template
 * @returns {any} name → value
 */
function sampleValues(spec) {
  log.debug("Entering sampleValues().");
  const out = {};
  spec.values.forEach(function (name, i) {
    out[name] = i === 0 ? name + ' <b>&amp; "q" \'s\'' : (i === 1
      ? name + ' line\r\nInjected: x\u0007' : name + ' é 中');
  });
  log.debug("Leaving sampleValues().");
  return out;
}

/**
 * The templates part.
 *
 * @param {any} T - mail_templates
 * @returns {any} inputs and answers
 */
function templatesPart(T) {
  log.debug("Entering templatesPart().");
  const out = {
    chain: TAGS.map(function (tag) {
      return [tag, T.chainFor(tag)];
    }),
    order: [['', ''], ['', 'fr'], ['fr-CA, fr;q=0.8, en;q=0.5', 'de'],
      ['de-CH;q=0.5, ja', 'SV '], ['x_y, en-gb', ''], ['fr;q=0, es;q=1.0', ''],
      ['es; q = 0.3 , zh-TW', 'es'], ['EN', 'en'], ['a-b-c-d', ''],
      ['fr;q=abc', ''], ['*', ''], [' , ,', 'fr-ca']]
      .map(function (one) {
        return [one[0], one[1], T.languageOrder(one[0], one[1])];
      }),
    placeholders: ['{{a}} {{ b1 }} {{a}} {{1x}} {{ c d }} {{e}}', '', '{{x}}}']
      .map(function (text) {
        return [text, T.placeholders(text)];
      }),
    plain: ['a\r\nb\tc\u0000\u001f\u007f\u0080 é', 7, null]
      .map(function (v) {
        return [v, T.plain(v)];
      }),
    builtInLanguages: T.BUILT_IN.map(function (spec) {
      return [spec.id, T.builtInLanguages(spec.id)];
    }),
    reasons: [],
    problems: [],
    rendered: []
  };
  ['security', 'account', 'notification', 'nope'].forEach(function (cat) {
    CATALOG_LANGS.concat(['zh-TW', 'fr-ca']).forEach(function (lang) {
      out.reasons.push([cat, lang, T.reasonFor(cat, lang)]);
    });
  });
  // EVERY BUILT-IN WORDING IN EVERY LANGUAGE passes problem() — which is
  // what holds the Rust allow-list to sanitize-html's on real messages.
  T.BUILT_IN.forEach(function (spec) {
    CATALOG_LANGS.forEach(function (lang) {
      const found = T.builtInFor(spec.id, lang);
      const parts = found ? found.parts : spec;
      out.problems.push({ id: spec.id, lang: lang, parts: null,
                          problem: T.problem(spec, parts) });
    });
  });
  const reset = T.builtIn('password-reset');
  const layout = T.builtIn('layout');
  const ok = { subject: 'S {{service}}', text: 'T {{link}}',
               html: '<p>H <a href="{{link}}">x</a></p>' };
  const variants = [
    {}, { subject: ' ' }, { subject: 's'.repeat(251) },
    { subject: 'a\nb' }, { text: 'T {{link}} https://x' },
    { html: '<p>mailto:x</p>' }, { text: 'T {{link}} {{nope}} {{zz}}' },
    { text: 'T without the link' }, { html: '<p><!-- c --></p>' },
    { html: '<img src="x">' }, { html: '<script>x</script>' },
    { html: '<p onclick="x">a</p>' }, { html: '<span class="c">a</span>' },
    { html: '<a href="{{nope}}">x</a>' },
    { html: '<a href="{{username}}">x</a>' },
    { html: '<a href="//evil">x</a>' }, { html: '<a href="#top">x</a>' },
    { html: '<a href="&#106;avascript:x">x</a>' },
    { html: '<a href = \'{{link}}\' title="t">x</a>' },
    { html: '<a href={{link}}>x</a>' }, { html: '<P DIR="rtl">a</P>' },
    { html: '<p lang="fr" dir="ltr">a<br/>b<br>c</p><hr>' },
    { html: '<table border="1"><tr><td>a</td></tr></table>' },
    { html: '<table><thead><tr><th>a</th></tr></thead><tbody><tr><td>b' +
            '</td></tr></tbody></table><ul><li>x</li></ul><ol><li>y</li>' +
            '</ol><pre><code>c</code></pre><blockquote>q</blockquote>' },
    { html: '<h1>a</h1><h5>b</h5>' }, { html: '<style>p{}</style><p>a</p>' },
    { html: '<div style="color:red">a</div>' }, { html: '<a name="n">x</a>' },
    { html: '<p>a &amp; b &lt; c</p>' }, { html: '<p>unclosed' },
    { html: '<p>a</p></div>' }, { html: '<a href="{{link}}" href="x">x</a>' },
    { html: '<iframe></iframe>' },
    { html: '<p>x<svg><a href="y"/></svg></p>' },
    { html: '<a href="{{ link }}">x</a>' }, { html: '<a HREF="{{link}}">x</a>' },
    { html: '<p title="t">x</p>' }, { html: '<b>x</b><i>y</i><u>z</u>' +
            '<em>e</em><small>s</small><strong>g</strong>' },
    { html: '<p>a<b>b</p></b>' }, { html: '<<p>>' },
    { html: '<a href="data:text/html,x">x</a>' },
    { html: '<a href=" javascript:x">x</a>' },
    { html: '<p>{{content}}</p>' }];
  variants.forEach(function (v) {
    const parts = Object.assign({}, ok, v);
    out.problems.push({ id: 'password-reset', lang: 'x', parts: parts,
                        problem: T.problem(reset, parts) });
  });
  [{ subject: '{{subject}}', text: 'a {{content}} b',
     html: '<p>{{content}}</p>' },
   { subject: '{{subject}}', text: 'a b', html: '<p>{{content}}</p>' },
   { subject: '{{subject}}', text: '{{content}}{{content}}',
     html: '<p>{{content}}</p>' },
   { subject: 'no subject', text: '{{content}}', html: '{{content}}' },
   { subject: '{{subject}} {{reason}}', text: '{{ content }} {{reason}}',
     html: '<div>{{content}}</div>' }].forEach(function (parts) {
    out.problems.push({ id: 'layout', lang: 'x', parts: parts,
                        problem: T.problem(layout, parts) });
  });
  out.problems.push({ id: 'none', lang: 'x', parts: ok,
                      problem: T.problem(null, ok) });
  // EVERY MESSAGE IN EVERY LANGUAGE, rendered and wrapped as the channel
  // does it (queueOne()), with values the renderer must escape.
  T.BUILT_IN.forEach(function (spec) {
    if (spec.id === T.LAYOUT_ID) {
      return;
    }
    CATALOG_LANGS.forEach(function (lang) {
      const found = T.builtInFor(spec.id, lang);
      const parts = found ? found.parts : spec;
      const chosen = found ? found.lang : 'en';
      const values = sampleValues(spec);
      values.realm = 'Acme <Realm>';
      values.service = 'sts.example.com';
      spec.links.forEach(function (name) {
        values[name] = 'https://sts.example.com/portal/x?a=1&b="2"';
      });
      const layoutFound = T.builtInFor(T.LAYOUT_ID, chosen);
      const layoutParts = layoutFound ? layoutFound.parts : layout;
      const layoutLang = layoutFound ? layoutFound.lang : 'en';
      const body = T.render(parts, values);
      const wrapped = T.wrap(layoutParts, body, Object.assign({}, values, {
        reason: T.reasonFor(spec.category, layoutLang) }));
      out.rendered.push({ id: spec.id, lang: lang, chosen: chosen,
        layoutLang: layoutLang, values: values, body: body,
        wrapped: wrapped, document: T.htmlDocument(wrapped.html, chosen) });
    });
  });
  log.debug("Leaving templatesPart().");
  return out;
}

/**
 * The transports part: the pure classifiers.
 *
 * @param {any} MT - mail_transports
 * @param {any} errorCodes - error_codes
 * @returns {any} inputs and answers
 */
function transportsPart(MT, errorCodes) {
  log.debug("Entering transportsPart().");
  const t = new MT.MailTransports(MT.MailTransports.defaultDeps());
  const coded = function (e) {
    return { code: errorCodes.codeOf(e), retry: e.retry, message: e.message };
  };
  const out = {
    addresses: ['a@example.com', '', 'a b@x.com', '<a@x.com>', 'a,b@x.com',
      'a@x', '@x.com', 'a@', 'a@-x.com', 'a@x-.com', 'a@x..com',
      'é@example.com', 'a@exa_mple.com', 'x'.repeat(64) + '@a.com',
      'x'.repeat(65) + '@a.com', 'a@' + 'b'.repeat(250) + '.com',
      'a"b@x.com', 'a@b@x.com', 'a@x.c0m', 'a@1.2.3.4', 'A.B+c@X.Y-Z.org']
      .map(function (a) {
        return [a, MT.addressProblem(a)];
      }),
    smtp: [{ code: 'EAUTH', response: '535 no' }, { code: 'ETLS' },
      { message: 'self signed certificate in chain' },
      { message: 'Hostname/IP does not match altnames' },
      { responseCode: 550, response: '550 no such user' },
      { responseCode: 451, response: '451 later' },
      { message: 'connect ECONNREFUSED' }, {}].map(function (e) {
      return [e, coded(t.classifySmtp(Object.assign(new Error(e.message ||
        'x'), e)))];
    }),
    cloud: [{ name: 'Throttling', message: 'slow' },
      { $metadata: { httpStatusCode: 503 }, message: 'down' },
      { statusCode: 429 }, { code: 400, message: 'bad' },
      { name: 'MessageRejected', message: 'Email address is not verified.' },
      { $retryable: {}, message: 'r' }, { message: 'getaddrinfo ENOTFOUND x' },
      {}].map(function (e) {
      return [e, coded(t.classifyCloud(Object.assign(new Error(e.message ||
        ''), e), 'SES'))];
    })
  };
  log.debug("Leaving transportsPart().");
  return out;
}

/**
 * The transports' builds and the cloud transports' requests: build() over
 * scripted secrets, nodemailer and the SDKs replaced by recorders.
 *
 * @param {any} MT - mail_transports
 * @param {any} errorCodes - error_codes
 * @param {any} secrets - secrets.js
 * @param {any} keys - the DKIM keys
 * @returns {Promise<any>} the builds and the requests
 */
async function buildsPart(MT, errorCodes, secrets, keys) {
  log.debug("Entering buildsPart().");
  const calls = [];
  let acsStatus = { status: 'Succeeded', id: 'acs-1' };
  const sdks = {
    nodemailer: { createTransport: function (opts) {
      calls.push({ kind: 'smtp', auth: opts.auth || null,
                   cert: !!(opts.tls && opts.tls.cert) });
      return { sendMail: function () {
        return Promise.resolve({ messageId: '<m@x>', response: '250',
                                 rejected: [] });
      }, close: function () {} };
    } },
    '@aws-sdk/client-sesv2': {
      SESv2Client: function (opts) {
        this.send = function (cmd) {
          const input = JSON.parse(JSON.stringify(cmd.input));
          input.Content.Raw.Data =
            Buffer.from(cmd.input.Content.Raw.Data).toString('base64');
          calls.push({ kind: 'ses', opts: opts, input: input });
          return Promise.resolve({ MessageId: 'ses-1' });
        };
      },
      SendEmailCommand: function (input) {
        this.input = input;
      }
    },
    '@azure/identity': { DefaultAzureCredential: function () {} },
    '@azure/communication-email': {
      EmailClient: function (a, b) {
        const args = [typeof a, b ? 'credential' : 'none'];
        this.beginSend = function (msg) {
          calls.push({ kind: 'acs', args: args, input: msg });
          return Promise.resolve({ pollUntilDone: function () {
            return Promise.resolve(acsStatus);
          } });
        };
      }
    },
    '@googleapis/gmail': {
      auth: { JWT: function (o) {
        calls.push({ kind: 'gmail-auth', email: o.email, scopes: o.scopes,
                     subject: o.subject });
      } },
      gmail: function () {
        return { users: { messages: { send: function (req) {
          calls.push({ kind: 'gmail', input: req });
          return Promise.resolve({ data: { id: 'g-1' } });
        } } } };
      }
    }
  };
  const base = { setting: 'smtp', transport: 'smtp',
    smtpHost: 'smtp.example.com', smtpPort: 465, smtpTls: 'implicit',
    smtpServerName: 'mx.example.com', smtpAuth: 'none', smtpUser: 'u',
    smtpCaFile: '', smtpClientCertFile: '', smtpClientKeyFile: '',
    dkimDomain: '', dkimSelector: '', dkimAlgorithm: 'rsa-sha256',
    sesRegion: '', sesConfigurationSet: '', acsAuth: 'managed-identity',
    acsEndpoint: '', gmailSender: 'sender@example.com',
    from: 'no-reply@example.com', timeoutMs: 30000 };
  const gmailKey = JSON.stringify({ client_email: 'sa@example.iam',
                                    private_key: 'k' });
  const cases = [
    ['unknown', { transport: 'nope', setting: 'nope' }, {}],
    ['off', { transport: 'off', setting: 'off' }, {}],
    ['capture', { transport: 'capture' }, {}],
    ['smtp no host', { smtpHost: '' }, {}],
    ['smtp login no secret', { smtpAuth: 'login' }, {}],
    ['smtp login', { smtpAuth: 'login' }, { password: 'pw' }],
    ['smtp plain', { smtpAuth: 'plain' }, { password: 'pw' }],
    ['smtp xoauth2 token', { smtpAuth: 'xoauth2' }, { password: 'tok' }],
    ['smtp xoauth2 refresh', { smtpAuth: 'xoauth2' },
     { password: '{"clientId":"c","clientSecret":"s","refreshToken":"r",' +
                 '"accessUrl":"https://o/t"}' }],
    ['smtp cert without key', { smtpClientCertFile: '/c.pem' }, {}],
    ['smtp dkim no key', { dkimDomain: 'example.com', dkimSelector: 's' },
     {}],
    ['smtp dkim no selector', { dkimDomain: 'example.com' },
     { dkim: keys.rsa.privateKeyPem }],
    ['smtp dkim ok', { dkimDomain: 'example.com', dkimSelector: 's' },
     { dkim: keys.rsa.privateKeyPem }],
    ['ses', { transport: 'ses', sesRegion: 'eu-west-1',
              sesConfigurationSet: 'cs' }, {}],
    ['ses no set', { transport: 'ses' }, {}],
    ['acs no secret', { transport: 'acs', acsAuth: 'connection-string' }, {}],
    ['acs connection', { transport: 'acs', acsAuth: 'connection-string' },
     { acs: 'endpoint=https://a/;accesskey=k' }],
    ['acs no endpoint', { transport: 'acs' }, {}],
    ['acs identity', { transport: 'acs', acsEndpoint: 'https://a.example/' },
     {}],
    ['gmail no key', { transport: 'gmail' }, {}],
    ['gmail bad key', { transport: 'gmail' }, { gmail: 'not json' }],
    ['gmail partial key', { transport: 'gmail' },
     { gmail: '{"client_email":"x"}' }],
    ['gmail', { transport: 'gmail' }, { gmail: gmailKey }]
  ];
  const message = { from: 'no-reply@example.com', fromName: 'IYA',
    to: 'ann@example.com', subject: 'Héllo', text: 'Text é\n',
    html: '<p>HTML</p>', messageId: '<id1@example.com>',
    date: new Date(T0), lang: 'fr' };
  const out = [];
  for (const one of cases) {
    const held = one[2];
    const t = new MT.MailTransports(Object.assign(
      MT.MailTransports.defaultDeps(), {
        load: function (name) {
          return sdks[name] || require(name);
        },
        readSecret: function (spec) {
          const map = new Map([[secrets.MAIL_SMTP_PASSWORD, held.password],
            [secrets.MAIL_DKIM_KEY, held.dkim],
            [secrets.MAIL_ACS_CONNECTION_STRING, held.acs],
            [secrets.MAIL_GMAIL_KEY, held.gmail]]);
          return Promise.resolve(map.get(spec) || null);
        },
        readFile: function (p) {
          return 'file ' + p;
        }
      }));
    const cfg = Object.assign({}, base, one[1]);
    const before = calls.length;
    let answer = null;
    try {
      const made = await t.build(cfg);
      answer = { ok: true, name: made.name };
      if (made.name !== 'smtp' && made.name !== 'capture') {
        const sent = await made.send(message);
        answer.sent = sent;
      }
    } catch (e) {
      answer = { ok: false, code: errorCodes.codeOf(e), message: e.message,
                 retry: e.retry };
    }
    out.push({ name: one[0], cfg: cfg, secrets: held, answer: answer,
               calls: calls.slice(before) });
  }
  acsStatus = { status: 'Failed', error: { code: 'Denied',
                                           message: 'no sender' } };
  const t = new MT.MailTransports(Object.assign(
    MT.MailTransports.defaultDeps(), { load: function (name) {
      return sdks[name] || require(name);
    }, readSecret: function () {
      return Promise.resolve(null);
    } }));
  const acs = await t.build(Object.assign({}, base, { transport: 'acs',
    acsEndpoint: 'https://a.example/' }));
  let failed = null;
  try {
    await acs.send(message);
  } catch (e) {
    failed = { code: errorCodes.codeOf(e), message: e.message,
               retry: e.retry };
  }
  log.debug("Leaving buildsPart().");
  return { message: Object.assign({}, message, { date: T0 }), cases: out,
           acsFailed: failed };
}

/**
 * The child: every part, written to the answer file.
 *
 * @param {string} root - the repository root
 * @param {string} answer - where to write
 */
async function child(root, answer) {
  log.debug("Entering child().");
  Date.now = function () {
    return NOW;
  };
  const C = function (name) {
    return require(path.join(root, 'common', name));
  };
  const config = C('config');
  const errorCodes = C('error_codes');
  const T = C('mail_templates');
  const MT = C('mail_transports');
  const secrets = C('secrets');
  const mailModule = C('mail');
  const realms = C('realms');
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  const pem = function (pair) {
    return { privateKeyPem: pair.privateKey.export({ type: 'pkcs8',
                                                    format: 'pem' }),
             publicKeyPem: pair.publicKey.export({ type: 'spki',
                                                  format: 'pem' }) };
  };
  const keys = { rsa: pem(rsa), ed25519: pem(ed) };
  const out = { t0: T0, keys: keys, templates: templatesPart(T),
                transports: transportsPart(MT, errorCodes) };
  out.builds = await buildsPart(MT, errorCodes, secrets, keys);
  // THE DIRECTORY: one person per language, and the refusal cases.
  const entries = {};
  PEOPLE.forEach(function (p) {
    entries[p[0]] = { mail: [p[0] + '@example.com'],
      stsMailVerified: [p[0] + '@EXAMPLE.com'],
      preferredLanguage: p[1] ? [p[1]] : [],
      displayName: ['Display ' + p[0]], cn: [p[0]] };
  });
  entries.nomail = { cn: ['nomail'] };
  entries.badmail = { mail: ['not an address'] };
  entries.unverified = { mail: ['unverified@example.com'],
                         stsMailVerifyAddress: ['next@example.com'],
                         stsPseudonymVerifyAddress: ['alias@example.com'] };
  entries.declines = { mail: ['declines@example.com'] };
  const groups = { 'cn=ops,ou=groups,dc=example,dc=com':
                     { mail: ['ops@example.com'], cn: ['ops'] },
                   'cn=quiet,ou=groups,dc=example,dc=com': { cn: ['quiet'] } };
  out.entries = entries;
  out.groups = groups;
  mailModule.setDirectory({
    personEntry: function (u) {
      return entries[u] ? { dn: 'uid=' + u, attributes: entries[u] } : null;
    },
    personByMail: function () {
      return '';
    },
    groupEntry: function (dn) {
      return groups[dn] ? { dn: dn, attributes: groups[dn] } : null;
    },
    writeMailFlag: function () {
      return true;
    }
  });
  // THE TRANSPORT: the real SMTP transport, nodemailer's half recorded.
  const sentRaw = [];
  const transportOptions = [];
  let failNext = [];
  const nodemailer = {
    createTransport: function (opts) {
      transportOptions.push({ host: opts.host, port: opts.port,
        secure: opts.secure, requireTLS: opts.requireTLS,
        servername: opts.tls && opts.tls.servername,
        minVersion: opts.tls && opts.tls.minVersion,
        timeout: opts.socketTimeout });
      return {
        sendMail: function (m) {
          if (failNext.length) {
            const e = Object.assign(new Error('relay says no'),
                                    failNext.shift());
            return Promise.reject(e);
          }
          sentRaw.push({ envelope: m.envelope,
                         raw: Buffer.from(m.raw).toString('base64') });
          return Promise.resolve({ messageId: '<relay@x>',
                                   response: '250 2.0.0 OK', rejected: [] });
        },
        close: function () {}
      };
    }
  };
  let dkimPem = keys.rsa.privateKeyPem;
  const transportDeps = Object.assign(MT.MailTransports.defaultDeps(), {
    load: function (name) {
      return name === 'nodemailer' ? nodemailer : require(name);
    },
    readSecret: function (spec) {
      return Promise.resolve(spec === secrets.MAIL_DKIM_KEY ? dkimPem
        : (spec === secrets.MAIL_SMTP_PASSWORD ? 'smtp-secret' : null));
    }
  });
  const handed = [];
  const realTransports = new MT.MailTransports(transportDeps);
  const recordingTransports = {
    build: async function (cfg) {
      const made = await realTransports.build(cfg);
      return { name: made.name, close: made.close, send: function (m) {
        handed.push(JSON.parse(JSON.stringify(m)));
        return made.send(m);
      } };
    }
  };
  const audits = [];
  const deps = Object.assign(mailModule.Mail.defaultDeps(), {
    transports: recordingTransports,
    audit: { audit: function (row) {
      audits.push(JSON.parse(JSON.stringify(row)));
      return row;
    } },
    administrators: function () {
      return ['ann', 'nomail', 'sven'];
    },
    claims: { claim: function () {
      return Promise.resolve({ ok: true, claimedAt: NOW });
    } },
    scheduler: function () {
      return null;
    }
  });
  const mail = new mailModule.Mail(deps);
  // WHAT A VALUE GIVEN AS A MESSAGE OR AN INSTANT BECAME (#539): the i18n
  // translator's work, which `sts-mail` reaches through a port; Rust is
  // handed Node's answer for each.
  const resolveValues = mail.resolveValues;
  mail.resolveValues = function (given, langs) {
    const made = resolveValues.call(mail, given, langs);
    RESOLUTIONS.push({ given: JSON.parse(JSON.stringify(given || {})),
                       langs: langs, made: JSON.parse(JSON.stringify(made)) });
    return made;
  };
  const base = {
    'global.publicBaseUrl': 'https://sts.example.com',
    'mail.transport': 'smtp', 'mail.smtpHost': 'smtp.example.com',
    'mail.smtpPort': 587, 'mail.from': 'no-reply@example.com',
    'mail.fromName': 'IYA STS', 'mail.dkimDomain': 'example.com',
    'mail.dkimSelector': 's2026', 'mail.dkimAlgorithm': 'rsa-sha256',
    'mail.ratePerRecipient': 10000, 'mail.ratePerCategory': 10000,
    'mail.dedupWindowS': 600, 'mail.rateWindowS': 3600,
    'mail.attempts': 3, 'mail.backoffS': 60
  };
  out.settings = base;
  Object.keys(base).forEach(function (k) {
    setting(config, k, base[k]);
  });
  const sends = [];
  const send = async function (label, req, how) {
    const before = { audits: audits.length, handed: handed.length,
                     raw: sentRaw.length, resolutions: RESOLUTIONS.length };
    const result = how ? how(req) : mail.send(req);
    const delivered = result && result.delivered;
    if (delivered && typeof delivered.then === 'function') {
      await delivered;
    }
    SCRIPT.push({ op: 'send', index: sends.length,
                  how: how ? how.name || 'custom' : 'send' });
    sends.push({ label: label, now: NOW, request: req,
      result: JSON.parse(JSON.stringify(result || null)),
      refusedCodes: ((result && result.refused) || []).map(function (r) {
        return errorCodes.codeOf(r) || r.code;
      }),
      handed: handed.slice(before.handed), raw: sentRaw.slice(before.raw),
      audits: audits.slice(before.audits),
      resolutions: RESOLUTIONS.slice(before.resolutions) });
  };
  // EVERY MESSAGE, TO EVERY PERSON (every language), signed.
  const realm = realms.current();
  out.realm = { id: realms.currentId(),
                name: String((realm && realm.name) || realms.currentId()),
                domain: String(realms.domainOf(realm) || ''),
                prefix: realms.currentPrefix() };
  for (const spec of T.BUILT_IN) {
    if (spec.id === T.LAYOUT_ID) {
      continue;
    }
    for (const p of PEOPLE) {
      tick(1000);
      const links = {};
      spec.links.forEach(function (name) {
        links[name] = '/portal/x?user=' + p[0] + '#token=t-' + spec.id;
      });
      await send(spec.id + ' to ' + p[0], { username: p[0],
        template: spec.id, values: sampleValues(spec), links: links,
        via: 'vectors', actor: 'tester' });
    }
  }
  // ED25519, A NON-ASCII NAME AND A LONG LINE; THEN UNSIGNED, NAMELESS.
  setting(config, 'mail.dkimAlgorithm', 'ed25519-sha256');
  setting(config, 'mail.fromName', 'Iyä, "STS"');
  dkimPem = keys.ed25519.privateKeyPem;
  tick(1000);
  await send('ed25519', { username: 'ann', template: 'test-message',
    values: { when: 'w'.repeat(120), transport: 'smtp', username: 'ann' } });
  setting(config, 'mail.fromName', '');
  setting(config, 'mail.dkimDomain', '');
  tick(1000);
  await send('unsigned', { username: 'sven', template: 'test-message',
    values: { when: 'nu', transport: 'smtp', username: 'sven' } });
  setting(config, 'mail.dkimDomain', 'example.com');
  setting(config, 'mail.dkimAlgorithm', 'rsa-sha256');
  setting(config, 'mail.fromName', 'IYA STS');
  dkimPem = keys.rsa.privateKeyPem;
  // THE REFUSALS, each with its code and its audit row.
  tick(1000);
  await send('no entry', { username: 'ghost', template: 'test-message' });
  await send('no mail', { username: 'nomail', template: 'test-message' });
  await send('bad mail', { username: 'badmail', template: 'test-message' });
  await send('unknown template', { username: 'ann', template: 'nope' });
  await send('layout', { username: 'ann', template: 'layout' });
  await send('no request', null);
  await send('administrators', { toAdministrators: true,
    template: 'administrator-alert', values: { act: 'x', why: 'y' },
    dedupKey: 'admin:x' });
  await send('group', { groupDn: 'cn=ops,ou=groups,dc=example,dc=com',
    template: 'report-ready', values: {}, links: { link: '/report/1' } });
  await send('group without mail', { groupDn:
    'cn=quiet,ou=groups,dc=example,dc=com', template: 'report-ready',
    links: { link: '/report/1' } });
  await send('missing group', { groupDn: 'cn=none', template: 'report-ready',
    links: { link: '/report/1' } });
  await send('bad links', { username: 'ann', template: 'password-reset',
    values: {}, links: { link: '//evil.example/x' } });
  await send('bad links 2', { username: 'ann', template: 'password-reset',
    values: {}, links: { link: 'https://evil.example/x' } });
  await send('bad links 3', { username: 'ann', template: 'password-reset',
    values: {}, links: { link: '/a b' } });
  await send('dedup 1', { username: 'fred', template: 'test-message',
    dedupKey: 'k1' });
  await send('dedup 2', { username: 'fred', template: 'test-message',
    dedupKey: 'k1' });
  mark('declined');
  out.declined = [
    mail.setDeclined('declines', 'notification', true, 'declines'),
    mail.setDeclined('declines', 'security', true),
    mail.setDeclined('declines', 'account', true),
    mail.setDeclined('declines', 'bogus', true)
  ].map(function (r) {
    return { result: JSON.parse(JSON.stringify(r)),
             code: errorCodes.codeOf(r) };
  });
  await send('declined', { username: 'declines',
    template: 'post-login-reminder', values: {}, links: { link: '/x' } });
  await send('declined security still goes', { username: 'declines',
    template: 'password-changed', values: {} });
  setting(config, 'mail.from', 'bad from');
  await send('bad from', { username: 'ann', template: 'test-message' });
  setting(config, 'mail.from', '');
  await send('default from', { username: 'ann', template: 'test-message' });
  setting(config, 'mail.from', 'no-reply@example.com');
  setting(config, 'mail.ratePerRecipient', 2);
  tick(5000000);
  await send('rate 1', { username: 'kit', template: 'test-message' });
  await send('rate 2', { username: 'kit', template: 'test-message' });
  await send('rate 3', { username: 'kit', template: 'test-message' });
  setting(config, 'mail.ratePerRecipient', 10000);
  setting(config, 'mail.ratePerCategory', 1);
  await send('category 1', { username: 'sam', template: 'password-changed' });
  await send('category 2', { username: 'sam', template: 'account-disabled' });
  setting(config, 'mail.ratePerCategory', 10000);
  await send('pending address', { username: 'unverified',
    template: 'address-verification', links: { link: '/v' } },
    function (r) {
      return mail.sendToPendingAddress(r);
    });
  await send('pending address none', { username: 'ann',
    template: 'address-verification', links: { link: '/v' } },
    function (r) {
      return mail.sendToPendingAddress(r);
    });
  await send('pseudonym', { username: 'unverified',
    template: 'pseudonym-verification', links: { link: '/v' } },
    function (r) {
      return mail.sendToPseudonymAddress(r);
    });
  await send('former address', { username: 'ann',
    template: 'address-changed', formerAddress: 'old@example.com',
    values: {} }, function (r) {
      return mail.sendToFormerAddress(r);
    });
  // A RELAY THAT DEFERS, THEN REFUSES: retried, then dead, then retried by
  // hand.
  setting(config, 'mail.attempts', 2);
  failNext = [{ responseCode: 451, response: '451 later' }];
  SCRIPT.push({ op: 'fail', failures: failNext.slice() });
  tick(1000);
  await send('deferred', { username: 'li', template: 'test-message' });
  const deadId = sends[sends.length - 1].result.queued[0].id;
  failNext = [{ responseCode: 550, response: '550 no' }];
  SCRIPT.push({ op: 'fail', failures: failNext.slice() });
  tick(120000);
  mark('retry');
  const swept = await mail.sweep();
  const deadView = mail.message(deadId);
  const before = { handed: handed.length, raw: sentRaw.length };
  const retried = mail.retry(deadId, 'admin');
  await new Promise(function (resolve) {
    setTimeout(resolve, 100);
  });
  out.retry = { id: deadId, swept: swept, dead: deadView,
                retried: JSON.parse(JSON.stringify(retried)),
                again: mail.message(deadId),
                notThere: mail.retry('nope'),
                notThereCode: errorCodes.codeOf(mail.retry('nope')),
                notDead: mail.retry(sends[0].result.queued[0].id),
                handed: handed.slice(before.handed),
                raw: sentRaw.slice(before.raw) };
  // THE LINK BASE: unpinned in development, then product.
  setting(config, 'global.publicBaseUrl', '');
  mark('linkBase0');
  out.linkBases = [mail.linkBase()];
  await send('dev link base', { username: 'ann', template: 'password-reset',
    links: { link: '/p' } });
  setting(config, 'global.mode', 'product');
  mark('linkBase1');
  out.linkBases.push(mail.linkBase());
  await send('product, no pin', { username: 'ann',
    template: 'password-reset', links: { link: '/p' } });
  // CAPTURE NEVER REACHES PRODUCT: refused on write (STS-MAIL-0003, the
  // settings slice's write rule), and refused at build and at start.
  mark('captureWrite');
  out.captureWriteRefused = config.setOverride('mail.transport', 'capture');
  mark('productStartup');
  out.productStartup = await mail.startupProblem();
  setting(config, 'global.mode', 'development');
  setting(config, 'mail.transport', 'capture');
  mark('productOverCapture');
  const productSet = config.setOverride('global.mode', 'product');
  out.productOverCapture = productSet;
  if (productSet && productSet.ok) {
    mark('captureInProduct');
    out.captureInProduct = await mail.transport().then(function () {
      return null;
    }, function (e) {
      return { code: errorCodes.codeOf(e), message: e.message };
    });
    mark('startupProblem');
    out.startupProblem = await mail.startupProblem();
  }
  setting(config, 'global.mode', 'development');
  setting(config, 'mail.transport', 'off');
  await send('off', { username: 'ann', template: 'test-message' });
  setting(config, 'mail.transport', 'default');
  mark('effective');
  out.effective = [mail.effectiveTransport(), mail.available()];
  // THE TEMPLATES OF A REALM: saved, chosen, refused, put back.
  setting(config, 'mail.transport', 'smtp');
  setting(config, 'global.publicBaseUrl', 'https://sts.example.com/base/');
  const own = { subject: 'Own {{service}}', text: 'Own {{link}} {{username}}',
                html: '<p>Own <a href="{{link}}">go</a></p>' };
  mark('saved');
  out.saved = [
    mail.saveTemplate('password-reset', 'fr-ca', own, 'admin'),
    mail.saveTemplate('password-reset', 'FR', own, 'admin'),
    mail.saveTemplate('nope', 'fr', own),
    mail.saveTemplate('password-reset', 'fr_CA', own),
    mail.saveTemplate('password-reset', 'fr', { subject: 'x' }),
    mail.saveTemplate('layout', 'sv', { subject: '[{{realm}}] {{subject}}',
      text: '{{content}}\n-- {{reason}}', html: '<div>{{content}}</div>' }),
    mail.resetTemplate('password-reset', 'de'),
    mail.resetTemplate('nope', 'fr')
  ].map(function (r) {
    return { result: JSON.parse(JSON.stringify(r)),
             code: errorCodes.codeOf(r) };
  });
  mark('templateViews');
  out.templateViews = [mail.templateView('password-reset', 'FR-CA'),
    mail.templateView('password-reset', 'en'), mail.templateView('x', 'en')];
  for (const p of ['claire', 'fred', 'sven', 'ann']) {
    tick(1000);
    await send('own wording to ' + p, { username: p,
      template: 'password-reset', values: { username: p },
      links: { link: '/portal/reset' } });
  }
  mark('resetBack');
  out.resetBack = mail.resetTemplate('password-reset', 'fr');
  mark('listTemplates');
  out.listTemplates = mail.listTemplates();
  out.sends = sends;
  out.script = SCRIPT;
  out.transportOptions = transportOptions;
  mark('uses');
  out.uses = await usesPart(C, mail, handed, audits);
  fs.writeFileSync(answer, JSON.stringify(out));
  log.debug("Leaving child().");
}

/**
 * The uses: what each hands the channel, through the real MailUses with
 * the channel above.
 *
 * @param {any} C - a require of common/
 * @param {any} mail - the channel
 * @param {any[]} handed - what the transport was handed
 * @param {any[]} audits - the channel's audit rows
 * @returns {Promise<any>} the requests and answers
 */
async function usesPart(C, mail, handed, audits) {
  log.debug("Entering usesPart().");
  const MU = C('mail_uses');
  const requests = [];
  const recordingMail = new Proxy(mail, { get: function (target, name) {
    if (name === 'send') {
      return function (req) {
        requests.push(JSON.parse(JSON.stringify(req)));
        return target.send(req);
      };
    }
    const v = target[name];
    return typeof v === 'function' ? v.bind(target) : v;
  } });
  const uses = new MU.MailUses(Object.assign(MU.MailUses.defaultDeps(), {
    mail: recordingMail,
    now: function () {
      return NOW;
    }
  }));
  const out = [];
  let marks = { handed: handed.length, audits: audits.length,
                resolutions: RESOLUTIONS.length };
  const record = async function (label, result) {
    const delivered = result && result.delivered;
    if (delivered && typeof delivered.then === 'function') {
      await delivered;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 20);
    });
    out.push({ label: label,
               result: JSON.parse(JSON.stringify(result || null)),
               requests: requests.splice(0),
               handed: handed.slice(marks.handed),
               audits: audits.slice(marks.audits),
               resolutions: RESOLUTIONS.slice(marks.resolutions) });
    marks = { handed: handed.length, audits: audits.length,
              resolutions: RESOLUTIONS.length };
  };
  tick(1000);
  await record('notice password-changed', uses.notice('password-changed', 'fred',
    { values: { how: 'by you' }, via: 'portal' }));
  await record('notice bySystem', uses.notice('account-disabled', 'sven',
    { values: { why: 'policy' }, bySystem: true, act: 'disabled' }));
  await record('notice no user', uses.notice('password-changed', ''));
  await record('signal credentialChanged', uses.fromAccountSignal(
    'credentialChanged', { username: 'li', initiatingEntity: 'admin' }));
  await record('signal app password', uses.fromAccountSignal('credentialChanged',
    { username: 'li', friendlyName: 'x' }));
  await record('signal compromised', uses.fromAccountSignal(
    'credentialCompromised', { username: 'wei', initiatingEntity: 'system',
    reasonUser: 'leaked' }));
  await record('signal recovery', uses.fromAccountSignal('recoveryActivated',
    { username: 'kit', initiatingEntity: 'user' }));
  await record('signal recovery mailed', uses.fromAccountSignal(
    'recoveryActivated', { username: 'kit', mailed: true }));
  await record('admin reset link', uses.mailAdministratorLink('reset', 'maria',
    'tok/1', 'root', 'console'));
  await record('admin activation link', uses.mailAdministratorLink('activation',
    'maria', 'tok2', '', 'api'));
  await record('admin link no mail', uses.mailAdministratorLink('reset', 'nomail',
    'tok3', 'root', 'console'));
  await record('access requested', uses.accessRequested('bea',
    { client: 'app-1', expiresMinutes: 30 }));
  await record('access requested rights', uses.accessRequested('pilar',
    { client: 'app-2', rights: 'read mail', dedupKey: 'k' }));
  await record('pki pin status', uses.pkiPinStatus({ changes: 'two pins',
    dedupKey: 'pins:1' }));
  await record('post-login reminder', uses.postLoginReminder('mateo',
    { started: 'act-1', mails: 2, actor: 'admin' }));
  await record('uma approval', uses.umaApprovalRequested('maria',
    { requester: 'bob', client: 'app', resource: 'photos', scopes: 'view',
      expiresMinutes: 10 }));
  await record('authzen request', uses.authzenAccessRequested('hans',
    { requester: 'bob', subject: 's', action: 'read', resource: 'r',
      application: 'a', expiresMinutes: 5 }));
  await record('authzen emergency', uses.authzenAccessRequested('sven',
    { requester: 'bob', emergency: true, justification: 'fire',
      dedupKey: 'e1' }));
  await record('account disabled', uses.accountDisabled('elena', 'policy',
    false));
  await record('sessions ended', uses.sessionsEnded('claire', 3, ''));
  await record('sessions ended by', uses.sessionsEnded('bea', 1, 'root'));
  await record('address changed', uses.addressChanged('wei',
    'old-wei@example.com', 'new-wei@example.com'));
  await record('address changed to none', uses.addressChanged('li',
    'old-li@example.com', ''));
  await record('address changed nothing', uses.addressChanged('li', '', 'x'));
  log.debug("Leaving usesPart().");
  return out;
}

// ===========================================================================
// THE OTHER DIRECTION.
// ===========================================================================

/**
 * Checks `mail-rust.json` in Node: every raw message Rust composed and
 * signed verifies under Node's DKIM verifier.
 *
 * @param {any} t - the runner's check collector
 * @param {any} v - mail-rust.json
 * @returns {Promise<void>} when done
 */
async function fromRust(t, v) {
  log.debug("Entering fromRust().");
  const crypto = require(path.join(__dirname, '..', '..', 'common',
                                   'crypto.js'));
  (v.signed || []).forEach(function (one) {
    const raw = Buffer.from(one.raw, 'base64');
    const verified = crypto.dkimVerify(raw, one.publicKeyPem);
    t.check(!!verified && verified.ok === true, 'mail: ' + one.label +
            ': the DKIM signature Rust made verifies in Node',
            JSON.stringify(verified));
  });
  t.check((v.signed || []).length > 0, 'mail: Rust signed messages',
          String((v.signed || []).length));
  log.debug("Leaving fromRust().");
}

if (require.main === module && process.argv[2] === '--child') {
  child(process.argv[3], process.argv[4]).then(function () {
    process.exit(0);
  }, function (e) {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { build: build, fromRust: fromRust };
