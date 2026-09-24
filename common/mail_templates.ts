'use strict';
//
// File: mail_templates.ts
//
// ===========================================================================
// THE MAIL CHANNEL'S MESSAGES (#63, 2026-09-22): what each one says, in each
// language a realm has written it in, and the rules a template must keep.
//
// A LIBRARY (rule 3), and one only `common/mail.ts` requires. It holds the
// BUILT-IN template of every message this service sends, in English, and
// renders a template — built-in or a realm's own — into a subject, a plain
// text part and an HTML part. It stores nothing: a realm's own templates are
// rows in `common/mail.ts`'s `mail.templates` store, handed in here.
//
// ---------------------------------------------------------------------------
// FOUR THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. A VALUE IS ESCAPED, EVERYWHERE, BY THE RENDERER — NEVER BY A CALLER.**
// `{{name}}` in the HTML part is `Html.esc()` of the value; in the text part
// and the subject it is the value with every control character (CR and LF
// above all — a header injection) replaced by a space. A caller hands raw
// values and cannot opt out.
//
// **2. A LINK IS A PLACEHOLDER, AND ONLY EVER THIS SERVICE'S OWN.** A template
// declares which of its placeholders are LINKS (`links`), and the value of a
// link is built by `common/mail.ts` from a PATH on this service's pinned
// origin — never from a request, never from a caller's URL. A template that
// writes an absolute URL of its own (`http:` or `https:` anywhere, in any
// part) is REFUSED when it is saved, so a realm's own wording cannot point a
// reset link somewhere else either.
//
// **3. NO REMOTE CONTENT, NO SCRIPT, NO TRACKING.** The HTML part may not
// carry an image, a stylesheet, a frame, a form, a script, an event handler,
// a `src`, a `srcset`, a `background`, a CSS `url()` or a `data:` or
// `javascript:` URI, and an `href` must be exactly one link placeholder. A
// message that loads nothing when it is opened tells nobody when it was.
//
// **4. A TEMPLATE IS NAMED FOR WHAT IT IS ABOUT, AND ITS CATEGORY IS FIXED.**
// `security` messages cannot be opted out of, `account` messages are ones a
// person or an administrator asked for (a link), and `notification` is the
// one category a person may decline. A realm may reword a template; it may
// not move it to another category, because that is what decides whether a
// person can refuse it.
// ===========================================================================

import Html = require('./html');
import helpers = require('./helpers');

type Json = any;

// The categories, and whether a person may decline each.
const CATEGORIES = [
  { id: 'security', optional: false,
    label: 'Security notices',
    // #64: the layout's `{{reason}}`, finishing "because it is ...".
    reason: 'a security notice about your account, which cannot be turned ' +
            'off',
    what: 'Something happened to your account: it was disabled, your ' +
          'sessions were ended, your password changed, a credential was ' +
          'marked compromised, recovery was started, your address changed.' },
  { id: 'account', optional: false,
    label: 'Links you or an administrator asked for',
    reason: 'something you or an administrator asked for',
    what: 'A password reset link, an activation link, an address ' +
          'verification link, a test message.' },
  { id: 'notification', optional: true,
    label: 'Notifications',
    reason: 'a notification, which you can turn off on your portal',
    what: 'Everything else this service may tell you about. Nothing sends ' +
          'in this category yet; it is where #62\'s messages will go, and ' +
          'declining it now is honoured then. (#64\'s sign-in codes and ' +
          'links are SECURITY messages: declining them would be declining ' +
          'to sign in.)' }
];

interface TemplateSpec {
  id: string;
  category: string;
  title: string;
  // Placeholders a caller supplies as plain values.
  values: string[];
  // Placeholders that are links: a PATH is supplied, the origin is added.
  links: string[];
  subject: string;
  text: string;
  html: string;
}

// ---------------------------------------------------------------------------
// THE BUILT-IN TEMPLATES, in English. `{{realm}}` (the realm's display name)
// and `{{service}}` (this service's name for the realm) are supplied to every
// template by `common/mail.ts` and need not be declared.
// ---------------------------------------------------------------------------
const COMMON = ['realm', 'service'];

const BUILT_IN: TemplateSpec[] = [
  { id: 'password-reset', category: 'account',
    title: 'A password reset link',
    values: ['username', 'expiresMinutes', 'requestedBy'],
    links: ['link'],
    subject: 'Reset your {{service}} password',
    text: 'Somebody — {{requestedBy}} — asked to reset the password of the ' +
          'account {{username}}.\n\nTo choose a new password, open this ' +
          'link within {{expiresMinutes}} minutes:\n\n{{link}}\n\nIt works ' +
          'once. If you did not ask for this, you can ignore this message: ' +
          'nothing changes until the link is used.\n',
    html: '<p>Somebody &mdash; {{requestedBy}} &mdash; asked to reset the ' +
          'password of the account <strong>{{username}}</strong>.</p>' +
          '<p><a href="{{link}}">Choose a new password</a> within ' +
          '{{expiresMinutes}} minutes. The link works once.</p>' +
          '<p>If you did not ask for this, you can ignore this message: ' +
          'nothing changes until the link is used.</p>' },
  { id: 'account-activation', category: 'account',
    title: 'An account activation link',
    values: ['username', 'expiresMinutes'],
    links: ['link'],
    subject: 'Activate your {{service}} account',
    text: 'An account, {{username}}, was created for you.\n\nTo choose ' +
          'its password, open this link within {{expiresMinutes}} ' +
          'minutes:\n\n{{link}}\n\nIt works once.\n',
    html: '<p>An account, <strong>{{username}}</strong>, was created for ' +
          'you.</p><p><a href="{{link}}">Choose its password</a> within ' +
          '{{expiresMinutes}} minutes. The link works once.</p>' },
  { id: 'address-verification', category: 'account',
    title: 'An address verification link',
    values: ['username', 'address', 'expiresMinutes'],
    links: ['link'],
    subject: 'Confirm your address for {{service}}',
    text: 'The account {{username}} names {{address}} as its email ' +
          'address.\n\nTo confirm that this is your address, open this ' +
          'link within {{expiresMinutes}} minutes:\n\n{{link}}\n\nIf this ' +
          'is not your account, ignore this message.\n',
    html: '<p>The account <strong>{{username}}</strong> names ' +
          '{{address}} as its email address.</p><p><a href="{{link}}">' +
          'Confirm that this is your address</a> within {{expiresMinutes}} ' +
          'minutes.</p><p>If this is not your account, ignore this ' +
          'message.</p>' },
  { id: 'password-changed', category: 'security',
    title: 'Your password was changed',
    values: ['username', 'when', 'how'],
    links: [],
    subject: 'Your {{service}} password was changed',
    text: 'The password of the account {{username}} was changed at ' +
          '{{when}} ({{how}}).\n\nIf this was not you, contact whoever ' +
          'manages your account now.\n',
    html: '<p>The password of the account <strong>{{username}}</strong> ' +
          'was changed at {{when}} ({{how}}).</p><p>If this was not you, ' +
          'contact whoever manages your account now.</p>' },
  { id: 'account-disabled', category: 'security',
    title: 'Your account was disabled',
    values: ['username', 'when', 'why'],
    links: [],
    subject: 'Your {{service}} account was disabled',
    text: 'The account {{username}} was disabled at {{when}}. {{why}}\n\n' +
          'Nobody can sign in to it until it is enabled again, and every ' +
          'session it held has been ended.\n',
    html: '<p>The account <strong>{{username}}</strong> was disabled at ' +
          '{{when}}. {{why}}</p><p>Nobody can sign in to it until it is ' +
          'enabled again, and every session it held has been ended.</p>' },
  { id: 'sessions-ended', category: 'security',
    title: 'Your sessions were ended',
    values: ['username', 'when', 'count', 'by'],
    links: [],
    subject: 'You were signed out of {{service}}',
    text: '{{count}} session(s) of the account {{username}} were ended at ' +
          '{{when}} by {{by}}.\n\nSign in again to continue. If you did ' +
          'not expect this, contact whoever manages your account.\n',
    html: '<p>{{count}} session(s) of the account ' +
          '<strong>{{username}}</strong> were ended at {{when}} by ' +
          '{{by}}.</p><p>Sign in again to continue. If you did not expect ' +
          'this, contact whoever manages your account.</p>' },
  { id: 'credential-compromised', category: 'security',
    title: 'A credential was marked compromised',
    values: ['username', 'when', 'what', 'why'],
    links: [],
    subject: 'A {{service}} credential of yours was marked compromised',
    text: 'The {{what}} of the account {{username}} was marked compromised ' +
          'at {{when}}. {{why}}\n\nIt no longer works. Choose a new one ' +
          'when you next sign in, or ask whoever manages your account.\n',
    html: '<p>The {{what}} of the account <strong>{{username}}</strong> ' +
          'was marked compromised at {{when}}. {{why}}</p><p>It no longer ' +
          'works. Choose a new one when you next sign in, or ask whoever ' +
          'manages your account.</p>' },
  { id: 'recovery-started', category: 'security',
    title: 'Account recovery was started',
    values: ['username', 'when', 'by'],
    links: [],
    subject: 'Recovery of your {{service}} account was started',
    text: 'Recovery of the account {{username}} was started at {{when}} by ' +
          '{{by}}.\n\nIf this was not you or somebody you asked, contact ' +
          'whoever manages your account now.\n',
    html: '<p>Recovery of the account <strong>{{username}}</strong> was ' +
          'started at {{when}} by {{by}}.</p><p>If this was not you or ' +
          'somebody you asked, contact whoever manages your account ' +
          'now.</p>' },
  { id: 'address-changed', category: 'security',
    title: 'Your address was changed',
    values: ['username', 'when', 'address'],
    links: [],
    subject: 'The email address of your {{service}} account was changed',
    text: 'The email address of the account {{username}} was changed at ' +
          '{{when}}, to {{address}}. This message went to the address it ' +
          'had before.\n\nIf you did not expect this, contact whoever ' +
          'manages your account now.\n',
    html: '<p>The email address of the account <strong>{{username}}' +
          '</strong> was changed at {{when}}, to {{address}}. This message ' +
          'went to the address it had before.</p><p>If you did not expect ' +
          'this, contact whoever manages your account now.</p>' },
  { id: 'administrator-alert', category: 'security',
    title: 'An act of the service, for administrators',
    values: ['username', 'when', 'act', 'why'],
    links: [],
    subject: '{{service}}: {{act}} for {{username}}',
    text: 'This service, not a person, took an act on the account ' +
          '{{username}} at {{when}}: {{act}}.\n\n{{why}}\n\nYou receive ' +
          'this because you hold Admin Write in this realm.\n',
    html: '<p>This service, not a person, took an act on the account ' +
          '<strong>{{username}}</strong> at {{when}}: {{act}}.</p>' +
          '<p>{{why}}</p><p>You receive this because you hold Admin Write ' +
          'in this realm.</p>' },
  // -------------------------------------------------------------------------
  // #64: THE THREE MESSAGES OF THE EMAIL MECHANISMS AND THE RECOVERY-CODE
  // RESET. `security`, so nobody can decline them: a sign-in code is asked
  // for by the person, and a refused reset is exactly what they must hear.
  // A sign-in code or link is never logged: `common/mail.ts` drops a sent
  // message's body, and the step keeps only a hash.
  // -------------------------------------------------------------------------
  { id: 'sign-in-code', category: 'security',
    title: 'A sign-in code',
    values: ['username', 'code', 'minutes'],
    links: [],
    subject: 'Your {{service}} sign-in code: {{code}}',
    text: 'Your code to sign in to {{service}} as {{username}} is:\n\n' +
          '    {{code}}\n\nIt works once, for {{minutes}} minutes. Nobody ' +
          'from {{service}} will ever ask you for it.\n\nIf you are not ' +
          'signing in, somebody who knows your account name is trying to: ' +
          'ignore this code, and consider changing your password.\n',
    html: '<p>Your code to sign in to {{service}} as ' +
          '<strong>{{username}}</strong> is:</p><p><strong>' +
          '{{code}}</strong></p><p>It works once, for {{minutes}} minutes. ' +
          'Nobody from {{service}} will ever ask you for it.</p><p>If you ' +
          'are not signing in, somebody who knows your account name is ' +
          'trying to: ignore this code, and consider changing your ' +
          'password.</p>' },
  { id: 'sign-in-link', category: 'security',
    title: 'A sign-in link',
    values: ['username', 'minutes'],
    links: ['signin'],
    subject: 'Your {{service}} sign-in link',
    text: 'To finish signing in to {{service}} as {{username}}, open this ' +
          'link IN THE BROWSER WHERE YOU STARTED SIGNING IN, within ' +
          '{{minutes}} minutes:\n\n{{signin}}\n\nIt works once, and ' +
          'only in that browser.\n\nIf you are not signing in, ignore ' +
          'this message: the link cannot sign anybody else in.\n',
    html: '<p>To finish signing in to {{service}} as ' +
          '<strong>{{username}}</strong>, <a href="{{signin}}">open this ' +
          'link</a> in the browser where you started signing in, within ' +
          '{{minutes}} minutes.</p><p>It works once, and only in that ' +
          'browser.</p><p>If you are not signing in, ignore this message: ' +
          'the link cannot sign anybody else in.</p>' },
  { id: 'reset-refused-attempt', category: 'security',
    title: 'A password reset was refused',
    values: ['username', 'when'],
    links: [],
    subject: 'Somebody tried to reset your {{service}} password',
    text: 'At {{when}} somebody asked to reset the password of the ' +
          'account {{username}}, named this address, and gave a recovery ' +
          'code that is not one of yours. Nothing was changed and no reset ' +
          'link was sent.\n\nIf this was you, try again with an unused ' +
          'recovery code. If it was not, somebody knows your account name ' +
          'and address; contact whoever manages your account.\n',
    html: '<p>At {{when}} somebody asked to reset the password of the ' +
          'account <strong>{{username}}</strong>, named this address, and ' +
          'gave a recovery code that is not one of yours. Nothing was ' +
          'changed and no reset link was sent.</p><p>If this was you, try ' +
          'again with an unused recovery code. If it was not, somebody ' +
          'knows your account name and address; contact whoever manages ' +
          'your account.</p>' },
  // -------------------------------------------------------------------------
  // #64: THE STANDARD LAYOUT, wrapped round EVERY message's body. Not a
  // message itself — `send()` refuses it by name — and reworded per realm
  // like any other, which is the "standard email template ... per-realm
  // customization" the ticket asked for. `{{content}}` is the message's own
  // rendered body (HTML already escaped, text already plain) and must appear
  // exactly once in each part; `{{subject}}` is the message's own subject;
  // `{{reason}}` is why the person received it (its category).
  // -------------------------------------------------------------------------
  { id: 'layout', category: 'account',
    title: 'The layout every message is wrapped in',
    values: ['subject', 'content', 'reason'],
    links: [],
    subject: '{{subject}}',
    text: '{{content}}\n-- \n{{service}} ({{realm}})\nYou received this ' +
          'because it is {{reason}}.\n',
    html: '<div>{{content}}</div><hr><p><small>{{service}} ({{realm}}). ' +
          'You received this because it is {{reason}}.</small></p>' },
  { id: 'test-message', category: 'account',
    title: 'A test message',
    values: ['username', 'when', 'transport'],
    links: [],
    subject: '{{service}} test message',
    text: 'This is a test message, sent at {{when}} through the ' +
          '{{transport}} transport at the request of {{username}}.\n',
    html: '<p>This is a test message, sent at {{when}} through the ' +
          '{{transport}} transport at the request of ' +
          '<strong>{{username}}</strong>.</p>' }
];

// The HTML a template may not contain (header point 3). Case-insensitive.
const FORBIDDEN_HTML: Array<[RegExp, string]> = [
  [/<\s*(script|img|image|iframe|frame|object|embed|link|style|form|input|button|video|audio|source|svg|math|meta|base)\b/i,
   'an element that loads or runs something'],
  [/\s(src|srcset|background|poster|formaction|action|data|xlink:href|style)\s*=/i,
   'an attribute that loads something (src, srcset, background, style…)'],
  [/\son[a-z]+\s*=/i, 'an event handler attribute'],
  [/url\s*\(/i, 'a CSS url()'],
  [/(javascript|data|vbscript)\s*:/i, 'a javascript:, data: or vbscript: URI']
];

// #64: the id of the layout every message is wrapped in.
const LAYOUT_ID = 'layout';

class MailTemplates {
  static readonly LAYOUT_ID = LAYOUT_ID;
  static readonly CATEGORIES = CATEGORIES;
  static readonly BUILT_IN = BUILT_IN;
  static readonly COMMON = COMMON;

  // The built-in template with this id, or null.
  static builtIn(id: string): TemplateSpec | null {
    helpers.log.debug("Entering MailTemplates.builtIn(). " + id);
    const found = BUILT_IN.filter(function (one) {
      return one.id === id;
    })[0] || null;
    helpers.log.debug("Leaving MailTemplates.builtIn().");
    return found;
  }

  static category(id: string): Json {
    helpers.log.debug("Entering MailTemplates.category(). " + id);
    helpers.log.debug("Leaving MailTemplates.category().");
    return CATEGORIES.filter(function (one) {
      return one.id === id;
    })[0] || null;
  }

  // Every `{{name}}` in a piece of text.
  static placeholders(text: string): string[] {
    helpers.log.debug("Entering MailTemplates.placeholders().");
    const out: string[] = [];
    String(text || '').replace(/\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}/g,
      function (whole: string, name: string): string {
        if (out.indexOf(name) < 0) {
          out.push(name);
        }
        return whole;
      });
    helpers.log.debug("Leaving MailTemplates.placeholders().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT IS WRONG WITH A REALM'S TEMPLATE, as one sentence, or '' — asked
  // when it is SAVED, so a template that breaks the rules never exists to be
  // rendered. `spec` is the built-in it rewords.
  // -------------------------------------------------------------------------
  static problem(spec: TemplateSpec, parts: Json): string {
    helpers.log.debug("Entering MailTemplates.problem(). " +
                      (spec && spec.id));
    if (!spec) {
      helpers.log.debug("Leaving MailTemplates.problem(). Unknown.");
      return 'there is no such message';
    }
    const subject = String((parts && parts.subject) || '');
    const text = String((parts && parts.text) || '');
    const html = String((parts && parts.html) || '');
    if (!subject.trim() || !text.trim() || !html.trim()) {
      helpers.log.debug("Leaving MailTemplates.problem(). Empty part.");
      return 'a template needs a subject, a text part and an HTML part';
    }
    if (subject.length > 250 || text.length > 20000 || html.length > 40000) {
      helpers.log.debug("Leaving MailTemplates.problem(). Too long.");
      return 'a subject is at most 250 characters, a text part 20000 and ' +
             'an HTML part 40000';
    }
    if (/[\r\n]/.test(subject)) {
      helpers.log.debug("Leaving MailTemplates.problem(). Subject lines.");
      return 'a subject is one line';
    }
    const known = COMMON.concat(spec.values, spec.links);
    const all = [subject, text, html];
    for (let i = 0; i < all.length; i++) {
      if (/https?:\/\//i.test(all[i]) || /\bmailto:/i.test(all[i])) {
        helpers.log.debug("Leaving MailTemplates.problem(). A URL.");
        return 'a template may not write an address of its own — a link is ' +
               'a placeholder (' + (spec.links.length
                 ? spec.links.map(function (l) { return '{{' + l + '}}'; })
                   .join(', ') : 'this message has none') +
               ') whose value is this service\'s own';
      }
      const unknown = MailTemplates.placeholders(all[i]).filter(
        function (name) {
          return known.indexOf(name) < 0;
        });
      if (unknown.length) {
        helpers.log.debug("Leaving MailTemplates.problem(). Unknown name.");
        return 'unknown placeholder(s) ' + unknown.map(function (n) {
          return '{{' + n + '}}';
        }).join(', ') + '; this message offers ' + known.map(function (n) {
          return '{{' + n + '}}';
        }).join(', ');
      }
    }
    if (spec.id === LAYOUT_ID) {
      // THE LAYOUT CARRIES THE MESSAGE EXACTLY ONCE in each part: a layout
      // without it would send every message empty, and one with it twice
      // would send every code twice.
      const once = function (part: string): boolean {
        helpers.log.debug("Entering once().");
        helpers.log.debug("Leaving once().");
        return (part.match(/\{\{\s*content\s*\}\}/g) || []).length === 1;
      };
      if (!once(text) || !once(html)) {
        helpers.log.debug("Leaving MailTemplates.problem(). No content.");
        return 'the layout must carry {{content}} exactly once in the text ' +
               'part and once in the HTML part — it is where every ' +
               'message\'s own body goes';
      }
      if (!/\{\{\s*subject\s*\}\}/.test(subject)) {
        helpers.log.debug("Leaving MailTemplates.problem(). No subject.");
        return 'the layout\'s subject must carry {{subject}}, the ' +
               'message\'s own subject';
      }
    }
    if (spec.links.length && spec.links.some(function (name) {
      return text.indexOf('{{' + name + '}}') < 0;
    })) {
      helpers.log.debug("Leaving MailTemplates.problem(). Link missing.");
      return 'the text part must carry every link (' +
             spec.links.map(function (l) { return '{{' + l + '}}'; })
               .join(', ') + '), because a reader may see no HTML at all';
    }
    for (let i = 0; i < FORBIDDEN_HTML.length; i++) {
      if (FORBIDDEN_HTML[i][0].test(html)) {
        helpers.log.debug("Leaving MailTemplates.problem(). Forbidden.");
        return 'the HTML part may not carry ' + FORBIDDEN_HTML[i][1] +
               ': a message this service sends loads nothing and runs ' +
               'nothing when it is opened';
      }
    }
    const hrefs = html.match(/\shref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi) || [];
    const badHref = hrefs.filter(function (one) {
      const value = one.replace(/^\s*href\s*=\s*/i, '')
        .replace(/^["']|["']$/g, '').trim();
      const m = /^\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}$/.exec(value);
      return !m || spec.links.indexOf(m[1]) < 0;
    });
    if (badHref.length) {
      helpers.log.debug("Leaving MailTemplates.problem(). Bad href.");
      return 'an href must be exactly one link placeholder (' +
             (spec.links.map(function (l) { return '{{' + l + '}}'; })
               .join(', ') || 'this message has none') + ')';
    }
    helpers.log.debug("Leaving MailTemplates.problem(). Fine.");
    return '';
  }

  // A value as it goes into a subject or a text part: no control character,
  // CR and LF above all.
  static plain(value: unknown): string {
    helpers.log.debug("Entering MailTemplates.plain().");
    helpers.log.debug("Leaving MailTemplates.plain().");
    // eslint-disable-next-line no-control-regex
    return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f]/g,
                                                      ' ');
  }

  // -------------------------------------------------------------------------
  // RENDER. `parts` is the template (a realm's, or the built-in), `values`
  // every placeholder's raw value — links already absolute, built by
  // `common/mail.ts`. A placeholder with no value renders empty. The text
  // part keeps its line breaks; a VALUE in it loses any of its own.
  // -------------------------------------------------------------------------
  static render(parts: Json, values: Json): Json {
    helpers.log.debug("Entering MailTemplates.render().");
    const v = values || {};
    const fill = function (text: string, escape: (x: unknown) => string):
      string {
      helpers.log.debug("Entering fill().");
      helpers.log.debug("Leaving fill().");
      return String(text || '').replace(
        /\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}/g,
        function (whole: string, name: string): string {
          return Object.prototype.hasOwnProperty.call(v, name)
            ? escape(v[name]) : '';
        });
    };
    const out = {
      subject: fill(parts.subject, MailTemplates.plain).trim(),
      text: fill(parts.text, MailTemplates.plain),
      html: fill(parts.html, function (x: unknown): string {
        return Html.esc(x);
      })
    };
    helpers.log.debug("Leaving MailTemplates.render().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE LAYOUT, WRAPPED ROUND A RENDERED MESSAGE (#64). `rendered` is
  // `render()`'s answer for the message; its body goes in as `{{content}}`
  // UNESCAPED — it was escaped when it was rendered, and escaping it again
  // would print its markup — and its subject as `{{subject}}`. Every other
  // placeholder is filled as `render()` fills one. The layout was checked by
  // `problem()` when it was saved, so it cannot add a link or load anything.
  // -------------------------------------------------------------------------
  static wrap(layoutParts: Json, rendered: Json, values: Json): Json {
    helpers.log.debug("Entering MailTemplates.wrap().");
    const v = Object.assign({}, values || {});
    delete v.content;
    delete v.subject;
    const fill = function (text: string, escape: (x: unknown) => string,
                           content: string): string {
      helpers.log.debug("Entering fill().");
      helpers.log.debug("Leaving fill().");
      return String(text || '').replace(
        /\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}/g,
        function (whole: string, name: string): string {
          if (name === 'content') {
            return content;
          }
          if (name === 'subject') {
            return escape(rendered.subject);
          }
          return Object.prototype.hasOwnProperty.call(v, name)
            ? escape(v[name]) : '';
        });
    };
    const out = {
      subject: fill(layoutParts.subject, MailTemplates.plain, '').trim() ||
               rendered.subject,
      text: fill(layoutParts.text, MailTemplates.plain, rendered.text),
      html: fill(layoutParts.html, function (x: unknown): string {
        return Html.esc(x);
      }, rendered.html)
    };
    helpers.log.debug("Leaving MailTemplates.wrap().");
    return out;
  }

  // The HTML part wrapped in the one document every message is — no head
  // that loads anything, and a language tag.
  static htmlDocument(body: string, lang: string): string {
    helpers.log.debug("Entering MailTemplates.htmlDocument().");
    helpers.log.debug("Leaving MailTemplates.htmlDocument().");
    return '<!DOCTYPE html><html lang="' + Html.esc(lang || 'en') + '">' +
           '<head><meta charset="utf-8"></head><body>' + body +
           '</body></html>';
  }

  // -------------------------------------------------------------------------
  // WHICH LANGUAGES TO TRY, best first, for an entry's `preferredLanguage`
  // (RFC 2798: an Accept-Language value, "de-CH, de;q=0.8, en;q=0.5"): each
  // tag and then its primary subtag, by q, then the realm's default, then
  // `en`, which every built-in template has.
  // -------------------------------------------------------------------------
  static languageOrder(preferred: string, fallback: string): string[] {
    helpers.log.debug("Entering MailTemplates.languageOrder().");
    const ranked = String(preferred || '').split(',').map(function (part,
                                                                    i) {
      const bits = part.trim().split(';');
      const tag = String(bits[0] || '').trim().toLowerCase();
      const q = bits.slice(1).map(function (b) {
        const m = /^\s*q\s*=\s*([0-9.]+)\s*$/.exec(b);
        return m ? Number(m[1]) : NaN;
      }).filter(function (n) { return !isNaN(n); })[0];
      return { tag: tag, q: q === undefined ? 1 : q, i: i };
    }).filter(function (one) {
      return /^[a-z]{1,8}(-[a-z0-9]{1,8})*$/.test(one.tag) && one.q > 0;
    }).sort(function (a, b) {
      return (b.q - a.q) || (a.i - b.i);
    });
    const out: string[] = [];
    const add = function (tag: string): void {
      helpers.log.debug("Entering add().");
      if (tag && out.indexOf(tag) < 0) {
        out.push(tag);
      }
      helpers.log.debug("Leaving add().");
    };
    ranked.forEach(function (one) {
      add(one.tag);
      add(one.tag.split('-')[0]);
    });
    add(String(fallback || '').trim().toLowerCase());
    add('en');
    helpers.log.debug("Leaving MailTemplates.languageOrder(). " +
                      out.join(','));
    return out;
  }
}

export = MailTemplates;
