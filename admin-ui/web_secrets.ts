// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_secrets.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SECRET STORE, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Secret store from the answer of `GET /admin-api/secrets`:
// where the key-encryption key and the database password come from, and what
// each store reports about itself.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `SecretsAdmin`'s in `admin-ui/secrets_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// ---------------------------------------------------------------------------
// RENDERING A VALUE THIS PAGE HAS NEVER HEARD OF.
//
// Every probe's `data` is somebody else's shape — a `sys/health` body, a
// `DescribeSecret` reply, a stat — so this is the only thing that decides how
// an arbitrary one is drawn, exactly as `database_admin.ts`'s `cell()` is for
// PostgreSQL. The cases are each a real shape that arrives here:
//
//   * **`null` is not `false` and not an empty string.** A null `expires` is
//     a secret that does not expire; a false one would be a lie about a
//     field nobody set.
//   * **A boolean is a state and not a quality**, so it is drawn in words and
//     never in green: `sealed: true` is bad and `renewable: true` is good,
//     and a renderer that coloured them would be guessing.
//   * **An ISO timestamp gets a relative reading beside it**, because
//     "2026-03-01T09:12:44Z" and "six months ago" are answers to two
//     different questions and the second is the one somebody reading a
//     monitoring page is asking.
// ---------------------------------------------------------------------------
const ISO_LIKE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

/**
 * Draws Monitoring → Secret store from the answer of `GET /admin-api/secrets`:
 * where the key-encryption key and the database password come from, and what
 * each store reports about itself.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SecretsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`), whose translator
   *   the page is drawn with (#539); the default when absent
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return SecretsPage.body(view, (ctx && ctx.t) || kit.context().t);
  }

  // Every helper below takes the page's translator `t` (#539) from body().
  static ago(iso: Json, t: Json): string {
    const then = Date.parse(iso);
    if (!then) {
      return '';
    }
    const seconds = Math.round((Date.now() - then) / 1000);
    const future = seconds < 0;
    const n = Math.abs(seconds);
    let said;
    if (n < 90) {
      said = t.text('consoleSecrets.seconds', { n: n });
    } else if (n < 5400) {
      said = t.text('consoleSecrets.minutes', { n: Math.round(n / 60) });
    } else if (n < 172800) {
      said = t.text('consoleSecrets.hours', { n: Math.round(n / 3600) });
    } else {
      said = t.text('consoleSecrets.days', { n: Math.round(n / 86400) });
    }
    return future ? t.text('consoleSecrets.inFuture', { said: said })
                  : t.text('consoleSecrets.ago', { said: said });
  }

  static cell(value: Json, t: Json): string {
    const self = this;
    if (value === null || value === undefined) {
      return '<span class="muted">&mdash;</span>';
    }
    if (typeof value === 'boolean') {
      return value ? t.html('consoleSecrets.yes') : t.html('consoleSecrets.no');
    }
    if (Array.isArray(value)) {
      if (!value.length) {
        return '<span class="muted">' + t.html('consoleSecrets.none') +
               '</span>';
      }
      if (value.every(function (one) {
        return one === null || typeof one !== 'object';
      })) {
        return value.map(function (one) {
          return '<code>' + kit.esc(String(one)) + '</code>';
        }).join(' ');
      }
      return '<div class="wide">' + value.map(function (one) {
        return self.objectTable(one, t);
      }).join('') + '</div>';
    }
    if (typeof value === 'object') {
      return self.objectTable(value, t);
    }
    const text = String(value);
    if (ISO_LIKE.test(text)) {
      const relative = self.ago(text, t);
      return kit.esc(text.replace('T', ' ').replace(/\.\d+/, '')) +
             (relative ? ' <span class="muted">(' + kit.esc(relative) +
                         ')</span>' : '');
    }
    // A certificate fingerprint, a mounted path or an ARN runs past the width
    // of the page; `clipped()` is the console's own control for that and opens
    // out on a click, so nothing is lost.
    //
    // **A VALUE WITH SPACES IN IT IS PROSE AND IS GIVEN TWICE THE ROOM.** Some
    // of what a probe answers is a SENTENCE — `capabilities` ends with a
    // verdict this service composed — and clipping a sentence at the width that
    // suits a fingerprint hides the half that says what to do about it, behind
    // a control whose label is "click the value to select it all, then copy".
    // An identifier is the thing worth folding; a sentence is the thing worth
    // reading.
    const limit = text.indexOf(' ') >= 0 ? 160 : 80;
    if (text.length > limit) {
      return kit.clipped(text, limit, t);
    }
    return kit.esc(text);
  }

  // A nested object, drawn as its own little table. The recursion is what lets
  // this page draw a `replication` block or a `rotationRules` block without
  // naming a single member of either — which is the same reason
  // `/admin/database` asks for every column rather than the ones it knows.
  static objectTable(value: Json, t: Json): string {
    const self = this;
    if (value === null || typeof value !== 'object') {
      return self.cell(value, t);
    }
    const keys = Object.keys(value);
    if (!keys.length) {
      return '<span class="muted">' + t.html('consoleSecrets.empty') +
             '</span>';
    }
    return '<table class="grid"><tbody>' +
      keys.map(function (key) {
        return '<tr><th>' + self.label(key) + '</th><td>' +
               self.cell(value[key], t) + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  }

  // A member name as a person reads it. The raw name goes in a `title`, because
  // `cas_required` is what somebody searching OpenBao's documentation will type
  // and a page that only showed "cas required" would have cost them the string
  // they need.
  static label(name: Json): string {
    const text = String(name)
      .replace(/_/g, ' ')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return '<span title="' + kit.esc(String(name)) + '">' +
           kit.esc(text) + '</span>';
  }

  // ---------------------------------------------------------------------------
  // WHY A PROBE DID NOT ANSWER.
  //
  // `database_admin.ts` tells 42P01 from 42501 because "an older server" and
  // "this role may not" are completely different things to do about. The same
  // is true here and the codes are HTTP ones: **403 is the policy working**,
  // which is the single most misread row on this page, and a missing file is
  // the ordinary state of a development-mode service that has never needed a
  // key.
  // ---------------------------------------------------------------------------
  // The explanation is this page's own prose and is translated (#539); the
  // probe's error itself, drawn above it, stays as the store wrote it.
  static whyNot(probe: Json, t: Json): string {
    if (probe.status === 403) {
      return t.html('consoleSecrets.why403');
    }
    if (probe.status === 404) {
      return t.html('consoleSecrets.why404');
    }
    if (probe.status === 400) {
      return t.html('consoleSecrets.why400');
    }
    if (/ENOENT/.test(probe.error || '')) {
      return t.html('consoleSecrets.whyEnoent');
    }
    if (/EACCES/.test(probe.error || '')) {
      return t.html('consoleSecrets.whyEacces');
    }
    if (/did not answer within/.test(probe.error || '')) {
      return t.html('consoleSecrets.whyTimeout');
    }
    if (/Cannot find module|needs the /.test(probe.error || '')) {
      return t.html('consoleSecrets.whySdk');
    }
    return '';
  }

  static probeRows(probes: Json, t: Json): string {
    const self = this;
    return probes.map(function (probe) {
      return '<h4>' + kit.esc(probe.id) +
        ' <span class="muted">' +
        (probe.ok ? t.html('consoleSecrets.tookMs', { ms: probe.tookMs })
                  : t.html('consoleSecrets.unavailableTookMs',
                           { ms: probe.tookMs })) + '</span></h4>' +
        '<p class="muted">' + kit.esc(probe.what) + '</p>' +
        (probe.ok
          ? self.objectTable(probe.data, t)
          : kit.warn('<p><code>' +
                       kit.esc(String(probe.status || '') +
                                 (probe.status ? ' ' : '')) +
                       kit.esc(probe.error) + '</code></p>' +
                       (self.whyNot(probe, t)
                         ? '<p>' + self.whyNot(probe, t) + '</p>' : ''),
                       t.html('consoleSecrets.didNotAnswer')));
    }).join('');
  }

  static body(json: Json, t: Json): string {
    const self = this;

    const configured = json.secrets.filter(function (one) {
      return one.configured;
    });
    const read = json.secrets.filter(function (one) {
      return one.lastRead && one.lastRead.ok;
    });
    const tiles = '<div class="tiles">' +
      kit.tile(String(configured.length) + '/' + String(json.secrets.length),
                 t.text('consoleSecrets.tileFromStore')) +
      kit.tile(String(json.stores.length),
               t.text('consoleSecrets.tileStores')) +
      kit.tile(String(read.length), t.text('consoleSecrets.tileRead')) +
      kit.tile(json.productMode ? t.text('consoleSecrets.modeProduct')
                                : t.text('consoleSecrets.modeDevelopment'),
               t.text('consoleSecrets.tileMode')) +
      kit.tile(json.persistingKeys ? t.text('consoleSecrets.keysDurable')
                                   : t.text('consoleSecrets.keysEphemeral'),
                 t.text('consoleSecrets.tileSigningKeys')) +
      kit.tile(String(json.failed.length),
               t.text('consoleSecrets.tileUnavailable')) +
      '</div>';

    // The two links are markup a message cannot carry, so the second
    // paragraph is cut at each of them.
    const what = kit.note(
      '<p>' + t.html('consoleSecrets.whatIs') + '</p><p>' +
      t.html('consoleSecrets.whatThree') + ' <a href="/admin/config">' +
      t.html('consoleSecrets.configuration') + '</a>' +
      t.html('consoleSecrets.whatConfig') + ' <a href="/admin/encryption">' +
      t.html('consoleSecrets.encryption') + '</a> ' +
      t.html('consoleSecrets.whatEncryption') + '</p><p>' +
      t.html('consoleSecrets.whatNoControl') + '</p>',
      t.html('consoleSecrets.whatTitle'));

    const refusals = kit.warn(
      '<p>' + t.html('consoleSecrets.halfFail') + '</p><p>' +
      t.html('consoleSecrets.eachProbe', { ms: String(json.timeoutMs) }) +
      '</p>',
      t.html('consoleSecrets.halfFailTitle'));

    // **THE STATE THAT MAKES EVERY ROW BELOW MEANINGLESS, SAID FIRST.** A
    // development-mode service on a memory store never reads the
    // key-encryption key, so the configuration can be wrong in every particular
    // and nothing will say so until the day somebody sets `global.mode` to
    // product. That is the one thing a reader of this page can most easily come
    // away not knowing.
    const unused = (!json.persistingKeys && !json.productMode)
      ? kit.warn(
          '<p>' + t.html('consoleSecrets.unusedDev') + '</p><p>' +
          t.html('consoleSecrets.unusedSigning') + '</p>',
          t.html('consoleSecrets.unusedTitle'))
      : '';

    return tiles + what + refusals + unused +
           json.secrets.map(function (row) {
             return self.secretBlock(row, json, t);
           }).join('') +
           self.storesBlock(json, t);
  }

  // ---------------------------------------------------------------------------
  // ONE SECRET: what it is, where it is configured to come from, whether this
  // process has actually read it, and the probes that are about the SECRET
  // rather than about the store holding it.
  // ---------------------------------------------------------------------------
  static secretBlock(row: Json, json: Json, t: Json): string {
    const self = this;
    // The notes (heading, what, without, rotating) are the view's prose,
    // drawn in English as they come.
    const notes = json.notes[row.secret] || { heading: row.secret, what: '',
                                              without: '', rotating: '' };
    if (!row.configured) {
      return '<h3>' + kit.esc(notes.heading) + '</h3>' +
        kit.note(
          '<p>' + notes.what + '</p>' +
          '<p>' + t.html('consoleSecrets.noProvider',
                         { setting: row.settings.provider }) + '</p>' +
          '<p>' + notes.without + '</p>',
          t.html('consoleSecrets.noProviderTitle'));
    }

    const last = row.lastRead;
    // A failed read is a failure, and its box stays English (#539). The
    // muted span is markup a message cannot carry, so the sentence of a
    // good read is cut around it.
    const read = last
      ? (last.ok
          ? kit.note('<p>' +
                       t.html('consoleSecrets.readOkAt',
                              { at: String(last.at).replace('T', ' ')
                                  .replace(/\.\d+Z$/, 'Z') }) +
                       ' <span class="muted">(' +
                       kit.esc(self.ago(last.at, t)) + ')</span>' +
                       t.html('consoleSecrets.readOkFrom',
                              { ms: String(last.tookMs),
                                provider: last.provider }) +
                       '</p><p class="muted">' +
                       t.html('consoleSecrets.readOkMemory') + '</p>',
                       t.html('consoleSecrets.readOkTitle'))
          : kit.warn('<p>The last read <strong>failed</strong> at ' +
                       kit.esc(String(last.at).replace('T', ' ')
                         .replace(/\.\d+Z$/, 'Z')) + ': <code>' +
                       kit.esc(last.error) + '</code></p>',
                       'The last read of this secret failed'))
      : kit.note('<p>' + t.html('consoleSecrets.notRead') + '</p>',
                   t.html('consoleSecrets.notReadTitle'));

    const where = '<table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleSecrets.provider') + '</th><td><code>' +
        kit.esc(row.provider) +
        '</code> &mdash; ' + kit.esc(row.label) + '</td>' +
        '<td class="why">' + t.html('consoleSecrets.setBy',
                                    { setting: row.settings.provider }) +
        '</td></tr>' +
      // **`field` AND `shared` ARE SKIPPED HERE AND NOT BECAUSE THEY ARE
      // UNINTERESTING**: both have a row of their own below with the sentence
      // that makes them mean something, and a provider's `describe()` carries
      // them too. Drawn from both places they appeared twice in one table, once
      // with an explanation and once without.
      Object.keys(row.where || {}).filter(function (key) {
        return ['field', 'shared'].indexOf(key) < 0 &&
               row.where[key] !== null && row.where[key] !== undefined;
      }).map(function (key) {
        return '<tr><th>' + self.label(key) + '</th><td>' +
               self.cell(row.where[key], t) +
               '</td><td class="why"></td></tr>';
      }).join('') +
      (row.field
        ? '<tr><th>' + t.html('consoleSecrets.field') + '</th><td><code>' +
          kit.esc(row.field) + '</code></td>' +
          '<td class="why">' + t.html('consoleSecrets.fieldWhy',
                                      { setting: row.settings.field }) +
          '</td></tr>'
        : '') +
      '<tr><th>' + t.html('consoleSecrets.ownLocation') + '</th><td>' +
        (row.shared ? t.html('consoleSecrets.no')
                    : t.html('consoleSecrets.yes')) +
        '</td><td class="why">' +
        (row.shared
          ? t.html('consoleSecrets.sharedLocation')
          : t.html('consoleSecrets.namesLocation',
                   { setting: row.settings.location })) +
        '</td></tr>' +
      '</tbody></table>';

    return '<h3>' + kit.esc(notes.heading) + '</h3>' +
      kit.note('<p>' + notes.what + '</p>' +
                 '<p>' + t.html('consoleSecrets.withoutIt') + ' ' +
                 notes.without + '</p>' +
                 '<p>' + t.html('consoleSecrets.rotatingIt') + ' ' +
                 notes.rotating + '</p>',
                 t.html('consoleSecrets.whatItIsTitle')) +
      where + read +
      (row.probes.length
        ? '<h4 class="muted">' + t.html('consoleSecrets.storeSays') +
          '</h4>' +
          self.probeRows(row.probes, t)
        : '');
  }

  // ---------------------------------------------------------------------------
  // THE STORES. One block per store rather than per secret, because two secrets
  // in one Vault must not make this page ask it twice whether it is sealed —
  // and because a reader looking at *is the store up* is not asking about
  // either secret.
  // ---------------------------------------------------------------------------
  static storesBlock(json: Json, t: Json): string {
    const self = this;
    if (!json.stores.length) {
      return '<h3>' + t.html('consoleSecrets.stores') + '</h3>' +
        kit.note(t.html('consoleSecrets.noStores'));
    }
    return '<h3>' + t.html('consoleSecrets.stores') + '</h3>' +
      kit.note('<p>' + t.html('consoleSecrets.perStore') + '</p>') +
      json.stores.map(function (store) {
        return '<h4>' + kit.esc(store.label) + ' <span class="muted">' +
          kit.esc(store.where) + '</span></h4>' +
          '<p class="muted">' + t.html('consoleSecrets.holds') + ' ' +
          store.secrets.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(', ') + '</p>' +
          (store.probes.length
            ? self.probeRows(store.probes, t)
            : kit.note(t.html('consoleSecrets.nothingPublished')));
      }).join('');
  }
}

export = SecretsPage;
