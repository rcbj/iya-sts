// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_encryption.ts
//
// ---------------------------------------------------------------------------
// MONITORING → ENCRYPTION, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Encryption from the answer of `GET /admin-api/encryption`: what is
// sealed at rest and what is not, the key, the algorithm, the data encryption
// keys and their rotation, and the counting.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `EncryptionAdmin`'s in `admin-ui/encryption_admin.ts`,
// moved with their comments; that module still draws the page until the
// console's cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws Encryption from the answer of `GET /admin-api/encryption`: what is
 * sealed at rest and what is not, the key, the algorithm, the data encryption
 * keys and their rotation, and the counting.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class EncryptionPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return EncryptionPage.body(ctx, view);
  }

  // VIEW TEXT INSIDE A MESSAGE (#539). A message's parameters are escaped
  // with `&#39;` for an apostrophe, where this console has always written
  // `&apos;` (kit.esc()), so a sentence of the view's — a reason, a note —
  // goes into a message as a marker, and the marker is replaced by the text
  // escaped the console's way: the English stays the same to the byte.
  static marks(values: Json): Json {
    const out = {};
    Object.keys(values).forEach(function (name) {
      out[name] = '\u0001' + name + '\u0001';
    });
    return out;
  }

  static fill(html: string, values: Json): string {
    Object.keys(values).forEach(function (name) {
      html = html.split('\u0001' + name + '\u0001')
        .join(kit.esc(values[name]));
    });
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE PAGE.
  // ---------------------------------------------------------------------------
  static bytes(n: Json): string {
    const num = Number(n) || 0;
    if (num < 1024) {
      return num + ' B';
    }
    if (num < 1024 * 1024) {
      return (num / 1024).toFixed(1) + ' KB';
    }
    return (num / (1024 * 1024)).toFixed(1) + ' MB';
  }

  // `t` is the page's translator (#539), handed down by body().
  static when(iso: Json, t: Json): string {
    return iso ? kit.esc(String(iso).replace('T', ' ').replace(/\..*$/, 'Z'))
               : '<span class="muted">' + t.html('consoleEncryption.never') +
                 '</span>';
  }

  static classesTable(json: Json, t: Json): string {
    const self = this;
    const rows = json.classes.map(function (one) {
      // The two halves of the table are told apart by a WORD in a cell rather
      // than by two tables, because the reading a person came for is the
      // comparison — *is this encrypted and is that* — and two tables make that
      // a scroll.
      const mark = one.sealed
        ? '<span class="ok">' + t.html('consoleEncryption.sealed') + '</span>'
        : '<span class="muted">' + t.html('consoleEncryption.notSealed') +
          '</span>';
      const counts = one.sealed
        ? t.html('consoleEncryption.outIn',
                 { out: String(one.encryptions),
                   in: String(one.decryptions) }) +
          (one.failures
            ? ' <span class="bad">' +
              t.html('consoleEncryption.failed',
                     { n: String(one.failures) }) +
              '</span>' : '')
        : '<span class="muted">&mdash;</span>';
      return '<tr><td>' + one.what + '</td>' +
             '<td><code>' + kit.esc(one.where) + '</code></td>' +
             '<td>' + mark +
             (one.label ? '<br><code>' + kit.esc(one.label) + '</code>'
                        : '') +
             '</td>' +
             '<td>' + counts + '</td>' +
             '<td>' + self.when(one.lastAt, t) + '</td>' +
             '<td class="why">' + one.why + '</td></tr>';
    }).join('');
    return '<table class="grid"><thead><tr>' +
           '<th>' + t.html('consoleEncryption.thWhat') + '</th><th>' +
           t.html('consoleEncryption.thWhere') + '</th><th>' +
           t.html('consoleEncryption.thAtRest') + '</th>' +
           '<th>' + t.html('consoleEncryption.thOperations') + '</th><th>' +
           t.html('consoleEncryption.thLast') + '</th><th>' +
           t.html('consoleEncryption.thWhy') + '</th>' +
           '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  static unclassifiedBlock(json: Json, t: Json): string {
    if (!json.unclassified.length) {
      return '';
    }
    return kit.warn(
      '<p>' + t.html('consoleEncryption.unclassifiedHead',
                     { n: json.unclassified.length }) + ' ' +
      json.unclassified.map(function (row) {
        return '<code>' + kit.esc(row.label) + '</code> (' +
               t.html('consoleEncryption.outIn',
                      { out: row.encryptions, in: row.decryptions }) + ')';
      }).join(', ') + '.</p>' +
      '<p>' + t.html('consoleEncryption.unclassifiedWhy') + '</p>');
  }

  // The section drawn under the algorithm: the lifecycle, the keys, and —
  // for Admin Write, where keys are stored — the two forms. No script.
  static renderDataKeys(ctx: Json, json: Json): string {
    const t = ctx.t;
    const dk = json.dataKeys;
    const life = dk.lifecycle;
    // The reasons (`scheduleOffReason` and the like) are the view's, drawn
    // in English as they come; the sentences around them are this file's.
    const status = !life ? '<p class="warn">' +
        t.html('consoleEncryption.noRotationModule') + '</p>'
      : '<p>' + (life.on
        ? (life.scheduled
          ? t.html('consoleEncryption.rotationScheduled',
                   { days: String(life.rotationDays),
                     lead: String(life.activationLeadSeconds),
                     retire: String(life.retireAfterDays) })
          : EncryptionPage.fill(
            t.html('consoleEncryption.rotationOff',
                   EncryptionPage.marks({ reason: 1 })),
            { reason: life.scheduleOffReason }))
        : EncryptionPage.fill(
          t.html('consoleEncryption.nothingRotated',
                 EncryptionPage.marks({ reason: 1 })),
          { reason: life.offReason })) +
      t.html('consoleEncryption.directoryCipher',
             { cipher: life.directoryCipher }) + '</p>' +
      (life.on ? '<p>' + (life.counting
        ? (dk.lastCounted
            ? t.html('consoleEncryption.countedLast',
                     { when: dk.lastCounted })
            : t.html('consoleEncryption.countedNotYet'))
        : EncryptionPage.fill(
          t.html('consoleEncryption.notCounted',
                 EncryptionPage.marks({ reason: 1 })),
          { reason: life.countOffReason })) + '</p>' : '');
    const tiles = '<div class="tiles">' +
      kit.tile(String(dk.counts.current),
               t.text('consoleEncryption.tileCurrent')) +
      kit.tile(String(dk.counts.pending),
               t.text('consoleEncryption.tilePending')) +
      kit.tile(String(dk.counts.superseded),
               t.text('consoleEncryption.tileSuperseded')) +
      kit.tile(String(dk.counts.destroyed),
               t.text('consoleEncryption.tileDestroyed')) +
      kit.tile(String(dk.counts.derived),
               t.text('consoleEncryption.tileDerived')) +
      '</div>';
    const params = kit.pageParamsOf(ctx.query || {});
    const nav = kit.pageNavPair('/admin/encryption', params, dk.paging, t);
    const table = dk.keys.length
      ? nav.head + '<table class="grid"><thead><tr><th>' +
        t.html('consoleEncryption.thRealm') + '</th>' +
        '<th>' + t.html('consoleEncryption.thClass') + '</th><th>' +
        t.html('consoleEncryption.thCipher') + '</th><th>' +
        t.html('consoleEncryption.thState') + '</th><th>' +
        t.html('consoleEncryption.thCreated') + '</th>' +
        '<th>' + t.html('consoleEncryption.thUsedFrom') + '</th><th>' +
        t.html('consoleEncryption.thAge') + '</th><th>' +
        t.html('consoleEncryption.thValues') + '</th>' +
        '<th>' + t.html('consoleEncryption.thKeyId') +
        '</th></tr></thead><tbody>' +
        dk.keys.map(function (k: Json): string {
          return '<tr><td><code>' + kit.esc(k.realm) + '</code></td>' +
            '<td><code>' + kit.esc(k.cls) + '</code></td>' +
            '<td><code>' + kit.esc(k.alg) + '</code></td>' +
            '<td>' + kit.esc(k.state) + '</td>' +
            '<td>' + kit.esc(k.createdAt || '—') + '</td>' +
            '<td>' + kit.esc(k.activateAt || '—') + '</td>' +
            '<td>' + kit.esc(k.ageDays === null ? '—'
                                                  : String(k.ageDays)) +
            '</td>' +
            '<td' + (k.countedAt ? ' title="' +
                     kit.esc(t.text('consoleEncryption.countedAt',
                                    { when: k.countedAt })) + '"' : '') +
            '>' +
            kit.esc(k.values === null ? '—' : String(k.values)) + '</td>' +
            '<td>' + kit.clipped(k.id, 40, t) + '</td></tr>';

        }).join('') + '</tbody></table>' + nav.foot
      : '<p class="muted">' + t.html('consoleEncryption.noDataKey') + '</p>';
    let forms = '';
    if (life && life.on && ctx.write) {
      forms = '<h4>' + t.html('consoleEncryption.rotateByHand') + '</h4>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="rotate-data-keys">' +
        '<label>' + t.html('consoleEncryption.realmLabel') +
        ' <input type="text" ' +
        'name="realm" id="data-keys-realm" autocomplete="off"></label> ' +
        '<label>' + t.html('consoleEncryption.classLabel') +
        ' <input type="text" ' +
        'name="cls" id="data-keys-cls" autocomplete="off"></label> ' +
        '<button type="submit" id="data-keys-rotate">' +
        t.html('consoleEncryption.rotateDataKeys') +
        '</button></form>' +
        '<p class="muted">' + t.html('consoleEncryption.rotateNote') +
        '</p>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="reencrypt-data-keys">' +
        '<button type="submit" id="data-keys-reencrypt">' +
        t.html('consoleEncryption.reencryptNow') +
        '</button>' + t.html('consoleEncryption.reencryptNote') + '</form>' +
        (life.counting
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="count-data-keys">' +
            '<button type="submit" id="data-keys-count">' +
            t.html('consoleEncryption.countNow') + '</button> ' +
            t.html('consoleEncryption.countNote') + '</form>'
          : '') +
        '<h4>' + t.html('consoleEncryption.rotateKek') + '</h4>' +
        (life.kekRotation
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="rotate-kek">' +
            '<button type="submit" id="kek-rotate">' +
            t.html('consoleEncryption.rotateKekButton') + '</button>' +
            t.html('consoleEncryption.rotateKekNote') + '</form>'
          : '<p class="muted">' +
            EncryptionPage.fill(
              t.html('consoleEncryption.notFromHere',
                     EncryptionPage.marks({ reason: 1 })),
              { reason: life.kekRotationOffReason }) + '</p>');

    }
    return status + tiles + '<p class="muted">' + kit.esc(dk.note) +
           '</p>' + table + forms;
  }

  // THE PAGE'S BODY (#446), one method so that it can be one renderer.
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - `encryptionJson()`'s answer
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    const self = this;
    const t = ctx.t;

    const tiles = '<div class="tiles">' +
      kit.tile(String(json.accounting.operations),
               t.text('consoleEncryption.tileOperations')) +
      kit.tile(String(json.accounting.encryptions),
               t.text('consoleEncryption.tileEncryptions')) +
      kit.tile(String(json.accounting.decryptions),
               t.text('consoleEncryption.tileDecryptions')) +
      kit.tile(String(json.accounting.failures),
               t.text('consoleEncryption.tileFailures')) +
      kit.tile(json.key.present
        ? (json.key.persists ? t.text('consoleEncryption.kekDurable')
                             : t.text('consoleEncryption.kekEphemeral'))
        : t.text('consoleEncryption.kekNone'),
        t.text('consoleEncryption.tileKek')) +
      kit.tile(json.mode, t.text('consoleEncryption.tileMode')) +
      '</div>';

    // The two links are markup a message cannot carry, so the first
    // paragraph is cut at each of them.
    const what = kit.note(
      '<p>' + t.html('consoleEncryption.whatAnswers') +
      ' <a href="/admin/crypto-metadata">' +
      t.html('consoleEncryption.cryptoReport') + '</a>' +
      t.html('consoleEncryption.whatDoes') +
      ' <a href="/admin/keys">' + t.html('consoleEncryption.keysPage') +
      '</a>' + t.html('consoleEncryption.whatHolds') + '</p><p>' +
      t.html('consoleEncryption.whatNeither') + '</p>',
      t.html('consoleEncryption.whatTitle'));

    // The provider's label and note are the view's, drawn as they come.
    const keyBlock = kit.note(
      '<p>' + t.html('consoleEncryption.keyReadBy') + '<strong>' +
      kit.esc(json.key.providerLabel) + '</strong> ' +
      '(<code>' + kit.esc(json.key.provider) + '</code>)' +
      (json.key.kmsKey ? ' &mdash; <strong>' + kit.esc(json.key.kmsKey) +
        '</strong>' + t.html('consoleEncryption.keyKms') : '') +
      t.html('consoleEncryption.keyOnce') + '</p><p>' + json.key.note +
      '</p>' +
      '<p>' + t.html('consoleEncryption.keyShort') +
      '</p><p class="muted">' + t.html('consoleEncryption.providers') + ' ' +
      json.key.providers.map(function (one) {
        return '<code>' + kit.esc(one.id) + '</code> ' + kit.esc(one.label);
      }).join(', ') + '. ' + t.html('consoleEncryption.providersSelect') +
      '</p>',
      t.html('consoleEncryption.keyTitle'));

    // **THE LIMITS, DRAWN AS A WARNING RATHER THAN A NOTE.** Everything else on
    // this page says what IS encrypted, and a reader who stops there comes away
    // believing more than is true — which is the shape of mistake this console
    // draws in amber everywhere else.
    // The boundaries are the view's sentences, drawn as they come.
    const boundsBlock = kit.warn(
      '<p>' + kit.esc(json.boundaries.realms) + '</p>' +
      '<p>' + kit.esc(json.boundaries.storage) + '</p>' +
      '<p>' + kit.esc(json.boundaries.keyResidency) + '</p>',
      t.html('consoleEncryption.boundsTitle'));

    // The values in <code> are the module's own figures; the row names and
    // the "-bit" words around them stay as written, inside the code.
    const algBlock = kit.note(
      '<p>' + json.algorithmNote + '</p>' +
      '<table class="grid"><tbody>' +
      [[t.text('consoleEncryption.algCipher'), json.algorithm.cipher],
       [t.text('consoleEncryption.algKey'), json.algorithm.keyBits + '-bit'],
       [t.text('consoleEncryption.algNonce'),
        json.algorithm.ivBits + '-bit, random per record'],
       [t.text('consoleEncryption.algTag'), json.algorithm.tagBits + '-bit'],
       [t.text('consoleEncryption.algDataKeys'), json.algorithm.dataKeys],
       [t.text('consoleEncryption.algWrapping'), json.algorithm.dekWrap],
       [t.text('consoleEncryption.algAad'), json.algorithm.aad],
       [t.text('consoleEncryption.algEnvelope'), json.algorithm.envelope]]
        .map(function (pair) {
          return '<tr><th>' + kit.esc(pair[0]) + '</th><td><code>' +
                 kit.esc(String(pair[1])) + '</code></td></tr>';
        }).join('') +
      '</tbody></table>' +
      '<p class="muted">' + t.html('consoleEncryption.algFigures') +
      ' <a href="/admin/crypto-metadata">' +
      t.html('consoleEncryption.cryptoReport') + '</a>' +
      t.html('consoleEncryption.algFiguresAfter') + '</p>',
      t.html('consoleEncryption.algTitle'));

    const countsBlock = kit.note(
      '<p>' + json.accountingNote + '</p><p>' + json.failuresNote + '</p>' +
      '<p class="muted">' +
      t.html('consoleEncryption.countsSince',
             { since: '\u0001since\u0001', first: '\u0001first\u0001',
               last: '\u0001last\u0001',
               plain: self.bytes(json.accounting.plaintextBytes),
               cipher: self.bytes(json.accounting.ciphertextBytes) })
        // The three times are markup (a "never" is a span), so they are
        // put in after the message, at markers.
        .split('\u0001since\u0001')
        .join(self.when(json.accounting.since, t))
        .split('\u0001first\u0001')
        .join(self.when(json.accounting.firstAt, t))
        .split('\u0001last\u0001')
        .join(self.when(json.accounting.lastAt, t)) +
      '</p>',
      t.html('consoleEncryption.countsTitle'));

    const storeBlock = kit.note(
      '<p>' + json.store.note + ' ' +
      t.html(json.store.persistsMinted ? 'consoleEncryption.storeIs'
                                       : 'consoleEncryption.storeIsNot',
             { mode: json.store.mode }) + '</p>',
      t.html('consoleEncryption.storeTitle'));

    return tiles + what +
                  '<h3>' + t.html('consoleEncryption.hEncrypted') + '</h3>' +
                  self.classesTable(json, t) +
                  self.unclassifiedBlock(json, t) +
                  '<h3>' + t.html('consoleEncryption.hKey') + '</h3>' +
                  keyBlock + boundsBlock +
                  '<h3>' + t.html('consoleEncryption.hAlgorithm') + '</h3>' +
                  algBlock +
                  '<h3>' + t.html('consoleEncryption.hDataKeys') + '</h3>' +
                  self.renderDataKeys(ctx, json) +
                  '<h3>' + t.html('consoleEncryption.hCounting') + '</h3>' +
                  countsBlock +
                  storeBlock;
  }
}

export = EncryptionPage;
