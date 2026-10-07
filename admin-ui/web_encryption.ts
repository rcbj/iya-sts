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

  static when(iso: Json): string {
    return iso ? kit.esc(String(iso).replace('T', ' ').replace(/\..*$/, 'Z'))
               : '<span class="muted">never</span>';
  }

  static classesTable(json: Json): string {
    const self = this;
    const rows = json.classes.map(function (one) {
      // The two halves of the table are told apart by a WORD in a cell rather
      // than by two tables, because the reading a person came for is the
      // comparison — *is this encrypted and is that* — and two tables make that
      // a scroll.
      const mark = one.sealed
        ? '<span class="ok">sealed</span>'
        : '<span class="muted">not sealed</span>';
      const counts = one.sealed
        ? kit.esc(String(one.encryptions)) + ' out, ' +
          kit.esc(String(one.decryptions)) + ' in' +
          (one.failures
            ? ' <span class="bad">' + kit.esc(String(one.failures)) +
              ' failed</span>' : '')
        : '<span class="muted">&mdash;</span>';
      return '<tr><td>' + one.what + '</td>' +
             '<td><code>' + kit.esc(one.where) + '</code></td>' +
             '<td>' + mark +
             (one.label ? '<br><code>' + kit.esc(one.label) + '</code>'
                        : '') +
             '</td>' +
             '<td>' + counts + '</td>' +
             '<td>' + self.when(one.lastAt) + '</td>' +
             '<td class="why">' + one.why + '</td></tr>';
    }).join('');
    return '<table class="grid"><thead><tr>' +
           '<th>What</th><th>Where it lives</th><th>At rest</th>' +
           '<th>Operations</th><th>Last</th><th>Why</th>' +
           '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  static unclassifiedBlock(json: Json): string {
    if (!json.unclassified.length) {
      return '';
    }
    return kit.warn(
      '<p><strong>' + json.unclassified.length + ' label(s) were counted ' +
      'that ' +
      'this page has no row for:</strong> ' +
      json.unclassified.map(function (row) {
        return '<code>' + kit.esc(row.label) + '</code> (' +
               row.encryptions + ' out, ' + row.decryptions + ' in)';
      }).join(', ') + '.</p>' +
      '<p>That is a call site somebody added without adding a row to ' +
      '<code>DATA_CLASSES</code> in ' +
      '<code>admin-ui/encryption_admin.ts</code>. It is drawn rather than ' +
      'dropped on purpose: the alternative is a table that goes on looking ' +
      'complete while the totals above it do not add up to the rows ' +
      'below.</p>');
  }

  // The section drawn under the algorithm: the lifecycle, the keys, and —
  // for Admin Write, where keys are stored — the two forms. No script.
  static renderDataKeys(ctx: Json, json: Json): string {
    const dk = json.dataKeys;
    const life = dk.lifecycle;
    const status = !life ? '<p class="warn">The data-key rotation module ' +
        'is not loaded in this process, so nothing here can be rotated.</p>'
      : '<p>' + (life.on
        ? (life.scheduled
          ? 'Every data encryption key is rotated after <strong>' +
            kit.esc(String(life.rotationDays)) + ' day(s)</strong> ' +
            '(<code>keys.dataKeyRotationDays</code>); a new key is used ' +
            kit.esc(String(life.activationLeadSeconds)) + ' second(s) ' +
            'after it is published, and a replaced key is destroyed no ' +
            'sooner than ' + kit.esc(String(life.retireAfterDays)) +
            ' day(s) after, once nothing is sealed under it.'
          : 'Scheduled rotation is <strong>off</strong>: ' +
            kit.esc(life.scheduleOffReason) + '. A rotation by hand ' +
            'still works.')
        : 'Nothing is rotated here: ' + kit.esc(life.offReason) + '.') +
      ' Data stored in the directory is sealed with <code>' +
      kit.esc(life.directoryCipher) + '</code> ' +
      '(<code>keys.directoryCipher</code>); everything else with ' +
      '<code>aes-256-gcm</code>.</p>' +
      (life.on ? '<p>' + (life.counting
        ? 'What is sealed under each key is counted once a day ' +
          '(<code>keys.data-key-count</code>)' + (dk.lastCounted
            ? ', last at ' + kit.esc(dk.lastCounted) : ', and has not ' +
              'been counted yet') + '.'
        : 'Values are not counted: ' + kit.esc(life.countOffReason) +
          '.') + '</p>' : '');
    const tiles = '<div class="tiles">' +
      kit.tile(String(dk.counts.current), 'current') +
      kit.tile(String(dk.counts.pending), 'waiting to be used') +
      kit.tile(String(dk.counts.superseded), 'superseded') +
      kit.tile(String(dk.counts.destroyed), 'destroyed') +
      kit.tile(String(dk.counts.derived), 'derived per run') +
      '</div>';
    const params = kit.pageParamsOf(ctx.query || {});
    const nav = kit.pageNavPair('/admin/encryption', params, dk.paging);
    const table = dk.keys.length
      ? nav.head + '<table class="grid"><thead><tr><th>Realm</th>' +
        '<th>Class</th><th>Cipher</th><th>State</th><th>Created</th>' +
        '<th>Used from</th><th>Age (days)</th><th>Values</th>' +
        '<th>Key id</th></tr></thead><tbody>' +
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
            '<td' + (k.countedAt ? ' title="counted ' +
                     kit.esc(k.countedAt) + '"' : '') + '>' +
            kit.esc(k.values === null ? '—' : String(k.values)) + '</td>' +
            '<td>' + kit.clipped(k.id, 40) + '</td></tr>';
        }).join('') + '</tbody></table>' + nav.foot
      : '<p class="muted">No data encryption key is held yet: one is made ' +
        'the first time a value of its realm and class is sealed.</p>';
    let forms = '';
    if (life && life.on && ctx.write) {
      forms = '<h4>Rotate by hand</h4>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="rotate-data-keys">' +
        '<label>Realm (empty for every realm): <input type="text" ' +
        'name="realm" id="data-keys-realm" autocomplete="off"></label> ' +
        '<label>Class (empty for every class): <input type="text" ' +
        'name="cls" id="data-keys-cls" autocomplete="off"></label> ' +
        '<button type="submit" id="data-keys-rotate">Rotate data keys' +
        '</button></form>' +
        '<p class="muted">Each key gets a successor, used once it has been ' +
        'published; what the old key sealed is re-sealed by the ' +
        're-encryption job.</p>' +
        '<form method="post" action="/admin/encryption/data-keys">' +
        '<input type="hidden" name="action" value="reencrypt-data-keys">' +
        '<button type="submit" id="data-keys-reencrypt">Re-encrypt now' +
        '</button> — re-seals what is still under a superseded key, and ' +
        'destroys a superseded key nothing is sealed under that has been ' +
        'superseded long enough.</form>' +
        (life.counting
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="count-data-keys">' +
            '<button type="submit" id="data-keys-count">Count now</button> ' +
            '&mdash; counts what is sealed under every key, in one pass of ' +
            'the store.</form>'
          : '') +
        '<h4>Rotate the key-encryption key</h4>' +
        (life.kekRotation
          ? '<form method="post" action="/admin/encryption/data-keys">' +
            '<input type="hidden" name="action" value="rotate-kek">' +
            '<button type="submit" id="kek-rotate">Rotate the ' +
            'key-encryption key</button> &mdash; the key management ' +
            'service makes a new version, and every data key is re-wrapped ' +
            'under it. The earlier version stays: data keys other nodes ' +
            'wrapped under it still unwrap. The identity this service runs ' +
            'as must be allowed to rotate the key, which the deployments ' +
            'here do not grant: they rotate it on the KMS\'s own ' +
            'schedule.</form>'
          : '<p class="muted">Not from here: ' +
            kit.esc(life.kekRotationOffReason) + '.</p>');
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

    const tiles = '<div class="tiles">' +
      kit.tile(String(json.accounting.operations), 'operations') +
      kit.tile(String(json.accounting.encryptions), 'encryptions') +
      kit.tile(String(json.accounting.decryptions), 'decryptions') +
      kit.tile(String(json.accounting.failures), 'failed to open') +
      kit.tile(json.key.present
        ? (json.key.persists ? 'durable' : 'ephemeral') : 'none',
        'key-encryption key') +
      kit.tile(json.mode, 'mode') +
      '</div>';

    const what = kit.note(
      '<p>This page answers <strong>what this service encrypts at rest, with ' +
      'which key, under which algorithm, and how much of it has ' +
      'happened</strong>. It is under Monitoring rather than beside the ' +
      'other two cryptography pages because of what it is: <a ' +
      'href="/admin/crypto-metadata">the crypto report</a> says what this ' +
      'service <em>does</em> when it signs or encrypts and reads the same on ' +
      'a service that started a second ago, and <a href="/admin/keys">the ' +
      'keys page</a> says what one realm <em>holds</em>. The numbers here go ' +
      'up while you watch.</p><p><strong>Neither a sealed value nor an ' +
      'opened one appears on this page.</strong> A sealed value is a private ' +
      'key, an authenticator&rsquo;s shared secret or somebody&rsquo;s ' +
      'recovery codes, and printing either half of one would hand over ' +
      'exactly what the sealing exists to protect. Its only controls rotate ' +
      'the data encryption keys, re-seal and count what they sealed, and ' +
      'rotate a key-encryption key that is in a key management service ' +
      '(which makes the new version itself), and they show nothing. A ' +
      'key-encryption key READ into this process is rotated by deploying ' +
      'its successor &mdash; this service reads one and never writes one ' +
      '&mdash; and a <em>decrypt this</em> button would be the one door ' +
      'onto material no door is supposed to have.</p>',
      'What this page is, and the two things it deliberately has not got');

    const keyBlock = kit.note(
      '<p>The key-encryption key is read by <code>common/secrets.js</code> ' +
      'from <strong>' + kit.esc(json.key.providerLabel) + '</strong> ' +
      '(<code>' + kit.esc(json.key.provider) + '</code>)' +
      (json.key.kmsKey ? ' &mdash; <strong>' + kit.esc(json.key.kmsKey) +
        '</strong>, which never leaves it: the service holds a handle, ' +
        'not the key, and asks it to wrap and unwrap each data key' : '') +
      ', once, at startup ' +
      'and before the listener binds. <code>file</code> is the default ' +
      'because it needs nothing: Kubernetes mounts a Secret as a file, ' +
      'Docker mounts a secret as a file, and every other provider here is ' +
      'that same idea with somebody else&rsquo;s access control in front of ' +
      'it.</p><p>' + json.key.note + '</p>' +
      '<p><strong>A key shorter than 32 bytes is REFUSED rather than ' +
      'stretched.</strong> Stretching would let a four-character password ' +
      'protect every signing key this service holds while the log said ' +
      'AES-256. Hex is tried before base64, because a 64-character hex ' +
      'string is also valid base64 and reading it that way produces 48 ' +
      'different bytes.</p><p class="muted">Available providers: ' +
      json.key.providers.map(function (one) {
        return '<code>' + kit.esc(one.id) + '</code> ' + kit.esc(one.label);
      }).join(', ') + '. <code>keys.kekProvider</code> selects one.</p>',
      'Where the key comes from');

    // **THE LIMITS, DRAWN AS A WARNING RATHER THAN A NOTE.** Everything else on
    // this page says what IS encrypted, and a reader who stops there comes away
    // believing more than is true — which is the shape of mistake this console
    // draws in amber everywhere else.
    const boundsBlock = kit.warn(
      '<p>' + kit.esc(json.boundaries.realms) + '</p>' +
      '<p>' + kit.esc(json.boundaries.storage) + '</p>' +
      '<p>' + kit.esc(json.boundaries.keyResidency) + '</p>',
      'What this key does not separate, and what this page does not cover');

    const algBlock = kit.note(
      '<p>' + json.algorithmNote + '</p>' +
      '<table class="grid"><tbody>' +
      [['Cipher', json.algorithm.cipher],
       ['Key', json.algorithm.keyBits + '-bit'],
       ['Nonce', json.algorithm.ivBits + '-bit, random per record'],
       ['Authentication tag', json.algorithm.tagBits + '-bit'],
       ['Data keys', json.algorithm.dataKeys],
       ['Data key wrapping', json.algorithm.dekWrap],
       ['Authenticated data', json.algorithm.aad],
       ['Envelope', json.algorithm.envelope]].map(function (pair) {
        return '<tr><th>' + kit.esc(pair[0]) + '</th><td><code>' +
               kit.esc(String(pair[1])) + '</code></td></tr>';
      }).join('') +
      '</tbody></table>' +
      '<p class="muted">Every figure in that table is read out of ' +
      '<code>common/crypto.js</code>&rsquo;s own <code>KEK_PARAMETERS</code> ' +
      'rather than written down here &mdash; the same rule ' +
      '<a href="/admin/crypto-metadata">the crypto report</a> follows about ' +
      'reading an algorithm table from the module that performs the ' +
      'algorithm, so this page cannot go on looking complete while being ' +
      'wrong.</p>',
      'The algorithm, and why it is authenticated');

    const countsBlock = kit.note(
      '<p>' + json.accountingNote + '</p><p>' + json.failuresNote + '</p>' +
      '<p class="muted">Since ' + self.when(json.accounting.since) +
      '. First operation ' + self.when(json.accounting.firstAt) +
      ', most recent ' + self.when(json.accounting.lastAt) + '. ' +
      kit.esc(self.bytes(json.accounting.plaintextBytes)) +
      ' of plaintext has ' +
      'passed through, producing ' +
      kit.esc(self.bytes(json.accounting.ciphertextBytes)) +
      ' of ciphertext.</p>',
      'How the counting works, and what a failure means');

    const storeBlock = kit.note(
      '<p>' + json.store.note + ' This service is on the <strong>' +
      kit.esc(json.store.mode) + '</strong> store, and what it MINTS ' +
      (json.store.persistsMinted ? 'IS' : 'is NOT') + ' persisted.</p>',
      'The store underneath all of it');

    return tiles + what +
                  '<h3>What is encrypted, and what is not</h3>' +
                  self.classesTable(json) +
                  self.unclassifiedBlock(json) +
                  '<h3>The key</h3>' + keyBlock + boundsBlock +
                  '<h3>The algorithm</h3>' + algBlock +
                  '<h3>The data encryption keys</h3>' +
                  self.renderDataKeys(ctx, json) +
                  '<h3>The counting</h3>' + countsBlock +
                  storeBlock;
  }
}

export = EncryptionPage;
