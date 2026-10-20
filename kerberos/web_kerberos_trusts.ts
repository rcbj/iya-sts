// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_kerberos_trusts.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → KERBEROS → TRUSTS, DRAWN FROM ITS VIEW ALONE (#430 Phase 4,
// 2026-10-20).
//
// Draws the Trusts tab on `/admin/kerberos` from the answer of `GET
// /admin-api/kerberos/trusts`: the realm's trust records, paged, with their
// keys described (never carried) and a health column; one record whole when
// `?trust=` names it, with the forms that change it — edit, rotate key,
// remove; and the form that adds one. Every form posts to
// `/admin/kerberos/trusts`, which the console resolves to `POST
// /admin-api/kerberos/trusts/{action}` through the operation's `mirrors`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its words are the `consoleKerberosTrusts` catalog's (#539); the health
// findings are drawn from their `kind` and `params`, the English `text` the
// API carries beside them being for a machine's reader.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

const PAGE = '/admin/kerberos/trusts';

// The catalog namespace, for the keys built from a value (a finding's kind,
// a type, a direction): the catalog test reads a literal key, so a built one
// names the namespace through this.
const NS = 'consoleKerberosTrusts.';

/**
 * Draws the Kerberos trusts from the answer of `GET
 * /admin-api/kerberos/trusts`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class KerberosTrustsPage {
  /**
   * Draws the tab's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the tab's management API operation
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    const t = ctx.t;
    const j = json || {};
    const mayChange = !!ctx.write;
    if (!j.kerberos || !j.kerberos.enabled) {
      return kit.note(t.html('consoleKerberosTrusts.intro')) +
        kit.warn(t.html('consoleKerberosTrusts.noKerberos'));
    }
    const back = kit.queryWith(kit.listViewOf(PAGE, ctx.query), {});
    const listBack = kit.queryWith(
      Object.assign({}, kit.listViewOf(PAGE, ctx.query), { trust: '' }), {})
      .replace(/([?&])trust=(&|$)/, '$1').replace(/[?&]$/, '');
    const nav = kit.pageNavPair(PAGE, kit.pageParamsOf(ctx.query),
      Object.assign({ param: 'trustsPage',
                      noun: t.html('consoleKerberosTrusts.noun'),
                      offset: 0 }, j.trustsPaging || {}), t);
    const settings = j.settings || {};
    const intro = kit.note(t.html('consoleKerberosTrusts.intro')) +
      kit.note(kit.esc(t.text('consoleKerberosTrusts.settingsNow', {
        hops: String(settings.maxReferralHops),
        grace: String(settings.graceSeconds),
        classic: settings.crossRealmClassicDelegation
          ? t.text('consoleKerberosTrusts.on')
          : t.text('consoleKerberosTrusts.off'),
        filtering: settings.requireSidFilteringInProduct
          ? t.text('consoleKerberosTrusts.on')
          : t.text('consoleKerberosTrusts.off') })) +
        ' <a href="/admin/kerberos#kerberos-tab-settings">' +
        t.html('consoleKerberosTrusts.settingsLink') + '</a>') +
      (j.product && settings.requireSidFilteringInProduct
        ? kit.note(t.html('consoleKerberosTrusts.productRule')) : '');

    const detail = j.trust
      ? KerberosTrustsPage.detail(ctx, j, j.trust, back, listBack)
      : (j.unknownTrust
        ? kit.warn(kit.esc(t.text('consoleKerberosTrusts.unknown',
                                  { partner: j.unknownTrust })))
        : '');

    const rows = (j.trusts || []).map(function (row: Json): string {
      return KerberosTrustsPage.row(ctx, row, back);
    }).join('') || '<tr><td colspan="11">' +
      t.html('consoleKerberosTrusts.none') + '</td></tr>';
    const table = '<h2>' + t.html('consoleKerberosTrusts.hList') + '</h2>' +
      nav.head +
      kit.wideTable(t.text('consoleKerberosTrusts.hList'),
        '<table id="kerberos-trusts"><tr>' +
        ['thPartner', 'thType', 'thDirection', 'thAttributes', 'thIncoming',
         'thOutgoing', 'thEnctypes', 'thEnabled', 'thLastKey', 'thHealth']
          .map(function (key: string): string {
            return '<th>' + t.html(NS + key) + '</th>';
          }).join('') + '<th></th></tr>' + rows + '</table>') +
      nav.foot +
      kit.perPageForm(PAGE, 'trustsPage', '1',
                      (j.trustsPaging || {}).perPage, undefined, undefined, t);

    const add = mayChange
      ? '<h2>' + t.html('consoleKerberosTrusts.hAdd') + '</h2>' +
        kit.note(t.html('consoleKerberosTrusts.addIntro', {
          min: String((j.form || {}).minPasswordLength || '') })) +
        KerberosTrustsPage.form(ctx, j, null, back)
      : kit.note(t.html('consoleKerberosTrusts.needWrite'));

    return intro + detail + table + add +
      kit.note('<a href="/admin-api/kerberos/trusts">' +
               t.html('consoleKerberosTrusts.linkApi') + '</a>');
  }

  // One key side's cell: held, kvno and source, when set, and — for the
  // incoming side — the previous version a rotation keeps and until when.
  private static keyCell(t: Json, side: Json): string {
    if (!side || !side.held) {
      return '<span class="sub">' + t.html('consoleKerberosTrusts.notHeld') +
        '</span>';
    }
    return 'kvno ' + kit.esc(String(side.kvno)) + ' <span class="sub">' +
      kit.esc(side.source === 'password'
        ? t.text('consoleKerberosTrusts.fromPassword')
        : t.text('consoleKerberosTrusts.generated')) + '</span>' +
      (side.previous
        ? '<br><span class="sub">' + kit.esc(t.text(
            'consoleKerberosTrusts.previous', {
              kvno: String(side.previous.kvno),
              until: String(side.previous.acceptedUntil) })) + '</span>'
        : '');
  }

  private static healthCell(t: Json, findings: Json[]): string {
    return (findings || []).map(function (one: Json): string {
      const cls = one.level === 'ok' ? 'state-valid' :
        (one.level === 'bad' ? 'state-invalid' : 'sub');
      return '<div class="' + cls + '">' + kit.esc(t.text(
        NS + 'health.' + one.kind, one.params || {})) +
        '</div>';
    }).join('');
  }

  private static button(action: string, partner: string, label: string,
                        back: string, extra?: string,
                        cls?: string): string {
    return '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
      '<input type="hidden" name="partnerRealm" value="' +
      kit.esc(partner) + '">' + (extra || '') +
      '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
      '<button type="submit" class="' + (cls || 'secondary') + '">' +
      kit.esc(label) + '</button></form>';
  }

  private static row(ctx: Json, row: Json, back: string): string {
    const t = ctx.t;
    const link = function (anchor: string): string {
      return PAGE + kit.queryWith(kit.listViewOf(PAGE, ctx.query),
                                  { trust: row.partnerRealm }) + anchor;
    };
    const actions = ctx.write
      ? '<a href="' + kit.esc(link('#trust-edit')) + '">' +
        t.html('consoleKerberosTrusts.edit') + '</a> ' +
        KerberosTrustsPage.button(row.enabled ? 'disable' : 'enable',
          row.partnerRealm, row.enabled
            ? t.text('consoleKerberosTrusts.disable')
            : t.text('consoleKerberosTrusts.enable'), back) +
        '<a href="' + kit.esc(link('#trust-rotate')) + '">' +
        t.html('consoleKerberosTrusts.rotate') + '</a> ' +
        (row.type === 'trust-realm'
          ? KerberosTrustsPage.button('pair', row.partnerRealm,
              t.text('consoleKerberosTrusts.pair'), back)
          : '') +
        '<a href="' + kit.esc(link('#trust-remove')) + '">' +
        t.html('consoleKerberosTrusts.remove') + '</a>'
      : '<a href="' + kit.esc(link('')) + '">' +
        t.html('consoleKerberosTrusts.details') + '</a>';
    return '<tr><td><a href="' + kit.esc(link('')) + '"><code>' +
      kit.esc(row.partnerRealm) + '</code></a><br><span class="sub">' +
      kit.esc(row.netbiosName || '') + (row.partnerSid ? ' · ' +
        kit.esc(row.partnerSid) : '') + '</span></td>' +
      '<td>' + kit.esc(t.text(NS + 'type.' + row.type)) +
      (row.partnerTrustRealm ? '<br><span class="sub">' +
        kit.esc(row.partnerTrustRealm) + '</span>' : '') + '</td>' +
      '<td>' + kit.esc(t.text(NS + 'direction.' +
                              row.direction)) + '</td>' +
      '<td>' + ((row.attributes || []).length
        ? kit.codeList(row.attributes)
        : '<span class="sub">' + t.html('consoleKerberosTrusts.noBits') +
          '</span>') + '<br><span class="sub">' +
        kit.esc(String(row.boundary || '')) + '</span></td>' +
      '<td>' + KerberosTrustsPage.keyCell(t, row.incoming) + '</td>' +
      '<td>' + KerberosTrustsPage.keyCell(t, row.outgoing) + '</td>' +
      '<td>' + kit.codeList((row.enctypeNames || []).map(function (e: Json):
        string {
        return e.name;
      })) + '</td>' +
      '<td>' + (row.enabled ? t.html('consoleKerberosTrusts.yes')
        : '<span class="state-invalid">' +
          t.html('consoleKerberosTrusts.no') + '</span>') + '</td>' +
      '<td class="sub">' + kit.esc(row.lastKeyChangeAt || '—') + '</td>' +
      '<td>' + KerberosTrustsPage.healthCell(t, row.health) + '</td>' +
      '<td>' + actions + '</td></tr>';
  }

  // ONE RECORD WHOLE (`?trust=`), with the three forms that need more than a
  // button: edit, rotate key, remove.
  private static detail(ctx: Json, j: Json, r: Json, back: string,
                        listBack: string): string {
    const t = ctx.t;
    const ft = r.forestTrustInfo;
    const facts = '<table class="key">' + [
      ['thPartner', '<code>' + kit.esc(r.partnerRealm) + '</code>'],
      ['thNetbios', kit.esc(r.netbiosName || '')],
      ['thSid', kit.esc(r.partnerSid || '—')],
      ['thType', kit.esc(t.text(NS + 'type.' + r.type)) +
        (r.partnerTrustRealm ? ' <code>' + kit.esc(r.partnerTrustRealm) +
         '</code>' : '')],
      ['thDirection', kit.esc(t.text(NS + 'direction.' +
                                     r.direction))],
      ['thAttributes', kit.codeList(r.attributes || []) + ' <span ' +
        'class="sub">trustAttributes 0x' +
        kit.esc(Number(r.trustAttributes || 0).toString(16)) + ', ' +
        kit.esc(String(r.boundary || '')) + '</span>'],
      ['thSuffixes', kit.codeList(r.suffixes || [])],
      ['thIncoming', '<code>' + kit.esc(r.incoming.principal) + '</code> ' +
        KerberosTrustsPage.keyCell(t, r.incoming)],
      ['thOutgoing', '<code>' + kit.esc(r.outgoing.principal) + '</code> ' +
        KerberosTrustsPage.keyCell(t, r.outgoing)],
      ['thEnctypes', kit.codeList((r.enctypeNames || [])
        .map(function (e: Json): string {
          return e.name;
        }))],
      ['thClaims', '<code>' + kit.esc(r.claimsTransformation) + '</code>'],
      ['thForest', ft ? kit.esc(t.text('consoleKerberosTrusts.forestCount',
        { domains: String((ft.domains || []).length),
          names: String((ft.topLevelNames || []).length) })) : '—'],
      ['thHealth', KerberosTrustsPage.healthCell(t, r.health)]
    ].map(function (pair: string[]): string {
      return '<tr><th>' + t.html(NS + pair[0]) +
        '</th><td>' + pair[1] + '</td></tr>';
    }).join('') + '</table>';
    const write = !!ctx.write;
    const edit = write
      ? '<h3 id="trust-edit">' + t.html('consoleKerberosTrusts.hEdit') +
        '</h3>' + KerberosTrustsPage.form(ctx, j, r, back)
      : '';
    const sourceSelect = function (id: string): string {
      return '<div class="formrow"><label for="' + id + '-source">' +
        t.html('consoleKerberosTrusts.keySource') + '</label>' +
        '<select id="' + id + '-source" name="keySource">' +
        '<option value="generate">' +
        t.html('consoleKerberosTrusts.sourceGenerate') + '</option>' +
        '<option value="password">' +
        t.html('consoleKerberosTrusts.sourcePassword') + '</option>' +
        '</select></div><div class="formrow"><label for="' + id +
        '-password">' + t.html('consoleKerberosTrusts.password') +
        '</label><input type="password" id="' + id + '-password" ' +
        'name="password" autocomplete="new-password" size="32"></div>';
    };
    const rotate = write
      ? '<h3 id="trust-rotate">' + t.html('consoleKerberosTrusts.hRotate') +
        '</h3>' + kit.note(kit.esc(t.text('consoleKerberosTrusts.rotateIntro',
          { grace: String((j.settings || {}).graceSeconds) }))) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="rotate-key">' +
        '<input type="hidden" name="partnerRealm" value="' +
        kit.esc(r.partnerRealm) + '">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<div class="formrow"><label for="trust-rotate-side">' +
        t.html('consoleKerberosTrusts.side') + '</label>' +
        '<select id="trust-rotate-side" name="side">' +
        ['both', 'incoming', 'outgoing'].map(function (one: string): string {
          return '<option value="' + one + '">' +
            t.html(NS + 'side.' + one) + '</option>';
        }).join('') + '</select></div>' + sourceSelect('trust-rotate') +
        (r.type === 'trust-realm'
          ? '<div class="formrow"><label><input type="checkbox" ' +
            'name="mirror" value="true"> ' +
            t.html('consoleKerberosTrusts.mirror') + '</label></div>'
          : '') +
        '<button type="submit">' + t.html('consoleKerberosTrusts.rotate') +
        '</button></form>'
      : '';
    const remove = write
      ? '<h3 id="trust-remove">' + t.html('consoleKerberosTrusts.hRemove') +
        '</h3>' + kit.warn(t.html('consoleKerberosTrusts.removeIntro')) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="partnerRealm" value="' +
        kit.esc(r.partnerRealm) + '">' +
        '<input type="hidden" name="back" value="' + kit.esc(listBack) +
        '"><div class="formrow"><label for="trust-remove-confirm">' +
        kit.esc(t.text('consoleKerberosTrusts.typeConfirm',
                       { partner: r.partnerRealm })) + '</label>' +
        '<input type="text" id="trust-remove-confirm" name="confirm" ' +
        'size="24" autocomplete="off"><button type="submit" ' +
        'class="danger">' + t.html('consoleKerberosTrusts.remove') +
        '</button></div></form>'
      : '';
    return '<h2 id="trust-detail">' + kit.esc(t.text(
      'consoleKerberosTrusts.hDetail', { partner: r.partnerRealm })) +
      '</h2>' + facts + edit + rotate + remove +
      kit.note('<a href="' + kit.esc(PAGE + listBack) + '">' +
               t.html('consoleKerberosTrusts.backToList') + '</a>');
  }

  // THE ADD AND EDIT FORM. On an edit the partner realm is fixed (every key
  // is salted with it), a key already held is kept — Rotate key changes it
  // — and the key source is asked only for a side the direction adds.
  private static form(ctx: Json, j: Json, r: Json | null,
                      back: string): string {
    const t = ctx.t;
    const f = j.form || {};
    const id = r ? 'trust-edit' : 'trust-add';
    const attrs = r ? (r.attributes || []) : (f.defaultAttributes || []);
    const enctypes = r ? (r.enctypes || []) : (f.defaultEnctypes || []);
    const ft = r && r.forestTrustInfo ? r.forestTrustInfo : null;
    const row = function (label: string, field: string): string {
      return '<div class="formrow"><label for="' + id + '-' + label + '">' +
        t.html(NS + label) + '</label>' + field +
        '</div>';
    };
    const text = function (name: string, value: string,
                           placeholder?: string): string {
      return '<input type="text" id="' + id + '-' + name + '" name="' +
        name + '" size="32" value="' + kit.esc(value || '') + '"' +
        (placeholder ? ' placeholder="' + kit.esc(placeholder) + '"' : '') +
        '>';
    };
    const select = function (name: string, values: string[],
                             chosen: string, prefix: string): string {
      return '<select id="' + id + '-' + name + '" name="' + name + '">' +
        values.map(function (one: string): string {
          return '<option value="' + kit.esc(one) + '"' +
            (one === chosen ? ' selected' : '') + '>' +
            kit.esc(prefix ? t.text(prefix + one) : one) + '</option>';
        }).join('') + '</select>';
    };
    const boxes = (f.attributes || []).map(function (name: string): string {
      return '<label class="check"><input type="checkbox" name="attribute" ' +
        'value="' + kit.esc(name) + '"' +
        (attrs.indexOf(name) >= 0 ? ' checked' : '') + '> <code>' +
        kit.esc(name) + '</code></label>';
    }).join(' ');
    const rules = (f.requires || []).map(function (one: Json): string {
      return kit.esc(t.text('consoleKerberosTrusts.ruleNeeds',
        { attribute: one.attribute, needs: one.needs }));
    }).concat((f.contradictions || []).map(function (one: Json): string {
      return kit.esc(t.text('consoleKerberosTrusts.ruleNotBoth',
        { a: one.a, b: one.b }));
    })).join('<br>');
    const encBoxes = (f.enctypes || []).map(function (e: Json): string {
      return '<label class="check"><input type="checkbox" name="enctype" ' +
        'value="' + kit.esc(String(e.id)) + '"' +
        (enctypes.indexOf(e.id) >= 0 ? ' checked' : '') + '> <code>' +
        kit.esc(e.name) + '</code></label>';
    }).join(' ');
    const realmOptions = ['<option value="">—</option>'].concat(
      (f.trustRealms || []).map(function (one: Json): string {
        return '<option value="' + kit.esc(one.id) + '"' +
          (r && r.partnerTrustRealm === one.id ? ' selected' : '') + '>' +
          kit.esc(one.id + ' (' + one.kerberosRealm + ')') + '</option>';
      })).join('');
    const forestDomains = ft ? (ft.domains || []).map(function (d: Json):
      string {
      return [d.sid, d.dnsName, d.netbiosName].concat(
        d.sidEnabled === false ? ['disabled'] : []).join(' ');
    }).join('\n') : '';
    const forestNames = ft ? (ft.topLevelNames || []).map(function (n: Json):
      string {
      return n.name + (n.enabled === false ? ' disabled' : '');
    }).join('\n') : '';
    // The forest trust information belongs to a cross-forest trust: drawn
    // open on an edit of one, folded on the add form, left out otherwise.
    const crossForest = r ? attrs.indexOf('forest-transitive') >= 0 : true;
    const forest = crossForest
      ? '<details' + (r ? ' open' : '') + '><summary>' +
        t.html('consoleKerberosTrusts.hForest') + '</summary>' +
        kit.note(t.html('consoleKerberosTrusts.forestIntro')) +
        row('forestDomains', '<textarea id="' + id + '-forestDomains" ' +
          'name="forestDomains" rows="3" cols="60" placeholder="' +
          'S-1-5-21-1-2-3 child.partner.example CHILD">' +
          kit.esc(forestDomains) + '</textarea>') +
        row('forestNames', '<textarea id="' + id + '-forestNames" ' +
          'name="forestNames" rows="2" cols="60" placeholder="' +
          'partner.example">' + kit.esc(forestNames) + '</textarea>') +
        '</details>'
      : '';
    return '<form method="post" action="' + PAGE + '" id="' + id +
      '-form">' +
      '<input type="hidden" name="action" value="' + (r ? 'update' : 'add') +
      '"><input type="hidden" name="back" value="' + kit.esc(back) + '">' +
      '<input type="hidden" name="attributesShown" value="1">' +
      (r ? '<input type="hidden" name="partnerRealm" value="' +
             kit.esc(r.partnerRealm) + '">'
         : row('partnerRealm', text('partnerRealm', '', 'PARTNER.EXAMPLE'))) +
      row('netbiosName', text('netbiosName', r ? r.netbiosName : '',
                              'PARTNER')) +
      row('partnerSid', text('partnerSid', r ? r.partnerSid : '',
                             'S-1-5-21-1-2-3')) +
      row('type', select('type', f.types || [], r ? r.type : 'external',
                         'consoleKerberosTrusts.type.')) +
      row('partnerTrustRealm', '<select id="' + id + '-partnerTrustRealm" ' +
        'name="partnerTrustRealm">' + realmOptions + '</select>') +
      row('direction', select('direction', f.directions || [],
        r ? r.direction : 'bidirectional',
        'consoleKerberosTrusts.direction.')) +
      row('keySource', select('keySource', f.keySources || [],
        'generate', 'consoleKerberosTrusts.source.')) +
      row('password', '<input type="password" id="' + id + '-password" ' +
        'name="password" autocomplete="new-password" size="32">') +
      kit.note(t.html(r ? 'consoleKerberosTrusts.keysKept'
                        : 'consoleKerberosTrusts.keysOnce')) +
      '<fieldset><legend>' + t.html('consoleKerberosTrusts.thAttributes') +
      '</legend>' + boxes + '<p class="sub">' + rules + '</p></fieldset>' +
      row('suffixes', text('suffixes', r ? (r.suffixes || []).join(', ') :
                           '', 'partner.example')) +
      '<fieldset><legend>' + t.html('consoleKerberosTrusts.thEnctypes') +
      '</legend>' + encBoxes + '</fieldset>' +
      row('claimsTransformation', select('claimsTransformation',
        f.claimsTransformations || [],
        r ? r.claimsTransformation : 'drop-all', '')) +
      forest +
      '<button type="submit">' + t.html(r ? 'consoleKerberosTrusts.save'
                                          : 'consoleKerberosTrusts.add') +
      '</button></form>';
  }
}

export = KerberosTrustsPage;
