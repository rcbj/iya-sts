// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_upload_pairs.js
//
// ===========================================================================
// MONITORING → RISK OFFERS ONLY THE DATASET AND FORMAT PAIRS THAT GO
// TOGETHER (#219), in process.
//
// rcbj: "the mismatched pairs are refused at the server. But, it is not
// obvious in the UI what the valid combinations are." The two forms had a
// dataset drop-down beside a format drop-down, every one beside every other.
// What is held here:
//
//   A. THE DROP-DOWN (`web_risk.ts`'s `pairSelect()`): one select named
//      `dataset|format`, a group per dataset, and EXACTLY the pairs
//      `risk_datasets.ts`'s CATALOGUE says a dataset is read from — none
//      more, none fewer.
//   B. THE GUIDE (`pairGuide()`): every pair, with what its file looks like.
//   C. THE RUNTIME (`ConsoleRuntime.splitJoinedFields()`): a joined field is
//      sent as the two fields the operation takes, and every other field is
//      left as it was.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'risk_upload_pairs',
  level: process.env.LOG_LEVEL || 'info' });

function catalogueView() {
  log.debug('Entering catalogueView().');
  const datasets = require('../risk/risk_datasets');
  const Cls = datasets.RiskDatasets || datasets;
  const view = {
    datasets: Object.keys(Cls.CATALOGUE).map(function (id) {
      const entry = Cls.CATALOGUE[id];
      return { dataset: id, title: entry.title, formats: entry.formats,
               perRealm: !!entry.perRealm };
    }),
    formats: Object.keys(Cls.FORMATS).map(function (id) {
      return Object.assign({ format: id }, Cls.FORMATS[id]);
    })
  };
  log.debug('Leaving catalogueView().');
  return { view: view, catalogue: Cls.CATALOGUE };
}

function optionValues(html) {
  log.debug('Entering optionValues().');
  const out = [];
  const re = /<option value="([^"]*)"/g;
  let m = re.exec(html);
  while (m) {
    out.push(m[1].replace(/&#124;|&vert;/g, '|'));
    m = re.exec(html);
  }
  log.debug('Leaving optionValues(). ' + out.length);
  return out;
}

module.exports = {
  name: 'risk upload pairs',
  describe: 'Monitoring → Risk offers only the dataset and format pairs ' +
            'that go together (#219): one drop-down, a guide, and the ' +
            'runtime that sends a joined field as its two fields',
  run: async function (t) {
    log.debug('Entering run().');
    const RiskPage = require('../admin-ui/web_risk');
    const ConsoleRuntime = require('../admin-ui/web_runtime');
    const { view, catalogue } = catalogueView();

    const select = RiskPage.pairSelect(view, 'risk-upload-pair');
    t.check(/name="dataset\|format"/.test(select) &&
            !/name="format"/.test(select) && !/name="dataset"/.test(select),
            'A1. one select, named dataset|format, and no separate pair');
    const offered = optionValues(select).sort();
    const valid = [];
    Object.keys(catalogue).forEach(function (id) {
      catalogue[id].formats.forEach(function (format) {
        valid.push(id + '|' + format);
      });
    });
    valid.sort();
    t.equal(JSON.stringify(offered), JSON.stringify(valid),
            'A2. it offers exactly the pairs the catalogue reads, no more');
    t.check((select.match(/<optgroup /g) || []).length ===
            Object.keys(catalogue).length,
            'A3. a group per dataset');

    const guide = RiskPage.pairGuide(view);
    t.check(valid.every(function (pair) {
      const parts = pair.split('|');
      return guide.indexOf('<code>' + parts[0] + '</code>') >= 0 &&
             guide.indexOf('<code>' + parts[1] + '</code>') >= 0;
    }), 'B1. the guide names every dataset and every format it takes');

    const data = new FormData();
    data.append('action', 'import');
    data.append('dataset|format', 'geo.country|ipinfo-lite-csv');
    data.append('version', 'v1');
    ConsoleRuntime.splitJoinedFields(data);
    const fields = ConsoleRuntime.fieldsOf(data);
    t.check(fields.dataset === 'geo.country' &&
            fields.format === 'ipinfo-lite-csv' &&
            fields['dataset|format'] === undefined &&
            fields.version === 'v1' && fields.action === 'import',
            'C1. a joined field is sent as its two fields, the rest as ' +
            'they were', JSON.stringify(fields));
    const short = new FormData();
    short.append('dataset|format', 'geo.city');
    ConsoleRuntime.splitJoinedFields(short);
    const half = ConsoleRuntime.fieldsOf(short);
    t.check(half.dataset === 'geo.city' && half.format === '',
            'C2. a value with too few parts leaves the rest empty, for the ' +
            'operation to refuse', JSON.stringify(half));
    log.debug('Leaving run().');
  }
};
