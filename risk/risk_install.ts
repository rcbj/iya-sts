'use strict';
//
// File: risk/risk_install.ts
//
// ===========================================================================
// PULL THE RISK DATASETS INTO THE DATABASE AT INSTALL TIME (#62 P1,
// 2026-09-22, the independent licence review's recommendation).
//
//   node risk/risk_install.js --manifest datasets.json \
//        --accept-terms dbip-lite,tor-project [--operator "Jo Bloggs"] \
//        [--terms-log ./risk-terms-acceptance.log] [--check-terms] \
//        [--dry-run]
//
// with `STS_DATABASE_URL` naming the deployment's database. It is an
// OPERATOR'S TOOL, run by whoever installs a deployment — from a shell, an
// init container, a deploy pipeline — and NOT a part of the running service.
// That is the whole point of it:
//
//   * **iya-sts DISTRIBUTES NO THIRD-PARTY DATASET.** Its repository, its
//     images and its tests carry none. A deployment obtains each dataset
//     itself, under its provider's terms, and this is how it does so.
//   * **THE OPERATOR ACCEPTS EACH PROVIDER'S TERMS BY NAME.** A dataset from a
//     provider not named in `--accept-terms` is refused, with that provider's
//     terms printed — IPinfo's ShareAlike, FireHOL's constituent lists, the
//     Tor Project's list — so nobody pulls data they have not agreed to hold.
//   * **AND THE ACCEPTANCE IS RECORDED** (the second licence review on #62):
//     each provider named is accepted in `--operator`'s name (the OS user
//     and host by default) through `risk_terms.ts` — a row in
//     `sts_risk_terms_acceptances` with the terms text and its digest — and
//     appended as a JSON line to `--terms-log` on the machine that ran this,
//     BEFORE anything is imported. `--check-terms` also fetches each named
//     provider's own terms page and records its digest, and warns
//     (STS-RISK-0015) when it differs from the page seen at the previous
//     acceptance: terms that change after an installation are then noticed
//     at the next one.
//   * **THE RUNNING SERVICE STILL DIALS NOBODY.** The downloads happen here,
//     in this process, before or beside the service; the service reads the
//     rows this writes. The root `CLAUDE.md`'s table of the addresses the
//     service dials is therefore unchanged.
//
// The manifest is JSON: `{ "datasets": [ { "dataset", "format", and either
// "url" (https only; `.gz` is gunzipped) or "file", with optional "version",
// "publishedAt", "sha256", "provider", "realm" } ] }`. Each is imported
// exactly as the console and the dataset directory import one —
// `risk_datasets.ts`'s `importVersion()`: verified against its SHA-256 where
// one is named, refused if it shrank past the limit, recorded whatever
// happens, and activated when it loaded. A version already recorded is not
// loaded again, so running this twice is safe.
//
// **ONLY THE SERVICE'S OWN DATASETS AND THE DEFAULT REALM'S LISTS.** A list
// for another realm is imported through Monitoring → Risk or the API, where
// the realm is known to exist.
// ===========================================================================

import bunyan = require('bunyan');
import fs = require('fs');
import os = require('os');
import path = require('path');
import https = require('https');
import zlib = require('zlib');
import errorCodes = require('../common/error_codes');
import riskStore = require('./risk_store');
import riskDatasets = require('./risk_datasets');
import riskTerms = require('./risk_terms');
import stsCrypto = require('../common/crypto');

const log = bunyan.createLogger({ name: 'sts-risk-install',
                                  level: process.env.STS_LOG_LEVEL || 'info' });

type Json = any;

// The largest download accepted: a full DB-IP city release is a few hundred
// megabytes uncompressed. A bound, not a tunable.
const MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_REDIRECTS = 3;

interface Options {
  manifest: string;
  accepted: string[];
  dryRun: boolean;
  operator?: string;
  termsLog?: string;
  checkTerms?: boolean;
}

// Where the acceptance log goes when --terms-log names nothing: the
// directory the loader was run from, which is the installation's, never the
// source tree's (an image's is read-only, and a log is not source).
const DEFAULT_TERMS_LOG = 'risk-terms-acceptance.log';
// The most of a terms page read for its digest.
const MAX_TERMS_PAGE_BYTES = 2 * 1024 * 1024;

class RiskInstall {
  // The command line, or null with the reason printed.
  static optionsOf(argv: string[]): Options | null {
    log.debug("Entering RiskInstall.optionsOf().");
    const out: Options = { manifest: '', accepted: [], dryRun: false,
                           operator: '', termsLog: DEFAULT_TERMS_LOG,
                           checkTerms: false };
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--manifest') {
        out.manifest = String(argv[++i] || '');
      } else if (arg === '--accept-terms') {
        out.accepted = String(argv[++i] || '').split(',').map(function (id) {
          return id.trim();
        }).filter(Boolean);
      } else if (arg === '--dry-run') {
        out.dryRun = true;
      } else if (arg === '--operator') {
        out.operator = String(argv[++i] || '');
      } else if (arg === '--terms-log') {
        out.termsLog = String(argv[++i] || '');
      } else if (arg === '--check-terms') {
        out.checkTerms = true;
      } else {
        process.stderr.write('risk_install: unknown argument ' + arg + '\n');
        log.debug("Leaving RiskInstall.optionsOf(). Unknown argument.");
        return null;
      }
    }
    if (!out.manifest) {
      process.stderr.write('usage: node risk/risk_install.js --manifest ' +
                           '<datasets.json> --accept-terms <provider,...> ' +
                           '[--operator <name>] [--terms-log <file>] ' +
                           '[--check-terms] [--dry-run]\n');
      log.debug("Leaving RiskInstall.optionsOf(). No manifest.");
      return null;
    }
    log.debug("Leaving RiskInstall.optionsOf().");
    return out;
  }

  // Which provider an entry's data comes from: what it names, its
  // dataset's, or its format's — the importer's own rule.
  static providerOf(entry: Json): string {
    log.debug("Entering RiskInstall.providerOf().");
    const dataset = riskDatasets.CATALOGUE[entry.dataset] || {};
    const format = riskDatasets.FORMATS[entry.format] || {};
    log.debug("Leaving RiskInstall.providerOf().");
    return String(entry.provider || dataset.provider || format.provider || '');
  }

  // -------------------------------------------------------------------------
  // ONE DOWNLOAD, over HTTPS only, to a file of its own. A redirect is
  // followed only to another https address, at most MAX_REDIRECTS times; a
  // `.gz` address is gunzipped as it arrives. Rejects with the reason.
  // -------------------------------------------------------------------------
  static download(url: string, target: string, hops?: number): Promise<void> {
    log.debug("Entering RiskInstall.download(). " + url);
    const left = hops === undefined ? MAX_REDIRECTS : hops;
    log.debug("Leaving RiskInstall.download().");
    return new Promise(function (resolve, reject) {
      if (!/^https:\/\//i.test(url)) {
        reject(new Error('only https addresses are fetched, not ' + url));
        return;
      }
      https.get(url, function (res) {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          if (left <= 0) {
            reject(new Error('too many redirects from ' + url));
            return;
          }
          const next = new URL(String(res.headers.location), url).toString();
          RiskInstall.download(next, target, left - 1).then(resolve, reject);
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(new Error(url + ' answered ' + status));
          return;
        }
        let received = 0;
        res.on('data', function (chunk) {
          received += chunk.length;
          if (received > MAX_DOWNLOAD_BYTES) {
            res.destroy(new Error(url + ' is larger than ' +
                                  MAX_DOWNLOAD_BYTES + ' bytes'));
          }
        });
        const gz = /\.gz(\?|$)/i.test(url) ||
          /gzip/i.test(String(res.headers['content-type'] || ''));
        const out = fs.createWriteStream(target);
        const source = gz ? res.pipe(zlib.createGunzip()) : res;
        source.on('error', reject);
        res.on('error', reject);
        out.on('error', reject);
        out.on('finish', function () {
          resolve();
        });
        source.pipe(out);
      }).on('error', reject);
    });
  }

  // A page's text over HTTPS, for its digest: one redirect at most, bounded.
  static fetchText(url: string, hops?: number): Promise<string> {
    log.debug("Entering RiskInstall.fetchText(). " + url);
    const left = hops === undefined ? 1 : hops;
    log.debug("Leaving RiskInstall.fetchText().");
    return new Promise(function (resolve, reject) {
      if (!/^https:\/\//i.test(url)) {
        reject(new Error('only https addresses are fetched, not ' + url));
        return;
      }
      https.get(url, function (res) {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location &&
            left > 0) {
          res.resume();
          RiskInstall.fetchText(new URL(String(res.headers.location), url)
            .toString(), left - 1).then(resolve, reject);
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(new Error(url + ' answered ' + status));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', function (chunk: Buffer) {
          size += chunk.length;
          if (size <= MAX_TERMS_PAGE_BYTES) {
            chunks.push(chunk);
          }
        });
        res.on('end', function () {
          resolve(Buffer.concat(chunks).toString('utf8'));
        });
        res.on('error', reject);
      }).on('error', reject);
    });
  }

  // -------------------------------------------------------------------------
  // THE ACCEPTANCES: each provider named in --accept-terms accepted in the
  // operator's name, recorded through `risk_terms.ts` and appended to the
  // terms log, before anything is imported. With --check-terms each
  // provider's own terms page is fetched and its digest recorded beside the
  // acceptance, with a warning when it differs from the last one seen.
  // Answers how many could not be recorded.
  // -------------------------------------------------------------------------
  static async acceptNamed(options: Options): Promise<number> {
    log.debug("Entering RiskInstall.acceptNamed().");
    const operator = options.operator ||
      (os.userInfo().username + '@' + os.hostname());
    let failed = 0;
    for (const providerId of options.accepted) {
      if (!riskTerms.needsAcceptance(providerId)) {
        continue;
      }
      const provider = riskTerms.PROVIDERS[providerId];
      let pageDigest = '';
      if (options.checkTerms && provider.termsUrl) {
        try {
          pageDigest = stsCrypto.truncatedSha256Hex(
            await RiskInstall.fetchText(provider.termsUrl), 64);
          const earlier = (await riskTerms.status()).acceptances
            .filter(function (a: Json): boolean {
              return a.provider === providerId && a.pageDigest;
            })[0];
          if (earlier && earlier.pageDigest !== pageDigest) {
            process.stderr.write(errorCodes.tag('STS-RISK-0015') +
              'risk_install: ' + provider.title + '\'s terms page (' +
              provider.termsUrl + ') has changed since it was last ' +
              'accepted (' + new Date(earlier.acceptedAt).toISOString() +
              ' by ' + earlier.acceptedBy + '). Read it before relying on ' +
              'this acceptance.\n');
          }
        } catch (e) {
          process.stderr.write('risk_install: ' + provider.title + '\'s ' +
            'terms page could not be fetched (' + ((e && e.message) || e) +
            '); the acceptance is recorded without its digest.\n');
          pageDigest = '';
        }
      }
      if (options.dryRun) {
        process.stdout.write('risk_install: would record ' + operator +
                             '\'s acceptance of ' + provider.title +
                             '\'s terms.\n');
        continue;
      }
      const accepted = await riskTerms.accept({
        provider: providerId, acceptedBy: operator,
        via: 'the install-time loader', pageDigest: pageDigest });
      if (!accepted.ok) {
        failed += 1;
        continue;
      }
      try {
        fs.appendFileSync(options.termsLog || DEFAULT_TERMS_LOG,
          JSON.stringify({
            at: new Date(accepted.acceptance.acceptedAt).toISOString(),
            provider: providerId, acceptedBy: operator,
            deployment: accepted.acceptance.deployment,
            termsDigest: accepted.acceptance.termsDigest,
            pageDigest: pageDigest, terms: accepted.acceptance.termsText
          }) + '\n');
      } catch (e) {
        process.stderr.write('risk_install: the terms log ' +
          (options.termsLog || DEFAULT_TERMS_LOG) + ' could not be written (' +
          ((e && e.message) || e) + '); the acceptance is recorded in the ' +
          'database.\n');
      }
      process.stdout.write('risk_install: ' + operator + ' accepted the ' +
                           'terms of ' + provider.title + '.\n');
    }
    log.debug("Leaving RiskInstall.acceptNamed(). " + failed + " failed.");
    return failed;
  }

  // -------------------------------------------------------------------------
  // THE RUN: each manifest entry checked against the accepted terms,
  // fetched or read, and imported into the database. Answers the number of
  // entries that failed.
  // -------------------------------------------------------------------------
  static async run(options: Options): Promise<number> {
    log.debug("Entering RiskInstall.run().");
    const manifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
    const entries = Array.isArray(manifest.datasets) ? manifest.datasets : [];
    const url = String(process.env.STS_DATABASE_URL || '');
    if (!url) {
      process.stderr.write(errorCodes.tag('STS-RISK-0012') + 'risk_install: ' +
        'STS_DATABASE_URL is not set; the datasets are pulled into the ' +
        'deployment\'s database, and this names it.\n');
      log.debug("Leaving RiskInstall.run(). No database.");
      return entries.length || 1;
    }
    const driver = require('../persistence/persistence_postgres')
      .create({ url: url, log: log });
    if (!options.dryRun) {
      await driver.open();
      riskStore.setDriver(driver, 'postgres');
    }
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-risk-install-'));
    let failed = await RiskInstall.acceptNamed(options);
    try {
      for (const entry of entries) {
        const failedOne = await RiskInstall.one(entry, options, work);
        failed += failedOne ? 1 : 0;
      }
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
      if (!options.dryRun && typeof driver.close === 'function') {
        await driver.close();
      }
    }
    log.debug("Leaving RiskInstall.run(). " + failed + " failed.");
    return failed;
  }

  // One entry: true when it failed.
  private static async one(entry: Json, options: Options,
                           work: string): Promise<boolean> {
    log.debug("Entering RiskInstall.one(). " + entry.dataset);
    const providerId = RiskInstall.providerOf(entry);
    const provider = riskDatasets.PROVIDERS[providerId];
    const say = function (text: string): void {
      log.debug("Entering say().");
      process.stdout.write('risk_install: ' + entry.dataset + ': ' + text +
                           '\n');
      log.debug("Leaving say().");
    };
    const realm = String(entry.realm || '');
    if (realm && realm !== 'default') {
      say('a list for realm "' + realm + '" is imported through Monitoring ' +
          '→ Risk or the API, where the realm is known to exist; skipped.');
      log.debug("Leaving RiskInstall.one(). Another realm.");
      return true;
    }
    if (!provider) {
      say('no provider "' + providerId + '" is known; skipped.');
      log.debug("Leaving RiskInstall.one(). Unknown provider.");
      return true;
    }
    if (options.accepted.indexOf(providerId) < 0) {
      process.stderr.write(errorCodes.tag('STS-RISK-0012') + 'risk_install: ' +
        entry.dataset + ' is ' + provider.title + '\'s data, and its terms ' +
        'were not accepted (--accept-terms ' + providerId + '). ' +
        provider.terms + (provider.url ? ' ' + provider.url : '') + '\n');
      log.debug("Leaving RiskInstall.one(). Terms not accepted.");
      return true;
    }
    if (options.dryRun) {
      say('would import ' + (entry.url || entry.file) + ' as ' +
          entry.format + ' under ' + provider.title + '\'s terms.');
      log.debug("Leaving RiskInstall.one(). Dry run.");
      return false;
    }
    let file = entry.file ? String(entry.file) : '';
    try {
      if (!file && entry.url) {
        file = path.join(work, String(entry.dataset).replace(/[^\w.-]/g, '_'));
        say('downloading ' + entry.url);
        await RiskInstall.download(String(entry.url), file);
      }
    } catch (e) {
      process.stderr.write(errorCodes.tag('STS-RISK-0012') + 'risk_install: ' +
        entry.dataset + ' could not be fetched: ' +
        ((e && e.message) || e) + '\n');
      log.debug("Leaving RiskInstall.one(). Download failed.");
      return true;
    }
    const result = await riskDatasets.importVersion({
      dataset: entry.dataset, format: entry.format, path: file,
      realm: realm,
      version: entry.version,
      publishedAt: entry.publishedAt
        ? Date.parse(entry.publishedAt) || Number(entry.publishedAt) : 0,
      provider: providerId, sha256: entry.sha256,
      source: 'install', sourceUri: String(entry.url || entry.file || ''),
      actor: 'the install-time loader' });
    say(result.ok ? String(result.message)
                  : 'REFUSED: ' + (result.errors || []).join(' '));
    log.debug("Leaving RiskInstall.one().");
    return !result.ok;
  }
}

// Run when invoked, and export the class for the tests.
if (require.main === module) {
  const options = RiskInstall.optionsOf(process.argv.slice(2));
  if (!options) {
    process.exit(2);
  }
  RiskInstall.run(options).then(function (failed: number): void {
    process.exit(failed ? 1 : 0);
  }, function (e: Json): void {
    process.stderr.write(errorCodes.tag('STS-RISK-0012') + 'risk_install: ' +
                         ((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}

export = { RiskInstall: RiskInstall };
