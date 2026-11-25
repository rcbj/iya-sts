// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mail_transports.ts
//
// ===========================================================================
// THE FIVE WAYS A MESSAGE LEAVES (#63, 2026-09-22): capture, a self-hosted
// SMTP relay, Amazon SES v2, Azure Communication Services Email and the Gmail
// API — five classes behind one method, `send(message)`.
//
// **NOTHING BUT `common/mail.ts` REQUIRES THIS FILE** (the issue's first
// requirement). A caller asks the mail channel to send; which transport
// carried it is the channel's business, and a module that reached for a
// transport directly would skip the outbox, the claim, the rate ceiling and
// the audit row — every property the channel exists to have.
//
// ---------------------------------------------------------------------------
// FIVE THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **1. THE MESSAGE IS COMPOSED ONCE, HERE, AND NEVER FETCHES ANYTHING.**
// nodemailer's composer is built with `disableFileAccess` and
// `disableUrlAccess`, so no part of a message can be read from a path or a
// URL — the content is the strings `common/mail.ts` rendered and nothing
// else. SMTP, SES and Gmail are handed the same raw RFC 5322 bytes; Azure
// takes structured content and is handed the same subject and parts.
//
// **2. NO CLEARTEXT SMTP, AND NO SWITCH FOR IT.** `starttls` sets
// `requireTLS` (a server that does not offer STARTTLS is refused, and a
// downgrade by a man in the middle is a refusal rather than a cleartext
// session); `implicit` is TLS from the first byte. The relay's certificate
// is verified against the host name — or `mail.smtpServerName` — and against
// the system store or `mail.smtpCaFile`, TLS 1.2 at the least, in BOTH modes.
// This is the database dial's rule (`persistence/CLAUDE.md`), for its reason.
//
// **3. DKIM IS SIGNED BY `common/crypto.js`**, over the composed bytes, and
// prepended; nodemailer's own signer is never configured.
//
// **4. THE CLOUD SDKs ARE OPTIONAL PEERS**, required when the transport is
// BUILT, exactly as `common/secrets.js` requires its providers'. A missing
// one is STS-MAIL-0005 and names the package. They are loaded through
// `deps.load` so an in-process test can hand in a stub client.
//
// **5. EVERY FAILURE SAYS WHETHER IT IS WORTH REPEATING.** A thrown error
// carries a code and `retry`: a timeout, a lost connection, an SMTP 4xx, a
// provider's throttling or 5xx is retried (STS-MAIL-0009); an SMTP 5xx, a
// rejected sender, a failed login or a certificate that did not verify is
// final (0008, 0021, 0014). The outbox decides what to do with it.
// ===========================================================================

import fs = require('fs');
import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import secrets = require('./secrets');
import crypto = require('./crypto');
import nodeTls = require('tls');
import OutboundTls = require('./outbound_tls');
import truststores = require('./truststores');

type Json = any;

// What `common/mail.ts` hands a transport to send.
interface OutMessage {
  from: string;
  fromName: string;
  to: string;
  subject: string;
  text: string;
  html: string;
  messageId: string;
  date: Date;
  lang: string;
  // #1955 P6: `{ kind: 'openpgp', armoredKey }` or `{ kind: 'smime',
  // certificate (base64 DER) }`, with `outerSubject`; absent is cleartext.
  // An S/MIME one may carry `contentEncryption` (#2124), the realm's
  // `mail.smimeContentEncryption` read at the attempt; absent is GCM.
  encryption?: Json;
}

// What a transport answers: the provider's id for the message, when it gave
// one.
interface SentResult {
  providerId: string;
  detail?: string;
}

interface MailTransport {
  readonly name: string;
  send(message: OutMessage): Promise<SentResult>;
  close(): void;
}

interface TransportDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  // `require`, for nodemailer and the optional SDKs; a test hands in stubs.
  load: (name: string) => any;
  readSecret: (spec: Json) => Promise<string | null>;
  secrets: typeof secrets;
  readFile: (path: string) => string;
  dkimSign: typeof crypto.dkimSign;
  // #2220: the selector switch's DNS record and its DNS lookup. Optional, so
  // a test's deps built before them sign with the current selector only.
  dkimDnsRecord?: typeof crypto.dkimDnsRecord;
  resolveTxt?: (name: string) => Promise<string[][]>;
  now?: () => number;
  // #1955 P6: the two encryptions, `common/crypto.js`'s. Optional, so a
  // test's deps built before them still compose a cleartext message.
  openpgpEncrypt?: typeof crypto.openpgpEncrypt;
  smimeEnvelope?: typeof crypto.smimeEnvelope;
}

// A failure with its code and whether it is worth another attempt.
/**
 * Makes a send failure carrying its error code and whether another attempt is
 * worth making.
 *
 * @param message - the failure
 * @param code - its STS error code
 * @param retry - true when another attempt may succeed
 * @returns the Error, with `retry` set
 */
function sendError(message: string, code: string, retry: boolean): Error {
  helpers.log.debug("Entering sendError(). " + code);
  const e: Json = errorCodes.mark(new Error(message), code);
  e.retry = retry;
  helpers.log.debug("Leaving sendError().");
  return e;
}

// An address a message may carry: one mailbox, no display name, no
// whitespace, no angle brackets or commas that would make it two. RFC 5321's
// limits (64 octets local, 254 total).
/**
 * Checks that an address is one plain mailbox: no display name, no whitespace
 * or separators, within RFC 5321's limits.
 *
 * @param address - the address
 * @returns what is wrong with it, or '' when nothing is
 */
function addressProblem(address: string): string {
  helpers.log.debug("Entering addressProblem().");
  const a = String(address || '');
  if (!a || a.length > 254 || /[\s<>,;:"()\[\]\\]/.test(a)) {
    helpers.log.debug("Leaving addressProblem(). Malformed.");
    return 'is not one plain mailbox address';
  }
  const at = a.lastIndexOf('@');
  if (at < 1 || at > 64 || at === a.length - 1 ||
      !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/
        .test(a.slice(at + 1))) {
    helpers.log.debug("Leaving addressProblem(). Bad parts.");
    return 'has no local part and domain';
  }
  helpers.log.debug("Leaving addressProblem(). Fine.");
  return '';
}

// A timeout around one attempt, cleared when it settles — a delay inside one
// operation, which is what `tests/no_periodic_timers.js` allows.
function withTimeout<T>(work: Promise<T>, ms: number, what: string):
  Promise<T> {
  helpers.log.debug("Entering withTimeout(). " + what);
  let timer: NodeJS.Timeout | null = null;
  const limit = new Promise<T>(function (resolve, reject) {
    timer = setTimeout(function () {
      reject(sendError(what + ' did not finish within ' + ms + ' ms',
                       'STS-MAIL-0009', true));
    }, ms);
    if (timer && typeof timer.unref === 'function') {
      timer.unref();
    }
  });
  helpers.log.debug("Leaving withTimeout().");
  return Promise.race([work, limit]).finally(function () {
    if (timer) {
      clearTimeout(timer);
    }
  });
}

/**
 * The five ways a message leaves: capture, an SMTP relay, Amazon SES v2, Azure
 * Communication Services Email and the Gmail API, each behind one
 * `send(message)`.
 *
 * Only `common/mail.ts` uses this. The message is composed once and fetches
 * nothing; SMTP is never sent in the clear.
 */
class MailTransports {
  /**
   * Creates the transport builder.
   *
   * @param deps - its dependencies: the logger, the error-code table, a module
   * loader, the secret reader, a file reader and the DKIM signer
   */
  constructor(private readonly deps: TransportDeps) {
    deps.log.debug("Entering MailTransports.constructor().");
    deps.log.debug("Leaving MailTransports.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TransportDeps {
    helpers.log.debug("Entering MailTransports.defaultDeps().");
    helpers.log.debug("Leaving MailTransports.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      load: function (name: string): any {
        return require(name);
      },
      readSecret: function (spec: Json): Promise<string | null> {
        return secrets.readSecretText(spec);
      },
      secrets: secrets,
      readFile: function (path: string): string {
        require('./outbound_tls').assertNamedFile(path);
        return fs.readFileSync(path, 'utf8');
      },
      dkimSign: crypto.dkimSign,
      dkimDnsRecord: crypto.dkimDnsRecord,
      resolveTxt: function (name: string): Promise<string[][]> {
        return require('dns').promises.resolveTxt(name);
      },
      now: function (): number {
        return Date.now();
      },
      openpgpEncrypt: crypto.openpgpEncrypt,
      smimeEnvelope: crypto.smimeEnvelope
    };
  }

  // An optional SDK, or STS-MAIL-0005 naming it.
  private sdk(pkg: string, transport: string): any {
    const { log, load } = this.deps;
    log.debug("Entering MailTransports.sdk(). " + pkg);
    try {
      const loaded = load(pkg);
      log.debug("Leaving MailTransports.sdk().");
      return loaded;
    } catch (e) {
      log.debug("Caught in MailTransports.sdk(): " + ((e && e.message) || e));
      log.debug("Leaving MailTransports.sdk(). Not installed.");
      throw sendError('the "' + transport + '" mail transport needs the ' +
        pkg + ' package and it is not installed. It is an optional peer, ' +
        'not a dependency: build the image with STS_CLOUD_SDKS="' + pkg +
        '" or run `npm install ' + pkg + '`.', 'STS-MAIL-0005', false);
    }
  }

  // -------------------------------------------------------------------------
  // THE RAW MESSAGE (header point 1). `Auto-Submitted: auto-generated` (RFC
  // 3834) tells a vacation responder not to answer it.
  // -------------------------------------------------------------------------
  /**
   * Composes the raw RFC 5322 message, with file and URL access disabled and
   * `Auto-Submitted: auto-generated`.
   *
   * @param message - the message
   * @returns the raw bytes
   */
  async compose(message: OutMessage): Promise<Buffer> {
    const { log, load } = this.deps;
    log.debug("Entering MailTransports.compose().");
    if (message.encryption && message.encryption.kind &&
        message.encryption.kind !== 'none') {
      const encrypted = await this.composeEncrypted(message);
      log.debug("Leaving MailTransports.compose(). Encrypted, " +
                encrypted.length + " bytes.");
      return encrypted;
    }
    const MailComposer = load('nodemailer/lib/mail-composer');
    const composer = new MailComposer({
      from: message.fromName
        ? { name: message.fromName, address: message.from } : message.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
      messageId: message.messageId,
      date: message.date,
      headers: {
        'Auto-Submitted': 'auto-generated',
        'Content-Language': message.lang || 'en'
      },
      disableFileAccess: true,
      disableUrlAccess: true
    });
    const raw: Buffer = await composer.compile().build();
    log.debug("Leaving MailTransports.compose(). " + raw.length + " bytes.");
    return raw;
  }

  // -------------------------------------------------------------------------
  // AN ENCRYPTED MESSAGE (#1955 P6, `common/mail.ts` header point 9).
  //
  // THE INNER ENTITY is what the cleartext message would have been — its
  // text and HTML parts as multipart/alternative — carrying the REAL Subject,
  // From, To, Date and Message-ID as protected headers (`protected-headers=
  // "v1"`, RFC 9788's legacy display form readers already understand), so a
  // reader that decrypts shows the real subject.
  //
  // THE OUTER MESSAGE carries the neutral subject and nothing of the body:
  //
  //   * PGP/MIME (RFC 3156 section 4): multipart/encrypted; protocol=
  //     "application/pgp-encrypted", a first part `Version: 1` and a second
  //     application/octet-stream part holding the ASCII-armored OpenPGP
  //     message, both 7bit.
  //   * S/MIME (RFC 8551 section 3.3): application/pkcs7-mime;
  //     smime-type=authEnveloped-data, base64 of the CMS AuthEnvelopedData
  //     under AES-256-GCM (#2124, ASVS 5.0.0 11.3.3) — or, where
  //     `mail.smimeContentEncryption` is `aes256-cbc`, smime-type=
  //     enveloped-data and the CBC EnvelopedData sent before 1.2.0. The
  //     parameter is `crypto.smimeTypeFor()`'s, so it names what
  //     `smimeEnvelope()` wrote under the same reading of the setting.
  //
  // Both built with nodemailer's MimeNode, file and URL access disabled as
  // the composer above is. A failure to encrypt is final (STS-MAIL-0243):
  // another attempt would read the same key, and the message is never sent
  // in the clear instead.
  // -------------------------------------------------------------------------
  /**
   * Composes an encrypted message: PGP/MIME or S/MIME around the cleartext
   * message's parts, the real headers protected inside.
   *
   * @param message - the message, with `encryption`
   * @returns the raw bytes
   * @throws a final send failure (STS-MAIL-0243) when it cannot encrypt
   */
  async composeEncrypted(message: OutMessage): Promise<Buffer> {
    const { log, load } = this.deps;
    log.debug("Entering MailTransports.composeEncrypted(). " +
              message.encryption.kind);
    const MimeNode = load('nodemailer/lib/mime-node');
    const options = { disableFileAccess: true, disableUrlAccess: true };
    const build = function (node: Json): Promise<Buffer> {
      return new Promise(function (resolve, reject): void {
        node.build(function (e: Json, out: Buffer): void {
          if (e) {
            reject(e);
            return;
          }
          resolve(out);
        });
      });
    };
    const from = message.fromName
      ? { name: message.fromName, address: message.from } : message.from;
    const inner = new MimeNode('multipart/alternative', options);
    inner.setHeader('Content-Type',
                    'multipart/alternative; protected-headers="v1"');
    inner.setHeader({ From: from, To: message.to, Subject: message.subject,
                      Date: message.date, 'Message-ID': message.messageId });
    inner.createChild('text/plain; charset=utf-8').setContent(message.text);
    inner.createChild('text/html; charset=utf-8').setContent(message.html);
    let body: Buffer;
    try {
      body = await build(inner);
    } catch (e) {
      log.debug("Caught in MailTransports.composeEncrypted(): " +
                ((e && e.message) || e));
      log.debug("Leaving MailTransports.composeEncrypted(). Inner.");
      throw sendError('the message could not be composed for encryption: ' +
                      ((e && e.message) || e), 'STS-MAIL-0243', false);
    }
    const headers = {
      From: from, To: message.to,
      Subject: String(message.encryption.outerSubject || '...'),
      Date: message.date, 'Message-ID': message.messageId,
      'Auto-Submitted': 'auto-generated',
      'Content-Language': message.lang || 'en'
    };
    let outer: Json;
    try {
      if (message.encryption.kind === 'openpgp') {
        const encrypt = this.deps.openpgpEncrypt || crypto.openpgpEncrypt;
        const armored = await encrypt(body,
          String(message.encryption.armoredKey || ''), message.date);
        outer = new MimeNode('multipart/encrypted', options);
        outer.setHeader('Content-Type', 'multipart/encrypted; ' +
                        'protocol="application/pgp-encrypted"');
        outer.setHeader(headers);
        outer.createChild('application/pgp-encrypted')
          .setHeader('Content-Description', 'PGP/MIME version identification')
          .setHeader('Content-Transfer-Encoding', '7bit')
          .setContent('Version: 1\r\n');
        outer.createChild('application/octet-stream; name="encrypted.asc"')
          .setHeader('Content-Description', 'OpenPGP encrypted message')
          .setHeader('Content-Disposition', 'inline; filename="encrypted.asc"')
          .setHeader('Content-Transfer-Encoding', '7bit')
          .setContent(armored.replace(/\r?\n/g, '\r\n'));
      } else if (message.encryption.kind === 'smime') {
        const envelope = this.deps.smimeEnvelope || crypto.smimeEnvelope;
        const content = crypto.smimeContentEncryption(
          message.encryption.contentEncryption);
        const der = await envelope(body, Buffer.from(String(
          message.encryption.certificate || ''), 'base64'), content);
        outer = new MimeNode('application/pkcs7-mime; smime-type=' +
          crypto.smimeTypeFor(content) + '; name="smime.p7m"', options);
        outer.setHeader(headers);
        outer.setHeader('Content-Disposition',
                        'attachment; filename="smime.p7m"');
        outer.setHeader('Content-Transfer-Encoding', 'base64');
        outer.setContent(der);
      } else {
        // error-code: none — rethrown below as STS-MAIL-0243
        throw new Error('unknown encryption "' +
                        String(message.encryption.kind) + '"');
      }
    } catch (e) {
      log.debug("Caught in MailTransports.composeEncrypted(): " +
                ((e && e.message) || e));
      log.debug("Leaving MailTransports.composeEncrypted(). Not encrypted.");
      throw sendError('the message could not be encrypted to its ' +
                      'recipient: ' + ((e && e.message) || e),
                      'STS-MAIL-0243', false);
    }
    const raw = await build(outer);
    log.debug("Leaving MailTransports.composeEncrypted(). " + raw.length +
              " bytes.");
    return raw;
  }

  // -------------------------------------------------------------------------
  // BUILD the transport `cfg` describes — `cfg` is `common/mail.ts`'s reading
  // of the realm's settings. Secrets are read here, once per build. Throws
  // with a code when it cannot be built; the caller caches what it returns.
  // -------------------------------------------------------------------------
  /**
   * Builds the transport the realm's mail settings describe, reading its
   * secrets once.
   *
   * @param cfg - `common/mail.ts`'s reading of the realm's settings
   * @returns the transport
   * @throws Error with its code when it cannot be built, STS-MAIL-0001 when
   * none is configured
   */
  async build(cfg: Json): Promise<MailTransport> {
    const { log } = this.deps;
    log.debug("Entering MailTransports.build(). " + cfg.transport);
    let built: MailTransport;
    switch (cfg.transport) {
      case 'capture':
        built = this.capture();
        break;
      case 'smtp':
        built = await this.smtp(cfg);
        break;
      case 'ses':
        built = this.ses(cfg);
        break;
      case 'acs':
        built = await this.acs(cfg);
        break;
      case 'gmail':
        built = await this.gmail(cfg);
        break;
      default:
        log.debug("Leaving MailTransports.build(). Off.");
        throw sendError('no mail transport is configured (mail.transport ' +
                        'is "' + cfg.setting + '")', 'STS-MAIL-0001', false);
    }
    log.debug("Leaving MailTransports.build(). " + built.name);
    return built;
  }

  // THE CAPTURE TRANSPORT: sends nothing. The outbox keeps the message with
  // its body in state `captured`; this only says it was accepted.
  /**
   * Builds the capture transport, which sends nothing: the outbox keeps the
   * message.
   *
   * @returns the transport
   */
  capture(): MailTransport {
    const { log } = this.deps;
    log.debug("Entering MailTransports.capture().");
    log.debug("Leaving MailTransports.capture().");
    return {
      name: 'capture',
      send: function (message: OutMessage): Promise<SentResult> {
        return Promise.resolve({ providerId: message.messageId,
                                 detail: 'captured, not sent' });
      },
      close: function (): void {
        return undefined;
      }
    };
  }

  // -------------------------------------------------------------------------
  // A DKIM SELECTOR SWITCH, WITH AN OVERLAP (#2220).
  //
  // A DKIM key is replaced by publishing a NEW selector, switching to it, and
  // keeping the OLD selector's record in DNS until mail signed with it has
  // been delivered and checked (RFC 6376 section 3.1, M3AAWG's rotation
  // practice). This service holds the keys and decides which one signs; DNS
  // is the operator's:
  //
  //   1. put the new private key in the DKIM key's secret, under
  //      `mail.dkimNextKeyField` (`dkimNextKey`), and name its selector in
  //      `mail.dkimNextSelector` — the record to publish is logged here, at
  //      info, every time the transport is built;
  //   2. publish it as the TXT record `<selector>._domainkey.<domain>`;
  //   3. set `mail.dkimSwitchAt` to when signing should move to it.
  //
  // From that moment the transport signs with the next selector, BUT ONLY
  // ONCE DNS ANSWERS WITH ITS KEY: a record not (yet) published, or carrying
  // another key, keeps the current selector and says so (STS-MAIL-0244), so
  // a forgotten step 2 is a warning and not every message failing DMARC.
  // The transport is rebuilt within an hour (`common/mail.ts`) and when the
  // moment passes, so the check is made again. Once the switch has held for
  // a week, the operator makes the next selector the current one
  // (`mail.dkimSelector`, the key under `mail.dkimKeyField`) and clears the
  // three settings; the old record can then be withdrawn.
  // -------------------------------------------------------------------------
  /**
   * Decides which DKIM selector and key a transport signs with.
   *
   * @param cfg - the realm's mail settings
   * @param currentKey - the current selector's private key
   * @returns `{ selector, key }`
   */
  async dkimSigning(cfg: Json, currentKey: string): Promise<Json> {
    const { log, readSecret, secrets, dkimDnsRecord, resolveTxt,
            now } = this.deps;
    log.debug("Entering MailTransports.dkimSigning().");
    const current = { selector: String(cfg.dkimSelector || ''),
                      key: currentKey };
    const nextSelector = String(cfg.dkimNextSelector || '').trim();
    if (!nextSelector || typeof dkimDnsRecord !== 'function' ||
        !secrets.MAIL_DKIM_NEXT_KEY) {
      log.debug("Leaving MailTransports.dkimSigning(). No switch.");
      return current;
    }
    const name = nextSelector + '._domainkey.' + String(cfg.dkimDomain);
    let nextKey = '';
    let expected: Json = null;
    try {
      nextKey = String(await readSecret(secrets.MAIL_DKIM_NEXT_KEY) || '');
      this.deps.dkimSign('From: probe@' + cfg.dkimDomain + '\r\n\r\n',
        { domain: cfg.dkimDomain, selector: nextSelector,
          algorithm: cfg.dkimAlgorithm, privateKeyPem: nextKey });
      expected = dkimDnsRecord(nextKey);
    } catch (e) {
      log.debug("Caught in MailTransports.dkimSigning(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-MAIL-0244') + 'mail: ' +
               'mail.dkimNextSelector is "' + nextSelector + '" and its key ' +
               '(mail.dkimNextKeyField) cannot sign, so messages are signed ' +
               'with the current selector: ' + ((e && e.message) || e));
      log.debug("Leaving MailTransports.dkimSigning(). Next key unusable.");
      return current;
    }
    log.info('mail: publish the DKIM record for the next selector as the ' +
             'TXT record ' + name + ': ' + expected.record);
    const at = Date.parse(String(cfg.dkimSwitchAt || ''));
    const clock = typeof now === 'function' ? now() : Date.now();
    if (!isFinite(at) || clock < at) {
      log.debug("Leaving MailTransports.dkimSigning(). Not yet.");
      return current;
    }
    let published = false;
    try {
      const answers = typeof resolveTxt === 'function'
        ? await withTimeout(resolveTxt(name), 5000, 'the DKIM record lookup')
        : [];
      published = (answers || []).some(function (parts: string[]) {
        const text = (parts || []).join('');
        const m = /(?:^|;)\s*p=([^;]*)/.exec(text);
        return !!m && m[1].replace(/\s+/g, '') === expected.p;
      });
    } catch (e) {
      log.debug("Caught in MailTransports.dkimSigning(): " +
                ((e && e.message) || e));
      published = false;
    }
    if (!published) {
      log.warn(errorCodes.tag('STS-MAIL-0244') + 'mail: mail.dkimSwitchAt ' +
               'has passed, but DNS does not answer ' + name + ' with the ' +
               'next DKIM key, so messages are still signed with the ' +
               'current selector "' + current.selector + '". Publish: ' +
               expected.record);
      log.debug("Leaving MailTransports.dkimSigning(). Not published.");
      return current;
    }
    log.info('mail: messages are signed with the DKIM selector "' +
             nextSelector + '" from now on; keep the record of "' +
             current.selector + '" published until mail signed with it has ' +
             'been delivered.');
    log.debug("Leaving MailTransports.dkimSigning(). Switched.");
    return { selector: nextSelector, key: nextKey };
  }

  // -------------------------------------------------------------------------
  // SMTP (header points 2 and 3).
  // -------------------------------------------------------------------------
  /**
   * Builds the SMTP transport: STARTTLS required or implicit TLS, the relay's
   * certificate verified, and DKIM where configured.
   *
   * @param cfg - the realm's mail settings
   * @returns the transport
   */
  async smtp(cfg: Json): Promise<MailTransport> {
    const { log, load, readSecret, secrets, readFile, dkimSign } = this.deps;
    const self = this;
    log.debug("Entering MailTransports.smtp().");
    const host = String(cfg.smtpHost || '');
    if (!host) {
      log.debug("Leaving MailTransports.smtp(). No host.");
      throw sendError('the smtp transport has no host (mail.smtpHost, or ' +
                      'a preset)', 'STS-MAIL-0004', false);
    }
    // Verified, with RFC 9525's host check and the path rules (#201) —
    // `OutboundTls.verifiedOptions()`, the one helper every dialer outside
    // the four families asks. `mail.smtpCaFile` is added beside it below.
    // `outbound-smtp`'s truststores where it is assigned (#2118); unassigned,
    // node's store and mail.smtpCaFile as before.
    const assigned = truststores.namesFor('outbound-smtp').assigned ?
      OutboundTls.optionsFor('outbound-smtp') : null;
    if (assigned && assigned.problem) {
      throw sendError(assigned.problem.why, 'STS-MAIL-0004', false);
    }
    const tls: Json = Object.assign(assigned ||
                                    OutboundTls.verifiedOptions(null), {
      minVersion: 'TLSv1.2',
      servername: String(cfg.smtpServerName || '') || host
    });
    try {
      if (cfg.smtpCaFile && !assigned) {
        // BESIDE node's store, as this file's header and the setting say
        // (#1360): `ca` replaces the store, so a relay on a public CA stopped
        // verifying the moment somebody named a file for a private one. And
        // beside what `verifiedOptions()` already put there (#2118): writing
        // node's roots over it dropped the signer truststore under paranoid
        // PKI mode.
        tls.ca = (tls.ca || nodeTls.rootCertificates)
          .concat(String(readFile(String(cfg.smtpCaFile))));
      }
      if (cfg.smtpClientCertFile || cfg.smtpClientKeyFile) {
        if (!cfg.smtpClientCertFile || !cfg.smtpClientKeyFile) {
          throw new Error('mail.smtpClientCertFile and ' +
                          'mail.smtpClientKeyFile are set together or not ' +
                          'at all');
        }
        tls.cert = readFile(String(cfg.smtpClientCertFile));
        tls.key = readFile(String(cfg.smtpClientKeyFile));
      }
    } catch (e) {
      log.debug("Caught in MailTransports.smtp(): " + ((e && e.message) || e));
      log.debug("Leaving MailTransports.smtp(). A file.");
      throw sendError('the smtp transport\'s TLS files could not be read: ' +
                      ((e && e.message) || e), 'STS-MAIL-0004', false);
    }
    let auth: Json = undefined;
    if (cfg.smtpAuth && cfg.smtpAuth !== 'none') {
      const secret = await readSecret(secrets.MAIL_SMTP_PASSWORD);
      if (!secret) {
        log.debug("Leaving MailTransports.smtp(). No secret.");
        throw sendError('mail.smtpAuth is "' + cfg.smtpAuth + '" and ' +
                        'mail.smtpPasswordProvider is "none", so there is ' +
                        'nothing to log in with', 'STS-MAIL-0004', false);
      }
      if (cfg.smtpAuth === 'xoauth2') {
        let parsed: Json = null;
        try {
          parsed = JSON.parse(secret);
        } catch (e) {
          log.debug("Caught in MailTransports.smtp(): a bare access token. " +
                    ((e && e.message) || e));
          parsed = null;
        }
        auth = parsed && typeof parsed === 'object'
          ? { type: 'OAuth2', user: String(cfg.smtpUser || ''),
              clientId: parsed.clientId, clientSecret: parsed.clientSecret,
              refreshToken: parsed.refreshToken,
              accessUrl: parsed.accessUrl }
          : { type: 'OAuth2', user: String(cfg.smtpUser || ''),
              accessToken: secret };
      } else {
        auth = { user: String(cfg.smtpUser || ''), pass: secret,
                 method: cfg.smtpAuth === 'plain' ? 'PLAIN' : 'LOGIN' };
      }
    }
    let dkimKey = '';
    if (cfg.dkimDomain) {
      dkimKey = String(await readSecret(secrets.MAIL_DKIM_KEY) || '');
      if (!dkimKey || !cfg.dkimSelector) {
        log.debug("Leaving MailTransports.smtp(). DKIM half-configured.");
        throw sendError('mail.dkimDomain is set, so every message must be ' +
                        'signed, and ' + (dkimKey ? 'mail.dkimSelector is ' +
                        'empty' : 'no DKIM key is configured ' +
                        '(mail.dkimKeyProvider)'), 'STS-MAIL-0022', false);
      }
      // Proved now, with a message of nothing, so a key that cannot sign is
      // a build failure rather than a dead letter per message.
      try {
        dkimSign('From: probe@' + cfg.dkimDomain + '\r\n\r\n',
                 { domain: cfg.dkimDomain, selector: cfg.dkimSelector,
                   algorithm: cfg.dkimAlgorithm, privateKeyPem: dkimKey });
      } catch (e) {
        log.debug("Caught in MailTransports.smtp(): " +
                  ((e && e.message) || e));
        log.debug("Leaving MailTransports.smtp(). DKIM key unusable.");
        throw sendError('the DKIM key cannot sign: ' + ((e && e.message) || e),
                        'STS-MAIL-0022', false);
      }
    }
    // THE SELECTOR SWITCH (#2220): which selector and key this transport
    // signs with — the next one once its moment has come and DNS publishes
    // it, the current one otherwise.
    const signing = cfg.dkimDomain
      ? await this.dkimSigning(cfg, dkimKey)
      : { selector: String(cfg.dkimSelector || ''), key: dkimKey };
    const nodemailer = load('nodemailer');
    const implicit = cfg.smtpTls === 'implicit';
    const transporter = nodemailer.createTransport({
      host: host,
      port: Number(cfg.smtpPort),
      secure: implicit,
      requireTLS: !implicit,
      ignoreTLS: false,
      tls: tls,
      auth: auth,
      connectionTimeout: cfg.timeoutMs,
      greetingTimeout: cfg.timeoutMs,
      socketTimeout: cfg.timeoutMs,
      disableFileAccess: true,
      disableUrlAccess: true
    });
    log.debug("Leaving MailTransports.smtp(). " + host + ':' + cfg.smtpPort +
              ' ' + (implicit ? 'implicit TLS' : 'STARTTLS'));
    return {
      name: 'smtp',
      send: async function (message: OutMessage): Promise<SentResult> {
        let raw = await self.compose(message);
        if (signing.key) {
          try {
            const header = dkimSign(raw, { domain: cfg.dkimDomain,
              selector: signing.selector, algorithm: cfg.dkimAlgorithm,
              privateKeyPem: signing.key });
            raw = Buffer.concat([Buffer.from(header + '\r\n', 'binary'), raw]);
          } catch (e) {
            throw sendError('the message could not be DKIM-signed: ' +
                            ((e && e.message) || e), 'STS-MAIL-0022', false);
          }
        }
        let info: Json = null;
        try {
          info = await withTimeout(transporter.sendMail({
            envelope: { from: message.from, to: [message.to] },
            raw: raw
          }), cfg.timeoutMs + 1000, 'the SMTP transaction');
        } catch (e) {
          throw self.classifySmtp(e);
        }
        const rejected = (info && info.rejected) || [];
        if (rejected.length) {
          throw sendError('the relay rejected the recipient: ' +
                          String((info && info.response) || ''),
                          'STS-MAIL-0008', false);
        }
        return { providerId: String((info && info.messageId) ||
                                    message.messageId),
                 detail: String((info && info.response) || '') };
      },
      close: function (): void {
        try {
          transporter.close();
        } catch (e) {
          log.debug("Caught in close(): " + ((e && e.message) || e));
        }
      }
    };
  }

  // What an SMTP failure means (header point 5).
  /**
   * Classifies an SMTP failure: a refused login, a TLS failure or a 5xx is
   * final, a 4xx or anything else is worth repeating.
   *
   * @param e - the failure
   * @returns a coded send failure
   */
  classifySmtp(e: Json): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering MailTransports.classifySmtp(). code=" +
              (e && e.code) + " responseCode=" + (e && e.responseCode));
    if (e && errorCodes.codeOf(e)) {
      log.debug("Leaving MailTransports.classifySmtp(). Already coded.");
      return e;
    }
    const why = String((e && (e.response || e.message)) || e);
    const status = Number(e && e.responseCode) || 0;
    const code = String((e && e.code) || '');
    let out: Error;
    if (code === 'EAUTH') {
      out = sendError('the relay refused the login: ' + why,
                      'STS-MAIL-0021', false);
    } else if (code === 'ETLS' || /certificate|self.signed|unable to verify|CERT_|altnames/i.test(why)) {
      out = sendError('TLS with the relay failed, and nothing is sent in ' +
                      'the clear: ' + why, 'STS-MAIL-0014', false);
    } else if (status >= 500) {
      out = sendError('the relay refused the message (' + status + '): ' +
                      why, 'STS-MAIL-0008', false);
    } else if (status >= 400) {
      out = sendError('the relay deferred the message (' + status + '): ' +
                      why, 'STS-MAIL-0009', true);
    } else {
      out = sendError('the SMTP transaction failed: ' + why,
                      'STS-MAIL-0009', true);
    }
    log.debug("Leaving MailTransports.classifySmtp().");
    return out;
  }

  // -------------------------------------------------------------------------
  // AMAZON SES v2. Credentials from the default provider chain (the task role
  // on ECS Fargate), never a setting. The raw message, so the headers and the
  // parts are exactly the SMTP transport's.
  // -------------------------------------------------------------------------
  /**
   * Builds the Amazon SES v2 transport, with credentials from the default
   * provider chain and the raw message.
   *
   * @param cfg - the realm's mail settings
   * @returns the transport
   */
  ses(cfg: Json): MailTransport {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering MailTransports.ses().");
    const sdk = this.sdk('@aws-sdk/client-sesv2', 'ses');
    const client = new sdk.SESv2Client(cfg.sesRegion
      ? { region: String(cfg.sesRegion) } : {});
    log.debug("Leaving MailTransports.ses().");
    return {
      name: 'ses',
      send: async function (message: OutMessage): Promise<SentResult> {
        const raw = await self.compose(message);
        const input: Json = {
          FromEmailAddress: message.from,
          Destination: { ToAddresses: [message.to] },
          Content: { Raw: { Data: raw } }
        };
        if (cfg.sesConfigurationSet) {
          input.ConfigurationSetName = String(cfg.sesConfigurationSet);
        }
        let out: Json = null;
        try {
          out = await withTimeout(client.send(new sdk.SendEmailCommand(input)),
                                  cfg.timeoutMs, 'the SES SendEmail call');
        } catch (e) {
          throw self.classifyCloud(e, 'SES');
        }
        return { providerId: String((out && out.MessageId) || '') };
      },
      close: function (): void {
        try {
          if (typeof client.destroy === 'function') {
            client.destroy();
          }
        } catch (e) {
          log.debug("Caught in close(): " + ((e && e.message) || e));
        }
      }
    };
  }

  // What a cloud SDK's failure means: its own retryable flag, throttling, a
  // 5xx or 429 is worth repeating; anything else is final.
  /**
   * Classifies a cloud SDK's failure: its retryable flag, throttling, a 5xx or
   * a 429 is worth repeating; anything else is final.
   *
   * @param e - the failure
   * @param who - the provider, for the message
   * @returns a coded send failure
   */
  classifyCloud(e: Json, who: string): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering MailTransports.classifyCloud(). " + who);
    if (e && errorCodes.codeOf(e)) {
      log.debug("Leaving MailTransports.classifyCloud(). Already coded.");
      return e;
    }
    const status = Number((e && ((e.$metadata && e.$metadata.httpStatusCode) ||
                                 e.statusCode || e.code)) || 0);
    const name = String((e && (e.name || e.code)) || '');
    const retry = !!(e && (e.$retryable || e.retryable)) ||
      status === 429 || status >= 500 ||
      /Throttl|TooManyRequests|ServiceUnavailable|RequestTimeout|ECONN|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket/i
        .test(name + ' ' + String((e && e.message) || ''));
    const why = who + ' refused the message: ' + (name ? name + ': ' : '') +
      String((e && e.message) || e);
    log.debug("Leaving MailTransports.classifyCloud(). retry=" + retry);
    return sendError(why, retry ? 'STS-MAIL-0009' : 'STS-MAIL-0008', retry);
  }

  // -------------------------------------------------------------------------
  // AZURE COMMUNICATION SERVICES EMAIL. Sending is a long-running operation:
  // `beginSend()` answers a poller, polled to a terminal status inside the
  // attempt's timeout — `Succeeded` is sent, `Failed` or `Canceled` final.
  // -------------------------------------------------------------------------
  /**
   * Builds the Azure Communication Services Email transport, polling each send
   * to a terminal status within the attempt's timeout.
   *
   * @param cfg - the realm's mail settings
   * @returns the transport
   */
  async acs(cfg: Json): Promise<MailTransport> {
    const { log, readSecret, secrets } = this.deps;
    const self = this;
    log.debug("Entering MailTransports.acs().");
    const sdk = this.sdk('@azure/communication-email', 'acs');
    let client: any;
    if (cfg.acsAuth === 'connection-string') {
      const connection = await readSecret(secrets.MAIL_ACS_CONNECTION_STRING);
      if (!connection) {
        log.debug("Leaving MailTransports.acs(). No connection string.");
        throw sendError('mail.acsAuth is "connection-string" and ' +
                        'mail.acsConnectionStringProvider is "none"',
                        'STS-MAIL-0004', false);
      }
      client = new sdk.EmailClient(connection);
    } else {
      if (!/^https:\/\//.test(String(cfg.acsEndpoint || ''))) {
        log.debug("Leaving MailTransports.acs(). No endpoint.");
        throw sendError('managed-identity authentication needs ' +
                        'mail.acsEndpoint, an https URL', 'STS-MAIL-0004',
                        false);
      }
      const identity = this.sdk('@azure/identity', 'acs');
      client = new sdk.EmailClient(String(cfg.acsEndpoint),
                                   new identity.DefaultAzureCredential());
    }
    log.debug("Leaving MailTransports.acs().");
    return {
      name: 'acs',
      send: async function (message: OutMessage): Promise<SentResult> {
        if (message.encryption && message.encryption.kind &&
            message.encryption.kind !== 'none') {
          // #1955 P6: ACS takes structured content, never a MIME entity
          // composed here, so an encrypted message is final here rather
          // than sent in the clear (`mail.ts` refuses it at the queue too).
          throw sendError('the acs transport cannot carry an encrypted ' +
                          'message', 'STS-MAIL-0242', false);
        }
        let result: Json = null;
        try {
          const poller = await client.beginSend({
            senderAddress: message.from,
            content: { subject: message.subject, plainText: message.text,
                       html: message.html },
            recipients: { to: [{ address: message.to }] },
            headers: { 'Auto-Submitted': 'auto-generated' },
            userEngagementTrackingDisabled: true
          });
          result = await withTimeout(poller.pollUntilDone(), cfg.timeoutMs,
                                     'the Azure send operation');
        } catch (e) {
          throw self.classifyCloud(e, 'Azure Communication Services');
        }
        const status = String((result && result.status) || '');
        if (status !== 'Succeeded') {
          throw sendError('Azure Communication Services ended the send ' +
                          'as "' + (status || 'unknown') + '"' +
                          (result && result.error
                            ? ': ' + String(result.error.message ||
                                            result.error.code || '')
                            : ''), 'STS-MAIL-0008', false);
        }
        return { providerId: String((result && result.id) || '') };
      },
      close: function (): void {
        return undefined;
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE GMAIL API, as a Workspace mailbox: a service account with
  // domain-wide delegation of the gmail.send scope impersonates
  // `mail.gmailSender`, and `users.messages.send` takes the raw message.
  // -------------------------------------------------------------------------
  /**
   * Builds the Gmail API transport: a service account with domain-wide
   * delegation impersonating `mail.gmailSender`.
   *
   * @param cfg - the realm's mail settings
   * @returns the transport
   */
  async gmail(cfg: Json): Promise<MailTransport> {
    const { log, readSecret, secrets } = this.deps;
    const self = this;
    log.debug("Entering MailTransports.gmail().");
    const sdk = this.sdk('@googleapis/gmail', 'gmail');
    const keyText = await readSecret(secrets.MAIL_GMAIL_KEY);
    if (!keyText) {
      log.debug("Leaving MailTransports.gmail(). No key.");
      throw sendError('the gmail transport needs the service account key ' +
                      '(mail.gmailKeyProvider)', 'STS-MAIL-0004', false);
    }
    let key: Json = null;
    try {
      key = JSON.parse(keyText);
    } catch (e) {
      log.debug("Caught in MailTransports.gmail(): " +
                ((e && e.message) || e));
      key = null;
    }
    if (!key || !key.client_email || !key.private_key) {
      log.debug("Leaving MailTransports.gmail(). Not a key file.");
      throw sendError('the Gmail service account key is not a JSON key with ' +
                      'client_email and private_key', 'STS-MAIL-0004', false);
    }
    const subject = String(cfg.gmailSender || cfg.from || '');
    const auth = new sdk.auth.JWT({
      email: key.client_email,
      key: key.private_key,
      scopes: ['https://www.googleapis.com/auth/gmail.send'],
      subject: subject
    });
    const api = sdk.gmail({ version: 'v1', auth: auth });
    log.debug("Leaving MailTransports.gmail(). As " + subject);
    return {
      name: 'gmail',
      send: async function (message: OutMessage): Promise<SentResult> {
        const raw = await self.compose(message);
        let out: Json = null;
        try {
          out = await withTimeout(api.users.messages.send({
            userId: 'me',
            requestBody: { raw: raw.toString('base64url') }
          }), cfg.timeoutMs, 'the Gmail API send call');
        } catch (e) {
          throw self.classifyCloud(e, 'the Gmail API');
        }
        return { providerId: String((out && out.data && out.data.id) || '') };
      },
      close: function (): void {
        return undefined;
      }
    };
  }
}

/**
 * The mail channel's transports: the classes that carry a composed message to a
 * relay or a provider.
 *
 * Required by `common/mail.ts` and nothing else.
 *
 * @namespace
 */
export = {
  MailTransports: MailTransports,
  addressProblem: addressProblem,
  sendError: sendError
};
