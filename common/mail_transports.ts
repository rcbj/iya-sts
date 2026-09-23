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
}

// A failure with its code and whether it is worth another attempt.
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

class MailTransports {
  constructor(private readonly deps: TransportDeps) {
    deps.log.debug("Entering MailTransports.constructor().");
    deps.log.debug("Leaving MailTransports.constructor().");
  }

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
        return fs.readFileSync(path, 'utf8');
      },
      dkimSign: crypto.dkimSign
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
  async compose(message: OutMessage): Promise<Buffer> {
    const { log, load } = this.deps;
    log.debug("Entering MailTransports.compose().");
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
  // BUILD the transport `cfg` describes — `cfg` is `common/mail.ts`'s reading
  // of the realm's settings. Secrets are read here, once per build. Throws
  // with a code when it cannot be built; the caller caches what it returns.
  // -------------------------------------------------------------------------
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
  // SMTP (header points 2 and 3).
  // -------------------------------------------------------------------------
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
    const tls: Json = {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
      servername: String(cfg.smtpServerName || '') || host
    };
    try {
      if (cfg.smtpCaFile) {
        tls.ca = readFile(String(cfg.smtpCaFile));
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
        if (dkimKey) {
          try {
            const header = dkimSign(raw, { domain: cfg.dkimDomain,
              selector: cfg.dkimSelector, algorithm: cfg.dkimAlgorithm,
              privateKeyPem: dkimKey });
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

export = {
  MailTransports: MailTransports,
  addressProblem: addressProblem,
  sendError: sendError
};
