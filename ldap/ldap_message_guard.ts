// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_message_guard.ts
//
// ---------------------------------------------------------------------------
// THE LARGEST LDAP MESSAGE A CLIENT MAY SEND, DECIDED FROM ITS HEADER
// (#2220, ASVS 5.0.0 L3, dangerous-functionality.md's Known gaps).
//
// node-ldapjs's parser (`node-ldapjs/lib/messages/parser.js`) buffers a
// connection's bytes — concatenating every chunk onto what it holds — until
// as many have arrived as the message's BER header declares. A header that
// declares four gigabytes is six bytes, and nothing before a bind looked at
// it: one unauthenticated connection could make this process hold whatever
// it was sent. **THIS FILE READS EACH MESSAGE'S TAG AND LENGTH FROM THE
// STREAM BEFORE LDAPJS SEES A BYTE, AND CLOSES THE CONNECTION WHEN THE
// DECLARED LENGTH IS OVER THE LIMIT** — so the oversized message is never
// buffered, by ldapjs or here.
//
// **IN THIS REPOSITORY, NOT IN THE FORK**: the root CLAUDE.md sends every
// change to ldapjs to `rcbj/node-ldapjs`, and this needed none. ldapjs's
// connection handler adds ONE `data` listener that writes to the parser
// (`lib/server.js`'s `newConnection`); `ldap_server.js` moves the socket's
// `data` listeners behind `LdapMessageGuard.install()`, which hands each
// chunk on only once the guard has passed it. Both listeners (389 and 636)
// go through the same install, and so does a connection the PROXY protocol
// header preceded, since that header is read before ldapjs's handler runs.
//
// **TWO LIMITS** (`ldap.maxMessageBytes`, `ldap.maxMessageBytesBeforeBind`;
// the arithmetic is on those rows in `common/config.js`). Before a bind the
// only messages a client has any business sending are a bind (a DN and a
// password, or SASL credentials — a Kerberos token at Windows' largest
// MaxTokenSize is 64 KiB), StartTLS and a root DSE search. After it, an add
// or a modify may carry a jpegPhoto, a certificate chain or a group's member
// list, and the limit is the 5 MB every HTTP body here is held to. A SEARCH
// RESULT IS SERVER TO CLIENT and is not read by this file at all.
//
// **WHAT IS COUNTED** is the whole message: the tag, the length octets and
// the content. BER's indefinite length (0x80) is refused too — RFC 4511
// section 5.1 allows only the definite form, and an indefinite message has
// no length to bound. A first octet that is not a SEQUENCE (0x30) is not
// LDAP: the guard steps aside and ldapjs's own parser refuses it as before.
//
// No Entering/Leaving pair in `feed()`, `limitFor()` or the constructor:
// they run for every chunk (and every message) of every connection, and a
// pair per call would drown the log (the hot-path exception the code style
// allows, stated here as it requires). `install()` logs through the
// caller's logger.
// ---------------------------------------------------------------------------

/**
 * What `feed()` answers for a chunk the limit refuses.
 */
interface GuardRefusal {
  declared: number;
  limit: number;
  bound: boolean;
  reason: 'too-long' | 'indefinite';
}

interface GuardLimits {
  /** The limit once the connection has bound. */
  bound: number;
  /** The limit before it has. */
  unbound: number;
}

/**
 * Reads the BER header of each LDAP message a client sends and refuses the
 * one whose declared length is over the limit, before any of it is
 * buffered.
 */
export = class LdapMessageGuard {
  // Where the guard is in the stream: reading a header (`header` holds the
  // octets read so far), skipping a message's remaining content, or stepped
  // aside for a stream that is not LDAP.
  private header: number[] = [];
  private remaining = 0;
  private off = false;

  /**
   * Builds a guard for one connection.
   *
   * @param limits - answers the two limits, asked at each message's header
   *   so a change to either applies to the next message
   */
  constructor(private readonly limits: () => GuardLimits) {
  }

  /**
   * Reads one chunk the client sent.
   *
   * @param chunk - the bytes, as they arrived
   * @param bound - whether the connection has bound
   * @returns null to hand the chunk on, or the refusal
   */
  feed(chunk: Buffer, bound: boolean): GuardRefusal | null {
    let i = 0;
    while (i < chunk.length && !this.off) {
      if (this.remaining > 0) {
        const step = Math.min(this.remaining, chunk.length - i);
        this.remaining -= step;
        i += step;
        continue;
      }
      this.header.push(chunk[i]);
      i += 1;
      if (this.header[0] !== 0x30) {
        // Not an LDAPMessage: ldapjs refuses it, as it always did.
        this.off = true;
        break;
      }
      if (this.header.length < 2) {
        continue;
      }
      const first = this.header[1];
      if (first === 0x80) {
        return { declared: -1, limit: this.limitFor(bound), bound: bound,
                 reason: 'indefinite' };
      }
      let content = 0;
      if (first < 0x80) {
        content = first;
      } else {
        const octets = first & 0x7f;
        if (octets > 6) {
          // More than 2^48 bytes, which no limit admits.
          return { declared: Number.MAX_SAFE_INTEGER,
                   limit: this.limitFor(bound), bound: bound,
                   reason: 'too-long' };
        }
        if (this.header.length < 2 + octets) {
          continue;
        }
        for (let k = 0; k < octets; k++) {
          content = content * 256 + this.header[2 + k];
        }
      }
      const total = this.header.length + content;
      const limit = this.limitFor(bound);
      if (total > limit) {
        return { declared: total, limit: limit, bound: bound,
                 reason: 'too-long' };
      }
      this.header = [];
      this.remaining = content;
    }
    return null;
  }

  private limitFor(bound: boolean): number {
    const limits = this.limits();
    return bound ? limits.bound : Math.min(limits.unbound, limits.bound);
  }

  /**
   * Puts a guard between a connection and the `data` listeners already on
   * it — ldapjs's, which writes to its parser — so that each chunk reaches
   * them only once the guard has passed it, and a refused message closes
   * the connection instead.
   *
   * @param socket - the connection, after ldapjs's connection handler ran
   * @param options - `log`, `limits` (as the constructor takes),
   *   `isBound(socket)` and `refused(socket, refusal)`, called once before
   *   the connection is destroyed
   * @returns false when the socket was already guarded
   */
  static install(socket: any, options: {
    log: { debug(message: string): void };
    limits: () => GuardLimits;
    isBound: (socket: any) => boolean;
    refused: (socket: any, refusal: GuardRefusal) => void;
  }): boolean {
    const log = options.log;
    log.debug("Entering LdapMessageGuard.install().");
    if (!socket || socket.ldapMessageGuard) {
      log.debug("Leaving LdapMessageGuard.install(). Already guarded.");
      return false;
    }
    const guard = new LdapMessageGuard(options.limits);
    socket.ldapMessageGuard = guard;
    const theirs = socket.listeners('data');
    socket.removeAllListeners('data');
    let closed = false;
    socket.on('data', function (chunk: Buffer) {
      if (closed) {
        return;
      }
      const refusal = guard.feed(chunk, options.isBound(socket));
      if (refusal) {
        closed = true;
        options.refused(socket, refusal);
        socket.destroy();
        return;
      }
      for (let i = 0; i < theirs.length; i++) {
        theirs[i].call(socket, chunk);
      }
    });
    log.debug("Leaving LdapMessageGuard.install(). " + theirs.length +
              " listener(s) behind the guard.");
    return true;
  }
};
