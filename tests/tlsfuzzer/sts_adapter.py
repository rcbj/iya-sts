# File: sts_adapter.py
#
# Runs ONE unmodified tlsfuzzer script against one of this service's TLS
# listeners, adapting two things about the far end that no tlsfuzzer script
# can be told on its command line. Nothing here is tlsfuzzer's code: it
# imports the pinned upstream at run time (tests/tlsfuzzer/build-tlsfuzzer.sh)
# and wraps three of its methods, then hands control to the script itself.
#
#   python3 sts_adapter.py [--client-cert-request] [--ldap] SCRIPT ARGS...
#
# --client-cert-request   THE MAIN PORT AND THE DEBUGGER LISTENER ASK EVERY
#   connection for a client certificate and require none (tls/CLAUDE.md), so
#   the server's flight carries a CertificateRequest that almost no tlsfuzzer
#   script expects: each would fail at its first handshake on a message RFC
#   8446 section 4.3.2 and RFC 5246 section 7.4.4 allow. Where the script's
#   own graph has no ExpectCertificateRequest, a CertificateRequest the server
#   sends is PROCESSED by tlsfuzzer's own ExpectCertificateRequest (so its
#   structure is still checked, and it enters the transcript), and the client
#   answers it as a client with no certificate must: an EMPTY Certificate
#   before its ClientKeyExchange (TLS 1.2) or before its Finished (TLS 1.3).
#   A script that does expect one is left exactly as written.
#
# --ldap   LDAPS ON 636 SPEAKS LDAP, and tlsfuzzer's scripts send
#   "GET / HTTP/1.0" and wait for an answer. The directory closes the
#   connection on a request it cannot parse, so every probe that needs the
#   server to answer application data would fail on a question of protocol
#   above TLS. A complete HTTP request a script sends (ending in a blank
#   line, CRLF or bare LF — scripts use both) is replaced by an LDAP
#   BindRequest (RFC 4511 section 4.2) of THE SAME LENGTH — the name is padded
#   to fit — which the directory answers with one BindResponse in every mode
#   (success, or 48 where product mode refuses the bind). Record sizes and
#   the lengths the length and record-limit scripts compute are unchanged.
#
# This file carries no licence of tlsfuzzer's and no copy of any of its code;
# tlsfuzzer is GPL-2.0 and tlslite-ng LGPL-2.1, fetched and run, never
# vendored (tests/CLAUDE.md, THE TLS FUZZER).
import os
import runpy
import sys


def ber_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def ldap_bind(total):
    """An LDAPv3 simple BindRequest exactly `total` bytes long, or None."""
    for name_len in range(total, -1, -1):
        name = b'cn=' + b'x' * max(0, name_len - 3) if name_len >= 3 \
            else b'x' * name_len
        body = (b'\x02\x01\x03' + b'\x04' + ber_length(len(name)) + name +
                b'\x80\x00')
        op = b'\x60' + ber_length(len(body)) + body
        seq = b'\x02\x01\x01' + op
        msg = b'\x30' + ber_length(len(seq)) + seq
        if len(msg) == total:
            return msg
        if len(msg) < total:
            return None
    return None


def main():
    argv = sys.argv[1:]
    cert_request = False
    ldap = False
    aead = False
    while argv and argv[0] in ('--client-cert-request', '--ldap',
                               '--tls12-aead'):
        if argv[0] == '--client-cert-request':
            cert_request = True
        elif argv[0] == '--ldap':
            ldap = True
        else:
            aead = True
        argv = argv[1:]
    if not argv:
        sys.stderr.write('usage: sts_adapter.py [--client-cert-request] '
                         '[--ldap] SCRIPT [ARGS...]\n')
        sys.exit(2)
    script = argv[0]
    root = os.path.dirname(os.path.dirname(os.path.abspath(script)))
    sys.path[:0] = [root]

    from tlsfuzzer import runner as fuzz_runner
    from tlsfuzzer import messages as fuzz_messages
    from tlsfuzzer.expect import ExpectCertificateRequest, \
        ExpectServerHello, ExpectServerKeyExchange
    from tlslite import messagesocket
    from tlsfuzzer.helpers import RSA_SIG_ALL
    from tlslite.constants import CipherSuite, ContentType, ExtensionType, \
        GroupName, HandshakeType
    from tlslite.extensions import SignatureAlgorithmsExtension, \
        SupportedGroupsExtension

    current = {'state': None, 'request': False, 'key_exchange': False}

    original_init = fuzz_runner.Runner.__init__

    def runner_init(self, conversation):
        original_init(self, conversation)
        current['state'] = self.state
        current['request'] = cert_request and not graph_has(
            conversation, ExpectCertificateRequest)
        current['key_exchange'] = aead and not graph_has(
            conversation, ExpectServerKeyExchange)
        self.state.sts_request_pending = False
    fuzz_runner.Runner.__init__ = runner_init

    original_recv = messagesocket.MessageSocket.recvMessageBlocking

    def handshake_type(res):
        if (isinstance(res, tuple) and
                res[0].type == ContentType.handshake and res[1].bytes):
            return res[1].bytes[0]
        return None

    def recv(self):
        while True:
            res = original_recv(self)
            state = current['state']
            kind = handshake_type(res)
            if state is None or kind is None:
                return res
            msg = fuzz_messages.Message(res[0].type, res[1].bytes)
            if current['request'] and \
                    kind == HandshakeType.certificate_request:
                ExpectCertificateRequest().process(state, msg)
                state.sts_request_pending = True
                continue
            if current['key_exchange'] and \
                    kind == HandshakeType.server_key_exchange:
                ExpectServerKeyExchange().process(state, msg)
                continue
            return res
    messagesocket.MessageSocket.recvMessageBlocking = recv

    if aead:
        swap = aead_substitutes(CipherSuite)

        def substitute(ciphers):
            if not ciphers:
                return ciphers
            out = []
            for one in ciphers:
                one = swap.get(one, one)
                if one not in out:
                    out.append(one)
            return out

        chg = fuzz_messages.ClientHelloGenerator
        original_chg = chg.__init__

        ecdhe = set(swap.values())

        def chg_init(self, ciphers=None, extensions=None, *args, **kwargs):
            ciphers = substitute(ciphers)
            # A script written for RSA key exchange sends neither extension,
            # and ECDHE needs both: without signature_algorithms a TLS 1.2
            # server may only sign with SHA-1 (RFC 5246 section 7.4.1.4.1),
            # which OpenSSL's default security level refuses. Added only
            # where the script sent none of its own.
            if ciphers and ecdhe.intersection(ciphers) and \
                    not kwargs.get('ssl2'):
                extensions = dict(extensions or {})
                if ExtensionType.signature_algorithms not in extensions:
                    extensions[ExtensionType.signature_algorithms] = \
                        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
                if ExtensionType.supported_groups not in extensions:
                    extensions[ExtensionType.supported_groups] = \
                        SupportedGroupsExtension().create(
                            [GroupName.x25519, GroupName.secp256r1])
            original_chg(self, ciphers, extensions, *args, **kwargs)
        chg.__init__ = chg_init

        esh = ExpectServerHello
        original_esh = esh.__init__

        def esh_init(self, *args, **kwargs):
            if kwargs.get('cipher') is not None:
                kwargs['cipher'] = swap.get(kwargs['cipher'],
                                            kwargs['cipher'])
            original_esh(self, *args, **kwargs)
        esh.__init__ = esh_init

    if cert_request:
        def send_empty_certificate(state, queue):
            gen = fuzz_messages.CertificateGenerator()
            msg = gen.generate(state)
            if queue:
                state.msg_sock.queueMessageBlocking(msg)
            else:
                state.msg_sock.sendMessageBlocking(msg)
            gen.post_send(state)
            state.sts_request_pending = False

        cke = fuzz_messages.ClientKeyExchangeGenerator
        original_cke = cke.generate

        def cke_generate(self, state):
            if getattr(state, 'sts_request_pending', False) and \
                    state.version < (3, 4):
                send_empty_certificate(state, self.queue)
            return original_cke(self, state)
        cke.generate = cke_generate

        fin = fuzz_messages.FinishedGenerator
        original_fin = fin.generate

        def fin_generate(self, state):
            if getattr(state, 'sts_request_pending', False) and \
                    state.version >= (3, 4):
                send_empty_certificate(state, self.queue)
            return original_fin(self, state)
        fin.generate = fin_generate

    if ldap:
        adg = fuzz_messages.ApplicationDataGenerator
        original_adg = adg.__init__

        def adg_init(self, payload, *args, **kwargs):
            data = bytes(payload)
            if data.startswith(b'GET ') and data.endswith(b'\n\n') or \
                    data.startswith(b'GET ') and data.endswith(b'\r\n\r\n'):
                bind = ldap_bind(len(data))
                if bind is not None:
                    payload = bytearray(bind)
            original_adg(self, payload, *args, **kwargs)
        adg.__init__ = adg_init

    sys.argv = argv
    runpy.run_path(script, run_name='__main__')


def aead_substitutes(suite):
    """The TLS 1.2 suites scripts offer by default — CBC or GCM, with RSA,
    DHE or ECDHE-ECDSA key exchange — each mapped to the ECDHE-RSA AES-GCM
    suite of the same key size this service offers."""
    small = suite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    large = suite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    swap = {}
    for kex in ('RSA', 'DHE_RSA', 'ECDHE_RSA', 'ECDHE_ECDSA'):
        for bulk, target in (('AES_128_CBC_SHA', small),
                             ('AES_128_CBC_SHA256', small),
                             ('AES_256_CBC_SHA', large),
                             ('AES_256_CBC_SHA256', large),
                             ('AES_256_CBC_SHA384', large),
                             ('AES_128_GCM_SHA256', small),
                             ('AES_256_GCM_SHA384', large)):
            name = 'TLS_' + kex + '_WITH_' + bulk
            if hasattr(suite, name):
                swap[getattr(suite, name)] = target
    return swap


def graph_has(conversation, kind):
    seen = set()
    todo = [conversation]
    while todo:
        node = todo.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, kind):
            return True
        todo.append(getattr(node, 'child', None))
        todo.append(getattr(node, 'next_sibling', None))
    return False


if __name__ == '__main__':
    main()
