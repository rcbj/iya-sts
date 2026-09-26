/*
 * JscepDriver — a command line over jscep, the Java SCEP client library, for
 * tests/vendored/sts_scep_jscep.js (#250, 2026-09-26).
 *
 * jscep (com.google.code.jscep:jscep, MIT) is a LIBRARY, not a program, so
 * something has to call it. This is that something, and it is kept as thin as
 * a caller can be: every SCEP message on the wire is built, signed,
 * enveloped, sent, verified and opened by jscep and Bouncy Castle. What this
 * file adds is only what an application embedding jscep has to supply:
 *
 *   * the KEYS and the REQUEST, read from PEM files the job made with the
 *     `openssl` command at run time (nothing is generated here but the
 *     self-signed certificate RFC 8894 section 2.3 has a requester sign its
 *     first PKCSReq with, over the request's own key and subject);
 *   * a CertificateVerifier — jscep asks the application whether the CA it
 *     was handed by GetCACert is the right one. This one checks that the
 *     Issuing CA is signed by the realm Intermediate the job names, and that
 *     by the Root it names: the out-of-band check RFC 8894 section 2.2
 *     expects, rather than jscep's OptimisticCertificateVerifier;
 *   * for HTTPS, an SSLSocketFactory trusting the job's bundle;
 *   * for `--cipher` / `--sig`, the one place the driver goes below Client:
 *     jscep's Client always negotiates the strongest algorithm the server's
 *     GetCACaps offers, so to send a message with an algorithm the server
 *     does NOT offer (a refusal the job asserts) the driver builds jscep's
 *     own PkiMessageEncoder and EnrollmentTransaction with the named one —
 *     the same classes Client uses, with one argument chosen.
 *
 * Every command prints ONE JSON object on stdout; jscep's own log (slf4j,
 * slf4j-simple on stderr) is what the job reads for warnings and errors.
 * No key material is written by this program.
 *
 * Usage: java -jar jscep-driver.jar <command> --url=URL [--option=value]...
 *   caps                                  GetCACaps
 *   getca    --out=DIR                    GetCACert, each certificate a file
 *   nextca                                GetNextCACert through Client
 *   enroll   --csr= --key= [--identity= --identity-key=]
 *            [--cipher=AES|AES_128|AES_192|AES_256|DESede|DES]
 *            [--sig=SHA256withRSA|SHA512withRSA|SHA1withRSA] --out=
 *   poll     --csr= --key=                CertPoll for the request's
 *                                         transaction (jscep's own id)
 *   getcert  --identity= --key= --serial=HEX --out=
 *   getcrl   --identity= --key= --serial=HEX --out=
 * and on every command: --anchor=ROOT.pem --intermediate=INT.pem (the CA
 * check), --trust=BUNDLE.pem (HTTPS).
 */
package net.iyasec.sts.tests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportFactory;
import org.jscep.transport.UrlConnectionTransportFactory;
import org.jscep.transport.response.Capabilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class JscepDriver {
    private static final Logger LOG =
        LoggerFactory.getLogger("jscep-driver");

    private final Map<String, String> opts;
    private final Map<String, Object> out = new LinkedHashMap<>();

    private JscepDriver(final Map<String, String> opts) {
        this.opts = opts;
    }

    public static void main(final String[] args) {
        if (args.length < 1) {
            System.err.println("usage: jscep-driver <command> --url=...");
            System.exit(2);
        }
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--") || a.indexOf('=') < 0) {
                System.err.println("not an --option=value: " + a);
                System.exit(2);
            }
            opts.put(a.substring(2, a.indexOf('=')),
                     a.substring(a.indexOf('=') + 1));
        }
        java.security.Security.addProvider(new BouncyCastleProvider());
        JscepDriver d = new JscepDriver(opts);
        d.out.put("command", args[0]);
        int status = 0;
        try {
            d.run(args[0]);
        } catch (OperationFailureException e) {
            // A CertRep FAILURE to a GetCert or GetCRL: jscep throws it.
            d.out.put("ok", false);
            d.out.put("status", "FAILURE");
            d.out.put("failInfo", String.valueOf(e.getFailInfo()));
            status = 1;
        } catch (Exception e) {
            // Anything else jscep refused or failed on, named with its
            // causes, which is what the job asserts a refusal against.
            d.out.put("ok", false);
            d.out.put("exception", e.getClass().getName());
            StringBuilder why = new StringBuilder(String.valueOf(
                e.getMessage()));
            for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
                why.append(" <- ").append(c.getClass().getName())
                   .append(": ").append(c.getMessage());
            }
            d.out.put("message", why.toString());
            status = 1;
        }
        System.out.println(json(d.out));
        System.exit(status);
    }

    private String need(final String key) {
        String v = opts.get(key);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("--" + key + " is required");
        }
        return v;
    }

    private void run(final String command) throws Exception {
        Client client = client();
        switch (command) {
        case "caps":
            caps(client);
            break;
        case "getca":
            getca(client);
            break;
        case "nextca":
            CertStore next = client.getRolloverCertificate();
            out.put("ok", true);
            out.put("certificates", next.getCertificates(null).size());
            break;
        case "enroll":
            enroll(client);
            break;
        case "poll":
            poll(client);
            break;
        case "getcert":
            getcert(client);
            break;
        case "getcrl":
            getcrl(client);
            break;
        default:
            throw new IllegalArgumentException("no command " + command);
        }
    }

    // ---------------------------------------------------------------------
    // The Client, with the CA check and (for https) the trust bundle.
    // ---------------------------------------------------------------------
    private Client client() throws Exception {
        final X509Certificate anchor = opts.containsKey("anchor")
            ? readCertificate(opts.get("anchor")) : null;
        final X509Certificate intermediate = opts.containsKey("intermediate")
            ? readCertificate(opts.get("intermediate")) : null;
        CertificateVerifier verifier = new CertificateVerifier() {
            @Override
            public boolean verify(final X509Certificate ca) {
                if (anchor == null || intermediate == null) {
                    LOG.warn("No --anchor and --intermediate: the CA "
                             + "certificate is not checked.");
                    return true;
                }
                try {
                    ca.verify(intermediate.getPublicKey());
                    intermediate.verify(anchor.getPublicKey());
                    anchor.verify(anchor.getPublicKey());
                    ca.checkValidity();
                    LOG.info("The CA certificate {} chains to {}.",
                             ca.getSubjectX500Principal(),
                             anchor.getSubjectX500Principal());
                    return true;
                } catch (Exception e) {
                    LOG.error("The CA certificate {} does not chain to the "
                              + "anchor: {}", ca.getSubjectX500Principal(),
                              e.toString());
                    return false;
                }
            }
        };
        Client c = new Client(new URL(need("url")), verifier);
        if (opts.containsKey("trust")) {
            c.setTransportFactory(new UrlConnectionTransportFactory(
                socketFactory(opts.get("trust"))));
        }
        return c;
    }

    private static SSLSocketFactory socketFactory(final String bundle)
            throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        int n = 0;
        for (X509Certificate x : readCertificates(bundle)) {
            ks.setCertificateEntry("anchor-" + (n++), x);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx.getSocketFactory();
    }

    // ---------------------------------------------------------------------
    // The operations.
    // ---------------------------------------------------------------------
    private void caps(final Client client) {
        Capabilities caps = client.getCaCapabilities();
        out.put("ok", true);
        out.put("capabilities", caps.toString());
        out.put("post", caps.isPostSupported());
        out.put("renewal", caps.isRenewalSupported());
        out.put("rollover", caps.isRolloverSupported());
        out.put("cipher", caps.getStrongestCipher());
        out.put("digest", caps.getStrongestMessageDigest() == null ? null
                : caps.getStrongestMessageDigest().getAlgorithm());
        out.put("signature", caps.getStrongestSignatureAlgorithm());
    }

    private void getca(final Client client) throws Exception {
        CertStore store = client.getCaCertificate();
        File dir = new File(need("out"));
        dir.mkdirs();
        List<String> subjects = new ArrayList<>();
        int i = 0;
        for (Certificate c : store.getCertificates(null)) {
            X509Certificate x = (X509Certificate) c;
            writePem(new File(dir, "ca-" + (i++) + ".pem"), x);
            subjects.add(x.getSubjectX500Principal().getName());
        }
        CertStoreInspector inspector =
            new DefaultCertStoreInspectorFactory().getInstance(store);
        writePem(new File(dir, "recipient.pem"), inspector.getRecipient());
        writePem(new File(dir, "signer.pem"), inspector.getSigner());
        writePem(new File(dir, "issuer.pem"), inspector.getIssuer());
        out.put("ok", true);
        out.put("subjects", subjects);
        out.put("recipient",
                inspector.getRecipient().getSubjectX500Principal().getName());
        out.put("signer",
                inspector.getSigner().getSubjectX500Principal().getName());
        out.put("issuer",
                inspector.getIssuer().getSubjectX500Principal().getName());
    }

    private void enroll(final Client client) throws Exception {
        PKCS10CertificationRequest csr = readCsr(need("csr"));
        PrivateKey requestKey = readKey(need("key"));
        X509Certificate identity;
        PrivateKey identityKey;
        if (opts.containsKey("identity")) {
            // A renewal: signed by the certificate being renewed, over its
            // key — RFC 8894 section 2.3's second case, sent (as jscep does)
            // as a PKCSReq.
            identity = readCertificate(opts.get("identity"));
            identityKey = readKey(need("identity-key"));
        } else {
            identity = selfSigned(csr, requestKey);
            identityKey = requestKey;
        }
        EnrollmentResponse r;
        if (opts.containsKey("cipher") || opts.containsKey("sig")) {
            r = enrollWith(client, identity, identityKey, csr);
        } else {
            r = client.enrol(identity, identityKey, csr);
        }
        answer(r);
    }

    // jscep's Client, one argument chosen: the same encoder, decoder and
    // transaction classes Client.enrol() builds, with the cipher and the
    // signature algorithm the job names instead of the strongest the server
    // offers.
    private EnrollmentResponse enrollWith(final Client client,
            final X509Certificate identity, final PrivateKey key,
            final PKCS10CertificationRequest csr) throws Exception {
        Capabilities caps = client.getCaCapabilities();
        CertStore store = client.getCaCertificate();
        CertStoreInspector certs =
            new DefaultCertStoreInspectorFactory().getInstance(store);
        String cipher = opts.getOrDefault("cipher", caps.getStrongestCipher());
        String sig = opts.getOrDefault("sig",
                                       caps.getStrongestSignatureAlgorithm());
        out.put("cipher", cipher);
        out.put("signature", sig);
        PkcsPkiEnvelopeEncoder envelope =
            new PkcsPkiEnvelopeEncoder(certs.getRecipient(), cipher);
        PkiMessageEncoder encoder =
            new PkiMessageEncoder(key, identity, envelope, sig);
        PkiMessageDecoder decoder = new PkiMessageDecoder(certs.getSigner(),
            new PkcsPkiEnvelopeDecoder(identity, key));
        Transport transport = new UrlConnectionTransportFactory(
            opts.containsKey("trust") ? socketFactory(opts.get("trust"))
                                      : null)
            .forMethod(caps.isPostSupported() ? TransportFactory.Method.POST
                                              : TransportFactory.Method.GET,
                       new URL(need("url")));
        EnrollmentTransaction t =
            new EnrollmentTransaction(transport, encoder, decoder, csr);
        Transaction.State s = t.send();
        if (s == Transaction.State.CERT_ISSUED) {
            return new EnrollmentResponse(t.getId(), t.getCertStore());
        } else if (s == Transaction.State.CERT_REQ_PENDING) {
            return new EnrollmentResponse(t.getId());
        }
        return new EnrollmentResponse(t.getId(), t.getFailInfo());
    }

    private void poll(final Client client) throws Exception {
        PKCS10CertificationRequest csr = readCsr(need("csr"));
        PrivateKey key = readKey(need("key"));
        X509Certificate identity = selfSigned(csr, key);
        PublicKey pub = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        // The transactionID jscep gave the PKCSReq for this request: the
        // SHA-1 of its public key (EnrollmentTransaction's own rule).
        TransactionId id = TransactionId.createTransactionId(pub, "SHA-1");
        X500Principal subject =
            new X500Principal(csr.getSubject().getEncoded());
        answer(client.poll(identity, key, subject, id));
    }

    private void getcert(final Client client) throws Exception {
        X509Certificate identity = readCertificate(need("identity"));
        PrivateKey key = readKey(need("key"));
        CertStore store = client.getCertificate(identity, key,
            new BigInteger(need("serial"), 16));
        Collection<? extends Certificate> got = store.getCertificates(null);
        out.put("ok", !got.isEmpty());
        out.put("status", "SUCCESS");
        if (!got.isEmpty()) {
            X509Certificate x = (X509Certificate) got.iterator().next();
            writePem(new File(need("out")), x);
            out.put("serial", x.getSerialNumber().toString(16));
        }
    }

    private void getcrl(final Client client) throws Exception {
        X509Certificate identity = readCertificate(need("identity"));
        PrivateKey key = readKey(need("key"));
        CertStore store = client.getCaCertificate();
        X509Certificate issuer =
            new DefaultCertStoreInspectorFactory().getInstance(store)
                .getIssuer();
        X509CRL crl = client.getRevocationList(identity, key,
            issuer.getSubjectX500Principal(),
            new BigInteger(need("serial"), 16));
        Files.write(new File(need("out")).toPath(), crl.getEncoded());
        out.put("ok", true);
        out.put("status", "SUCCESS");
        out.put("issuer", crl.getIssuerX500Principal().getName());
        out.put("revoked", crl.getRevokedCertificates() == null ? 0
                : crl.getRevokedCertificates().size());
    }

    private void answer(final EnrollmentResponse r) throws Exception {
        out.put("transactionId", String.valueOf(r.getTransactionId()));
        if (r.isSuccess()) {
            X509Certificate leaf = null;
            List<String> subjects = new ArrayList<>();
            StringWriter all = new StringWriter();
            try (JcaPEMWriter w = new JcaPEMWriter(all)) {
                for (Certificate c : r.getCertStore().getCertificates(null)) {
                    X509Certificate x = (X509Certificate) c;
                    subjects.add(x.getSubjectX500Principal().getName());
                    w.writeObject(x);
                    if (x.getBasicConstraints() < 0 && leaf == null) {
                        leaf = x;
                    }
                }
            }
            if (opts.containsKey("out")) {
                try (Writer w = new FileWriter(need("out"),
                                               StandardCharsets.UTF_8)) {
                    w.write(all.toString());
                }
            }
            out.put("ok", true);
            out.put("status", "SUCCESS");
            out.put("subjects", subjects);
            out.put("serial", leaf == null ? null
                    : leaf.getSerialNumber().toString(16));
        } else if (r.isPending()) {
            out.put("ok", false);
            out.put("status", "PENDING");
        } else {
            FailInfo f = r.getFailInfo();
            out.put("ok", false);
            out.put("status", "FAILURE");
            out.put("failInfo", String.valueOf(f));
        }
    }

    // ---------------------------------------------------------------------
    // PEM, and the self-signed certificate of RFC 8894 section 2.3.
    // ---------------------------------------------------------------------
    private static X509Certificate selfSigned(
            final PKCS10CertificationRequest csr, final PrivateKey key)
            throws Exception {
        PublicKey pub = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        Date now = new Date();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            new X500Principal(csr.getSubject().getEncoded()),
            BigInteger.valueOf(now.getTime()),
            new Date(now.getTime() - 60000L),
            new Date(now.getTime() + 86400000L),
            new X500Principal(csr.getSubject().getEncoded()), pub);
        // RFC 8894 section 2.3: digitalSignature and keyEncipherment.
        b.addExtension(Extension.keyUsage, true, new KeyUsage(
            KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        b.addExtension(Extension.basicConstraints, true,
                       new BasicConstraints(false));
        ContentSigner signer =
            new JcaContentSignerBuilder("SHA256withRSA").build(key);
        return new JcaX509CertificateConverter()
            .getCertificate(b.build(signer));
    }

    private static PKCS10CertificationRequest readCsr(final String file)
            throws Exception {
        try (Reader r = new FileReader(file, StandardCharsets.UTF_8);
             PEMParser p = new PEMParser(r)) {
            return (PKCS10CertificationRequest) p.readObject();
        }
    }

    private static PrivateKey readKey(final String file) throws Exception {
        try (Reader r = new FileReader(file, StandardCharsets.UTF_8);
             PEMParser p = new PEMParser(r)) {
            Object o = p.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter();
            if (o instanceof PEMKeyPair) {
                return conv.getKeyPair((PEMKeyPair) o).getPrivate();
            }
            return conv.getPrivateKey((PrivateKeyInfo) o);
        }
    }

    private static X509Certificate readCertificate(final String file)
            throws Exception {
        List<X509Certificate> all = readCertificates(file);
        if (all.isEmpty()) {
            throw new IllegalArgumentException("no certificate in " + file);
        }
        return all.get(0);
    }

    private static List<X509Certificate> readCertificates(final String file)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> list = new ArrayList<>();
        try (InputStream in = new FileInputStream(file)) {
            for (Certificate c : cf.generateCertificates(in)) {
                list.add((X509Certificate) c);
            }
        }
        return list;
    }

    private static void writePem(final File f, final X509Certificate x)
            throws Exception {
        try (JcaPEMWriter w = new JcaPEMWriter(
                 new FileWriter(f, StandardCharsets.UTF_8))) {
            w.writeObject(x);
        }
    }

    // ---------------------------------------------------------------------
    // One JSON object: strings, booleans, numbers, null and lists of
    // strings are all this program ever prints.
    // ---------------------------------------------------------------------
    private static String json(final Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof Boolean || o instanceof Number) {
            return o.toString();
        }
        if (o instanceof Map) {
            StringBuilder b = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                b.append(json(String.valueOf(e.getKey()))).append(':')
                 .append(json(e.getValue()));
            }
            return b.append('}').toString();
        }
        if (o instanceof List) {
            StringBuilder b = new StringBuilder("[");
            boolean first = true;
            for (Object v : (List<?>) o) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                b.append(json(v));
            }
            return b.append(']').toString();
        }
        String s = o.toString();
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
