// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: Wss4jDriver.java
//
// ===========================================================================
// APACHE WSS4J, AS A COMMAND LINE (#1917, #1918): the independent peer a
// WS-Trust message this service signs or encrypts is held to, and the
// sender of requests it signs and encrypts. One JSON request on standard
// input, one JSON answer on the last line of standard output. Four
// commands:
//
//   sign     a SOAP envelope signed the way a WSS4J client signs one: a
//            wsu:Timestamp, a BinarySecurityToken holding `certPem`
//            (BST_DIRECT_REFERENCE), and a ds:Signature with `keyPem` over
//            the Body, the Timestamp and each of `parts` ({local, ns}),
//            RSA-SHA256, SHA-256 digests, exclusive c14n — WSS4J's own
//            InclusiveNamespaces PrefixList included, unless
//            `inclusivePrefixes` is false. Answers { ok, xml }.
//   verify   WSSecurityEngine.processSecurityHeader() over `xml`, in the
//            header's order, with a truststore of `trustPems` (direct trust
//            in the certificate this service publishes) and, for
//            decryption, `recipientKeyPem` with `recipientCertPem`. The
//            Basic Security Profile is enforced, as WSS4J does by default.
//            Answers { ok, actions: [{ action, refs: [{ name, wsuId }],
//            certificate }] } in the order WSS4J processed them, or
//            { ok: false, message }.
//   protect  (#2046) a SOAP envelope signed and/or encrypted the way a WSS4J
//            client protects a request, each part named rather than
//            implied: `sign` ({ certPem, keyPem, parts }) signs a
//            wsu:Timestamp and each part as `sign` does, with no Body unless
//            a part names it; `encrypt` ({ certPem, parts, keyIdentifier })
//            encrypts each part to `certPem` — `Content` for an element's
//            children (the SOAP Body's), `Element` for the element, `Header`
//            for a header block as a wsse11:EncryptedHeader — with
//            AES-256-GCM and XML Encryption 1.1's RSA-OAEP over SHA-256
//            (`keyTransport` "rsa-oaep-mgf1p" for OAEP over SHA-1), the
//            recipient named by
//            `keyIdentifier` (IssuerSerial, the default; DirectReference;
//            SKI; Thumbprint). `order` is sign-then-encrypt (the default)
//            or encrypt-then-sign. A part `{ local: "Body" }` with no `ns`
//            is the envelope's own Body. Answers { ok, xml }.
//   batch    (#2046) { items: [{ command, ... }] }, each run as above in one
//            process, so hundreds of messages cost one start of the JVM.
//            Answers { ok, results } in order, a failed item its own
//            { ok: false, message }.
//
// Everything a check needs is in the answer: the job, not this file,
// decides what a pass is. Nothing here holds a key: each comes in the
// request, made by the job at run time.
// ===========================================================================

package net.iyasec.sts.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.w3c.dom.Document;

public final class Wss4jDriver {
  private static final ObjectMapper JSON = new ObjectMapper();
  // The one password of the in-memory keystore, never a credential: the
  // keys arrive in the request and the store dies with the process.
  private static final String PASSWORD = "wss4j-driver";

  private Wss4jDriver() {
  }

  public static void main(String[] args) {
    ObjectNode out;
    if (args.length != 1 || !("sign".equals(args[0]) ||
                              "verify".equals(args[0]) ||
                              "protect".equals(args[0]) ||
                              "batch".equals(args[0]))) {
      System.err.println(
        "usage: wss4j-driver sign|verify|protect|batch < request.json");
      System.exit(2);
      return;
    }
    try {
      WSSConfig.init();
      JsonNode in = JSON.readTree(System.in);
      if ("batch".equals(args[0])) {
        out = JSON.createObjectNode();
        out.put("ok", true);
        ArrayNode results = out.putArray("results");
        for (JsonNode item : in.path("items")) {
          results.add(one(item.path("command").asText(), item));
        }
      } else {
        out = one(args[0], in);
      }
    } catch (Exception e) {
      out = failure(e);
    }
    System.out.println(out.toString());
  }

  // One command, its failure its own answer, so one bad item in a batch
  // costs only itself.
  private static ObjectNode one(String command, JsonNode in) {
    try {
      if ("sign".equals(command)) {
        return sign(in);
      }
      if ("verify".equals(command)) {
        return verify(in);
      }
      if ("protect".equals(command)) {
        return protect(in);
      }
      throw new IllegalArgumentException("unknown command " + command);
    } catch (Exception e) {
      return failure(e);
    }
  }

  private static ObjectNode failure(Exception e) {
    ObjectNode out = JSON.createObjectNode();
    out.put("ok", false);
    out.put("message", e.getClass().getName() + ": " + e.getMessage());
    return out;
  }

  private static ObjectNode protect(JsonNode in) throws Exception {
    Document doc = parse(in.path("xml").asText());
    String soapNs = doc.getDocumentElement().getNamespaceURI();
    KeyStore store = emptyStore();
    JsonNode signing = in.path("sign");
    JsonNode sealing = in.path("encrypt");
    boolean signs = signing.isObject();
    boolean seals = sealing.isObject();
    if (signs) {
      store.setKeyEntry("signer",
        privateKey(signing.path("keyPem").asText()), PASSWORD.toCharArray(),
        new Certificate[] { certificate(signing.path("certPem").asText()) });
    }
    if (seals) {
      store.setCertificateEntry("recipient",
                                certificate(sealing.path("certPem").asText()));
    }
    Merlin crypto = crypto(store);
    WSSecHeader header = new WSSecHeader(doc);
    header.insertSecurityHeader();
    boolean encryptFirst = "encrypt-then-sign".equals(
      in.path("order").asText("sign-then-encrypt"));
    if (seals && encryptFirst) {
      encrypt(header, crypto, sealing, soapNs);
    }
    if (signs) {
      WSSecTimestamp timestamp = new WSSecTimestamp(header);
      timestamp.setTimeToLive(300);
      timestamp.build();
      WSSecSignature signature = new WSSecSignature(header);
      signature.setUserInfo("signer", PASSWORD);
      signature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
      signature.setSignatureAlgorithm(WSS4JConstants.RSA_SHA256);
      signature.setDigestAlgo(WSS4JConstants.SHA256);
      signature.setSigCanonicalization(
        WSS4JConstants.C14N_EXCL_OMIT_COMMENTS);
      signature.getParts().add(new WSEncryptionPart(
        WSS4JConstants.TIMESTAMP_TOKEN_LN, WSS4JConstants.WSU_NS, ""));
      for (JsonNode part : signing.path("parts")) {
        signature.getParts().add(new WSEncryptionPart(
          part.path("local").asText(), part.path("ns").asText(soapNs),
          "Element"));
      }
      signature.build(crypto);
    }
    if (seals && !encryptFirst) {
      encrypt(header, crypto, sealing, soapNs);
    }
    ObjectNode out = JSON.createObjectNode();
    out.put("ok", true);
    out.put("xml", serialise(doc));
    return out;
  }

  private static void encrypt(WSSecHeader header, Merlin crypto,
                              JsonNode sealing, String soapNs)
      throws Exception {
    WSSecEncrypt encrypt = new WSSecEncrypt(header);
    encrypt.setUserInfo("recipient");
    String named = sealing.path("keyIdentifier").asText("IssuerSerial");
    int identifier = WSConstants.ISSUER_SERIAL;
    if ("DirectReference".equals(named)) {
      identifier = WSConstants.BST_DIRECT_REFERENCE;
    } else if ("SKI".equals(named)) {
      identifier = WSConstants.SKI_KEY_IDENTIFIER;
    } else if ("Thumbprint".equals(named)) {
      identifier = WSConstants.THUMBPRINT_IDENTIFIER;
    } else if (!"IssuerSerial".equals(named)) {
      throw new IllegalArgumentException("unknown keyIdentifier " + named);
    }
    encrypt.setKeyIdentifierType(identifier);
    encrypt.setSymmetricEncAlgorithm(WSS4JConstants.AES_256_GCM);
    // THE KEY TRANSPORT: XML Encryption 1.1's rsa-oaep with SHA-256 and
    // MGF1-SHA-256 unless asked for WSS4J's default, rsa-oaep-mgf1p (OAEP
    // over SHA-1), which a realm refuses to unwrap by default.
    if ("rsa-oaep-mgf1p".equals(
          sealing.path("keyTransport").asText("rsa-oaep"))) {
      encrypt.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_RSAOAEP);
    } else {
      encrypt.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_RSAOAEP_XENC11);
      encrypt.setDigestAlgorithm(WSS4JConstants.SHA256);
      encrypt.setMGFAlgorithm(WSS4JConstants.MGF_SHA256);
    }
    for (JsonNode part : sealing.path("parts")) {
      encrypt.getParts().add(new WSEncryptionPart(
        part.path("local").asText(), part.path("ns").asText(soapNs),
        part.path("mode").asText("Element")));
    }
    KeyGenerator generator =
      KeyUtils.getKeyGenerator(WSS4JConstants.AES_256_GCM);
    SecretKey key = generator.generateKey();
    encrypt.build(crypto, key);
  }

  private static ObjectNode sign(JsonNode in) throws Exception {
    Document doc = parse(in.path("xml").asText());
    X509Certificate cert = certificate(in.path("certPem").asText());
    PrivateKey key = privateKey(in.path("keyPem").asText());
    KeyStore store = emptyStore();
    store.setKeyEntry("signer", key, PASSWORD.toCharArray(),
                      new Certificate[] { cert });
    Merlin crypto = crypto(store);

    WSSecHeader header = new WSSecHeader(doc);
    header.insertSecurityHeader();
    WSSecTimestamp timestamp = new WSSecTimestamp(header);
    timestamp.setTimeToLive(300);
    timestamp.build();

    WSSecSignature signature = new WSSecSignature(header);
    signature.setUserInfo("signer", PASSWORD);
    signature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
    signature.setSignatureAlgorithm(WSS4JConstants.RSA_SHA256);
    signature.setDigestAlgo(WSS4JConstants.SHA256);
    signature.setSigCanonicalization(WSS4JConstants.C14N_EXCL_OMIT_COMMENTS);
    signature.setAddInclusivePrefixes(
      in.path("inclusivePrefixes").asBoolean(true));
    String soapNs = doc.getDocumentElement().getNamespaceURI();
    signature.getParts().add(new WSEncryptionPart("Body", soapNs, ""));
    signature.getParts().add(new WSEncryptionPart(
      WSS4JConstants.TIMESTAMP_TOKEN_LN, WSS4JConstants.WSU_NS, ""));
    for (JsonNode part : in.path("parts")) {
      signature.getParts().add(new WSEncryptionPart(
        part.path("local").asText(), part.path("ns").asText(), "Element"));
    }
    signature.build(crypto);

    ObjectNode out = JSON.createObjectNode();
    out.put("ok", true);
    out.put("xml", serialise(doc));
    return out;
  }

  private static ObjectNode verify(JsonNode in) throws Exception {
    Document doc = parse(in.path("xml").asText());
    KeyStore store = emptyStore();
    int n = 0;
    for (JsonNode pem : in.path("trustPems")) {
      store.setCertificateEntry("trusted-" + n, certificate(pem.asText()));
      n += 1;
    }
    if (in.hasNonNull("recipientKeyPem")) {
      store.setKeyEntry("recipient",
        privateKey(in.path("recipientKeyPem").asText()),
        PASSWORD.toCharArray(), new Certificate[] {
          certificate(in.path("recipientCertPem").asText()) });
    }
    Merlin crypto = crypto(store);

    RequestData data = new RequestData();
    data.setWssConfig(WSSConfig.getNewInstance());
    data.setSigVerCrypto(crypto);
    data.setDecCrypto(crypto);
    data.setCallbackHandler(new CallbackHandler() {
      @Override
      public void handle(Callback[] callbacks) {
        for (Callback one : callbacks) {
          if (one instanceof WSPasswordCallback) {
            ((WSPasswordCallback) one).setPassword(PASSWORD);
          }
        }
      }
    });
    WSHandlerResult results =
      new WSSecurityEngine().processSecurityHeader(doc, data);

    ObjectNode out = JSON.createObjectNode();
    out.put("ok", true);
    ArrayNode actions = out.putArray("actions");
    if (results != null) {
      // WSS4J lists its results newest first; the answer is in the order
      // the header was processed.
      List<WSSecurityEngineResult> processed =
        new java.util.ArrayList<>(results.getResults());
      java.util.Collections.reverse(processed);
      for (WSSecurityEngineResult result : processed) {
        ObjectNode one = actions.addObject();
        int action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
        one.put("action", actionName(action));
        ArrayNode refs = one.putArray("refs");
        Object listed = result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        if (listed instanceof List) {
          for (Object ref : (List<?>) listed) {
            WSDataRef dataRef = (WSDataRef) ref;
            ObjectNode r = refs.addObject();
            r.put("name", String.valueOf(dataRef.getName()));
            r.put("wsuId", String.valueOf(dataRef.getWsuId()));
          }
        }
        Object cert = result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        if (cert instanceof X509Certificate) {
          one.put("certificate", Base64.getEncoder().encodeToString(
            ((X509Certificate) cert).getEncoded()));
        }
      }
    }
    // The document as WSS4J left it: decrypted in place.
    out.put("xml", serialise(doc));
    return out;
  }

  private static String actionName(int action) {
    if (action == WSConstants.SIGN) {
      return "signature";
    }
    if (action == WSConstants.ENCR) {
      return "encryption";
    }
    if (action == WSConstants.TS) {
      return "timestamp";
    }
    if (action == WSConstants.BST) {
      return "token";
    }
    return "action-" + action;
  }

  private static Merlin crypto(KeyStore store) {
    Merlin crypto = new Merlin();
    crypto.setKeyStore(store);
    crypto.setTrustStore(store);
    return crypto;
  }

  private static KeyStore emptyStore() throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    return store;
  }

  private static X509Certificate certificate(String pem) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(
        pem.getBytes(StandardCharsets.US_ASCII)));
  }

  // A PKCS#8 PEM ("BEGIN PRIVATE KEY"), RSA or EC.
  private static PrivateKey privateKey(String pem) throws Exception {
    byte[] der = Base64.getMimeDecoder().decode(
      pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", ""));
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    try {
      return KeyFactory.getInstance("RSA").generatePrivate(spec);
    } catch (java.security.spec.InvalidKeySpecException e) {
      return KeyFactory.getInstance("EC").generatePrivate(spec);
    }
  }

  private static Document parse(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature(
      "http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new ByteArrayInputStream(
      xml.getBytes(StandardCharsets.UTF_8)));
  }

  private static String serialise(Document doc) throws Exception {
    Transformer transformer = TransformerFactory.newInstance()
      .newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(doc), new StreamResult(writer));
    return writer.toString();
  }
}
