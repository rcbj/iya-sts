// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: Wss4jDriver.java
//
// ===========================================================================
// APACHE WSS4J, AS A COMMAND LINE (#1917, #1918): the independent peer a
// WS-Trust message this service signs or encrypts is held to, and the
// sender of requests it signs. One JSON request on standard input, one JSON
// answer on the last line of standard output. Two commands:
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
                              "verify".equals(args[0]))) {
      System.err.println("usage: wss4j-driver sign|verify < request.json");
      System.exit(2);
      return;
    }
    try {
      WSSConfig.init();
      JsonNode in = JSON.readTree(System.in);
      out = "sign".equals(args[0]) ? sign(in) : verify(in);
    } catch (Exception e) {
      out = JSON.createObjectNode();
      out.put("ok", false);
      out.put("message", e.getClass().getName() + ": " + e.getMessage());
    }
    System.out.println(out.toString());
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
