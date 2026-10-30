// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

/*
 * KeycloakUmaDriver — a command line over keycloak-authz-client, Keycloak's
 * UMA 2.0 client and resource-server library, for tests/protocol/sts_uma.js
 * (#1196, rcbj's decision of 2026-10-30: Keycloak's library is the
 * independent peer, behind a path-rewriting proxy).
 *
 * The library is a LIBRARY, so something has to call it; this is that
 * something, kept as thin as a caller can be — jscep-driver's rule. Every
 * UMA message on the wire is built, sent and read by keycloak-authz-client:
 * the discovery document, the PAT it obtains, resource registration, the
 * permission endpoint, the uma-ticket grant and RPT introspection. What this
 * file adds is only what an application embedding the library supplies:
 *
 *   * its CONFIGURATION — the server URL, the realm name, the client and its
 *     secret. The library builds the discovery address from the realm name
 *     in Keycloak's layout, `<server>/realms/<realm>/.well-known/
 *     uma2-configuration`; the job points `server` at a loopback proxy of
 *     its own that answers that path with the realm's document, and every
 *     other request goes where the document says, to the service itself;
 *   * an HttpClient trusting the job's PEM bundle, for the service's TLS.
 *
 * One command per run. The request is ONE JSON object on stdin:
 *   { "server", "realm", "clientId", "secret", "trust" (a PEM file, or
 *     empty), ...the command's own members }
 * and the answer ONE JSON object on stdout: `{ "ok": true, ... }`, or
 * `{ "ok": false, "status", "body", "message" }` for an HTTP error the
 * library raised (the body as the server sent it).
 *
 *   discover                         the server configuration the library read
 *   pat                              obtainAccessToken(): client_credentials
 *   register   {pat?, name, scopes, type?}       ProtectedResource.create
 *   list       {pat?}                            ProtectedResource.findAll
 *   delete     {pat?, id}                        ProtectedResource.delete
 *   permission {pat?, resourceId, scopes}        PermissionResource.create
 *   authorize  {ticket, claimToken?, claimTokenFormat?, pct?, rpt?, scope?}
 *                                                AuthorizationResource.authorize
 *   introspect {rpt}                 introspectRequestingPartyToken (client
 *                                    authentication, Keycloak's way)
 *
 * With `pat` given, the protection API is called with that token
 * (`protection(String)`); without it the library obtains its own.
 * No key material is written by this program.
 */
package net.iyasec.sts.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.ServerConfiguration;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.authorization.client.resource.ProtectionResource;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionResponse;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

public final class KeycloakUmaDriver {
    private static final ObjectMapper JSON = new ObjectMapper();

    private KeycloakUmaDriver() {
    }

    public static void main(String[] args) {
        ObjectNode out;
        if (args.length != 1) {
            System.err.println("usage: keycloak-uma-driver <discover|pat|"
                + "register|list|delete|permission|authorize|introspect>"
                + " < request.json");
            System.exit(2);
            return;
        }
        try {
            JsonNode in = JSON.readTree(System.in);
            out = run(args[0], in);
        } catch (Throwable e) {
            out = failure(e);
        }
        try {
            System.out.println(JSON.writeValueAsString(out));
        } catch (Exception e) {
            System.out.println("{\"ok\":false,\"message\":\"unprintable\"}");
        }
        System.exit(0);
    }

    // An HTTP error the library raised, with the body the server sent; any
    // other failure by its message. The library wraps an HttpResponseException
    // in a RuntimeException ("Failed to obtain authorization data"), so the
    // cause chain is walked.
    private static ObjectNode failure(Throwable e) {
        ObjectNode out = JSON.createObjectNode();
        out.put("ok", false);
        out.put("message", String.valueOf(e.getMessage()));
        out.put("type", e.getClass().getName());
        Throwable at = e;
        while (at != null) {
            if (at instanceof HttpResponseException) {
                HttpResponseException h = (HttpResponseException) at;
                out.put("status", h.getStatusCode());
                byte[] bytes = h.getBytes();
                out.put("body", bytes == null ? ""
                    : new String(bytes, StandardCharsets.UTF_8));
                break;
            }
            at = at.getCause() == at ? null : at.getCause();
        }
        if (e instanceof AuthorizationDeniedException && !out.has("status")) {
            out.put("denied", true);
        }
        return out;
    }

    private static String text(JsonNode in, String name) {
        JsonNode v = in.get(name);
        return v == null || v.isNull() ? null : v.asText();
    }

    private static Set<String> strings(JsonNode in, String name) {
        Set<String> out = new HashSet<>();
        JsonNode v = in.get(name);
        if (v != null && v.isArray()) {
            for (JsonNode one : v) {
                out.add(one.asText());
            }
        }
        return out;
    }

    // An HttpClient that trusts the PEM bundle the job names (the service's
    // TLS anchors); the platform's own trust when none is named.
    private static HttpClient httpClient(String trust) throws Exception {
        if (trust == null || trust.isEmpty()) {
            return HttpClients.createDefault();
        }
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream pem = new FileInputStream(trust)) {
            Collection<? extends Certificate> certs =
                factory.generateCertificates(pem);
            int i = 0;
            for (Certificate c : certs) {
                store.setCertificateEntry("anchor-" + (i++), c);
            }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return HttpClients.custom().setSSLContext(context).build();
    }

    private static AuthzClient client(JsonNode in) throws Exception {
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("secret", text(in, "secret"));
        Configuration configuration = new Configuration(text(in, "server"),
            text(in, "realm"), text(in, "clientId"), credentials,
            httpClient(text(in, "trust")));
        return AuthzClient.create(configuration);
    }

    private static ProtectionResource protection(AuthzClient kc,
                                                 JsonNode in) {
        String pat = text(in, "pat");
        return pat == null || pat.isEmpty() ? kc.protection()
                                            : kc.protection(pat);
    }

    private static ObjectNode run(String command, JsonNode in)
            throws Exception {
        AuthzClient kc = client(in);
        ObjectNode out = JSON.createObjectNode();
        out.put("ok", true);
        switch (command) {
            case "discover": {
                ServerConfiguration c = kc.getServerConfiguration();
                out.set("configuration", JSON.valueToTree(c));
                return out;
            }
            case "pat": {
                AccessTokenResponse r = kc.obtainAccessToken();
                out.put("token", r.getToken());
                out.set("response", JSON.valueToTree(r));
                return out;
            }
            case "register": {
                ResourceRepresentation r = new ResourceRepresentation();
                r.setName(text(in, "name"));
                if (text(in, "type") != null) {
                    r.setType(text(in, "type"));
                }
                Set<ScopeRepresentation> scopes = new HashSet<>();
                for (String s : strings(in, "scopes")) {
                    scopes.add(new ScopeRepresentation(s));
                }
                r.setScopes(scopes);
                ResourceRepresentation made =
                    protection(kc, in).resource().create(r);
                out.put("id", made.getId());
                out.set("resource", JSON.valueToTree(made));
                return out;
            }
            case "list": {
                String[] ids = protection(kc, in).resource().findAll();
                ArrayNode list = out.putArray("ids");
                for (String id : ids) {
                    list.add(id);
                }
                return out;
            }
            case "delete": {
                protection(kc, in).resource().delete(text(in, "id"));
                return out;
            }
            case "permission": {
                PermissionRequest request = new PermissionRequest(
                    text(in, "resourceId"),
                    strings(in, "scopes").toArray(new String[0]));
                PermissionResponse r =
                    protection(kc, in).permission().create(request);
                out.put("ticket", r.getTicket());
                return out;
            }
            case "authorize": {
                AuthorizationRequest request = new AuthorizationRequest();
                request.setTicket(text(in, "ticket"));
                if (text(in, "claimToken") != null) {
                    request.setClaimToken(text(in, "claimToken"));
                    request.setClaimTokenFormat(
                        text(in, "claimTokenFormat"));
                }
                if (text(in, "pct") != null) {
                    request.setPct(text(in, "pct"));
                }
                if (text(in, "rpt") != null) {
                    request.setRpt(text(in, "rpt"));
                }
                if (text(in, "scope") != null) {
                    request.setScope(text(in, "scope"));
                }
                AuthorizationResponse r =
                    kc.authorization().authorize(request);
                out.put("token", r.getToken());
                out.put("upgraded", r.isUpgraded());
                out.set("response", JSON.valueToTree(r));
                return out;
            }
            case "introspect": {
                TokenIntrospectionResponse r = protection(kc, in)
                    .introspectRequestingPartyToken(text(in, "rpt"));
                out.put("active", r.getActive());
                List<?> permissions = r.getPermissions();
                out.set("permissions", JSON.valueToTree(permissions));
                out.set("response", JSON.valueToTree(r));
                return out;
            }
            default:
                throw new IllegalArgumentException("unknown command "
                    + command);
        }
    }
}
