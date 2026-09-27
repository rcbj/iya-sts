<?php
// THE SIMPLESAMLPHP PEER'S SERVICE PROVIDER (#191): one `saml:SP` auth
// source. It signs its AuthnRequests and logout messages — what a
// product-mode realm requires — and insists on an encrypted, signed
// assertion, to the key its metadata publishes.
//
// THERE IS NO ARTIFACT SOURCE, and that is SimpleSAMLphp's limit rather than
// this harness's: an SP whose ProtocolBinding asks for HTTP-Artifact sends
// its AuthnRequest over the HTTP-Artifact binding itself (SP.php picks the
// identity provider's HTTP-Artifact SingleSignOnService), and publishes no
// ArtifactResolutionService at which an identity provider could resolve it,
// so the artifact profile cannot be reached from a SimpleSAMLphp SP at all.
// Recorded on #191; the artifact Response is Shibboleth's, pysaml2's and
// Keycloak's to cover.
$peer = json_decode(file_get_contents('/var/simplesamlphp-peer/peer.json'),
                    true);
$base = 'http://' . $peer['host'];
$common = [
    'saml:SP',
    'privatekey' => 'sp.key',
    'certificate' => 'sp.crt',
    'sign.authnrequest' => true,
    'sign.logout' => true,
    'redirect.sign' => true,
    'assertion.encryption' => true,
    'WantAssertionsSigned' => true,
    'idp' => null,
    'discoURL' => null,
];
$config = [
    'admin' => ['core:AdminPassword'],
    'sp' => ['entityID' => $base . '/sp'] + $common,
];
