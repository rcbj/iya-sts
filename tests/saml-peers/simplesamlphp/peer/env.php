<?php
// GET ?as=…: the session this SP holds — its attributes, NameID, identity
// provider and session index — as JSON, or 401 when there is none.
require __DIR__ . '/_peer.php';

$as = new \SimpleSAML\Auth\Simple(peer_source());
if (!$as->isAuthenticated()) {
    peer_answer(401, ['authenticated' => false]);
    exit;
}
$nameId = $as->getAuthData('saml:sp:NameID');
// The saml2 library's NameID: getValue() in the one SimpleSAMLphp 2.5 uses,
// getContent() in the next.
$value = $nameId === null ? null
    : (method_exists($nameId, 'getValue') ? $nameId->getValue()
                                           : $nameId->getContent());
peer_answer(200, [
    'authenticated' => true,
    'idp' => $as->getAuthData('saml:sp:IdP'),
    'nameId' => $value,
    'nameIdFormat' => $nameId ? $nameId->getFormat() : null,
    'sessionIndex' => $as->getAuthData('saml:sp:SessionIndex'),
    'authnContext' => $as->getAuthData('saml:sp:AuthnContext'),
    'attributes' => $as->getAttributes(),
]);
