<?php
// GET ?as=sp|sp-artifact&idp=<entityID>[&forceAuthn=1][&isPassive=1]
// [&nameIdFormat=…]: start an SP-initiated sign-in at that identity
// provider, coming back to env.php.
require __DIR__ . '/_peer.php';

$source = peer_source();
$as = new \SimpleSAML\Auth\Simple($source);
$params = [
    'saml:idp' => (string) ($_GET['idp'] ?? ''),
    'ReturnTo' => '/peer/env.php?as=' . urlencode($source),
];
if (!empty($_GET['forceAuthn'])) {
    $params['ForceAuthn'] = true;
}
if (!empty($_GET['isPassive'])) {
    $params['isPassive'] = true;
    // Where an error status (NoPassive) lands, rather than on an unhandled
    // exception page.
    $params['ErrorURL'] = '/peer/env.php?as=' . urlencode($source) .
                          '&error=1';
}
if (!empty($_GET['nameIdFormat'])) {
    $params['saml:NameIDPolicy'] = ['Format' => (string) $_GET['nameIdFormat'],
                                   'AllowCreate' => true];
}
$as->login($params);
