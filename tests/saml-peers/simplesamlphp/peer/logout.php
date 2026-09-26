<?php
// GET ?as=…&return=<url>: SP-initiated Single Logout — SimpleSAMLphp sends
// the identity provider a LogoutRequest and comes back to `return`.
require __DIR__ . '/_peer.php';

$as = new \SimpleSAML\Auth\Simple(peer_source());
$as->logout(['ReturnTo' => (string) ($_GET['return'] ?? '/peer/env.php')]);
