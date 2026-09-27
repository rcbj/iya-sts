<?php
// The identity provider(s) this peer trusts: what /peer/configure.php parsed
// from the metadata the job handed it, with SimpleSAMLphp's own SAMLParser.
$f = '/var/simplesamlphp-peer/idp-remote.json';
$metadata = is_file($f) ? json_decode(file_get_contents($f), true) : [];
