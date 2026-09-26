<?php
// THE SIMPLESAMLPHP PEER'S CONFIGURATION (#191): the release's own
// config.php.dist, with what an interoperability run needs laid over it.
// The per-start values (the secret salt, the admin password, the host) are in
// /var/simplesamlphp-peer/peer.json, which entrypoint.sh writes, so no secret
// is in the image or in git.
require __DIR__ . '/config.php.dist';
$peer = json_decode(file_get_contents('/var/simplesamlphp-peer/peer.json'),
                    true);
$config = array_merge($config, [
    'baseurlpath' => 'http://' . $peer['host'] . '/simplesaml/',
    'secretsalt' => $peer['secretsalt'],
    'auth.adminpassword' => $peer['adminpassword'],
    'technicalcontact_email' => 'root@localhost',
    'timezone' => 'UTC',
    // The harness's error-and-warning source: every line at INFO and above,
    // to a file the job reads.
    'logging.level' => SimpleSAML\Logger::INFO,
    'logging.handler' => 'file',
    'loggingdir' => '/run/saml-peer-log/',
    'logging.logfile' => 'simplesamlphp.log',
    'tempdir' => '/var/simplesamlphp-peer/tmp',
    'cachedir' => '/var/simplesamlphp-peer/cache',
    'certdir' => '/var/simplesamlphp-peer/cert/',
    // SimpleSAMLphp's schema validation of every SAML message and metadata
    // document it receives; a failure is logged at WARNING.
    'debug' => ['saml' => false, 'backtraces' => true, 'validatexml' => true],
    // Plain HTTP on the suite's private bridge.
    'session.cookie.secure' => false,
    'session.cookie.samesite' => 'Lax',
    'store.type' => 'phpsession',
]);
