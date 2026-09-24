<?php
// POST {"idpMetadata": "<md:EntityDescriptor …>", "append": bool}: the
// identity provider this
// peer trusts, read by SimpleSAMLphp's own SAMLParser and its schema
// validation, and written where saml20-idp-remote.php loads it. The answer
// names the entity and whatever the validator said.
require __DIR__ . '/_peer.php';

$spec = json_decode(file_get_contents('php://input'), true) ?: [];
$xml = (string) ($spec['idpMetadata'] ?? '');
$problems = [];
try {
    (new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml, 'saml-meta');
    $valid = (new \SimpleSAML\Utils\XML())->isValid(
        $xml, 'saml-schema-metadata-2.0.xsd');
    if ($valid !== true) {
        $problems[] = 'schema: ' . $valid;
    }
    $file = '/var/simplesamlphp-peer/idp-remote.json';
    $out = (!empty($spec['append']) && is_file($file))
        ? (json_decode(file_get_contents($file), true) ?: []) : [];
    $added = [];
    foreach (\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml)
             as $entity) {
        $idp = $entity->getMetadata20IdP();
        if ($idp !== null) {
            $out[$idp['entityid']] = $idp;
            $added[] = $idp['entityid'];
        }
    }
    if (!$added) {
        $problems[] = 'no SAML 2.0 IDPSSODescriptor in the document';
    }
    file_put_contents($file, json_encode($out));
    peer_answer($problems ? 422 : 200, ['ok' => !$problems,
                                        'entities' => $added,
                                        'problems' => $problems]);
} catch (\Throwable $e) {
    \SimpleSAML\Logger::error('peer configure: ' . $e->getMessage());
    peer_answer(400, ['ok' => false, 'problems' => [$e->getMessage()]]);
}
