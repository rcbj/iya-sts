<?php
// What the four /peer pages share (#191): SimpleSAMLphp's bootstrap, and a
// JSON answer.
require_once '/var/simplesamlphp/public/_include.php';

function peer_answer(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

function peer_source(): string
{
    return 'sp';
}
