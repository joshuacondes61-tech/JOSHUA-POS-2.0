<?php
declare(strict_types=1);
// Serve the POS frontend while allowing Wasmer's PHP runtime to execute the API.
$index = __DIR__ . '/index.html';
if (!is_file($index)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'POS frontend file is missing.';
    exit;
}
readfile($index);
