#!/usr/bin/env php
<?php

require __DIR__ . '/../vendor/autoload.php';

use BulkDomainChecker\BulkDomainChecker;

if ($argc < 2) {
    echo "Usage: php check_domains.php path/to/domains.txt\n";
    exit(1);
}

$file = $argv[1];
if (!is_readable($file)) {
    echo "Cannot read file: $file\n";
    exit(1);
}

$domains = array_map('trim', file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
$checker = new BulkDomainChecker();
$results = $checker->check($domains);

foreach ($results as $domain => $available) {
    $status = $available === true
        ? 'AVAILABLE'
        : ($available === false ? 'TAKEN' : 'UNKNOWN');
    echo sprintf("%-30s %s\n", $domain, $status);
}