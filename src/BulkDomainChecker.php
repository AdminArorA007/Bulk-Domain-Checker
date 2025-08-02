<?php

namespace BulkDomainChecker;

class BulkDomainChecker
{
    /**
     * Accepts an array of domain names and returns an associative
     * array mapping each domain to its availability (true/false).
     */
    public function check(array $domains): array
    {
        $results = [];
        foreach ($domains as $domain) {
            $results[$domain] = null; // placeholder
        }
        return $results;
    }
}