<?php

use PHPUnit\Framework\TestCase;
use BulkDomainChecker\BulkDomainChecker;

class CheckDomainsTest extends TestCase
{
    public function testCanInstantiateChecker()
    {
        $checker = new BulkDomainChecker();
        $this->assertInstanceOf(BulkDomainChecker::class, $checker);
    }
}