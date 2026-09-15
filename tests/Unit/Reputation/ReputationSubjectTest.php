<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

use Kanopi\Firewall\Reputation\ReputationSubject;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The thing being asked about (#341).
 *
 * Small class, and most of it is one decision: what a firewall is allowed to
 * write down about a subject that is not an address.
 */
final class ReputationSubjectTest extends AbstractTestCase
{
    /**
     * The default subject is the one every rule before 2.28.0 asked about.
     */
    public function testTheDefaultKindIsTheClientAddress(): void
    {
        $subject = new ReputationSubject('203.0.113.5');

        $this->assertSame('client_ip', $subject->kind);
        $this->assertTrue($subject->isAddress());
        $this->assertFalse($subject->hashed);
    }

    /**
     * Anything else is not an address, which is what a provider checks.
     */
    public function testAnyOtherKindIsNotAnAddress(): void
    {
        $this->assertFalse((new ReputationSubject('alice@example.com', 'post.email'))->isAddress());
    }

    /**
     * An email address never reaches a log line.
     *
     * The test that matters here. A firewall writes log records on every
     * request, and an email address or a username in one of them is a
     * disclosure that outlives the request by however long the logs are kept.
     * The digest is there so two entries can be correlated without the value.
     */
    public function testDescribingASubjectDoesNotDiscloseIt(): void
    {
        $described = (new ReputationSubject('alice@example.com', 'post.email'))->describe();

        $this->assertStringNotContainsString('alice@example.com', $described);
        $this->assertStringNotContainsString('alice', $described);
        $this->assertStringContainsString('post.email', $described);
    }

    /**
     * The digest is stable, or it correlates nothing.
     */
    public function testTheDigestIsStableForTheSameValue(): void
    {
        $first = (new ReputationSubject('alice@example.com', 'post.email'))->describe();
        $second = (new ReputationSubject('alice@example.com', 'post.email'))->describe();
        $other = (new ReputationSubject('bob@example.com', 'post.email'))->describe();

        $this->assertSame($first, $second);
        $this->assertNotSame($first, $other);
    }

    /**
     * An address is written out, because it is the one subject an operator acts on.
     *
     * Blocking an address, looking it up, asking a provider about it by hand --
     * all of that needs the address, and it is already in the log context under
     * its own key.
     */
    public function testAnAddressIsWrittenOut(): void
    {
        $this->assertSame('client_ip 203.0.113.5', (new ReputationSubject('203.0.113.5'))->describe());
    }

    /**
     * A hashed subject says so, because "we sent a digest" is worth knowing.
     */
    public function testAHashedSubjectSaysSo(): void
    {
        $described = (new ReputationSubject('abc123', 'post.email', true))->describe();

        $this->assertStringContainsString('(hashed)', $described);
    }

    /**
     * The slug is a filename fragment, so it has to be one.
     */
    public function testTheSlugIsFilesystemSafe(): void
    {
        $this->assertSame('post-email', (new ReputationSubject('x', 'post.email'))->slug());
        $this->assertSame('header-x-api-key', (new ReputationSubject('x', 'header.X-Api-Key'))->slug());
    }
}
