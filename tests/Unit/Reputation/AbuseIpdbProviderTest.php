<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Reputation\AbuseIpdbProvider;
use Kanopi\Firewall\Reputation\HttpStatus;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The AbuseIPDB provider, as a provider (#204).
 *
 * The behaviour that reaches a request is covered by `AbuseIpdbTest` (the
 * rule's decisions) and `AbuseIpdbTransportTest` (the call itself). What is
 * left here is the contract: the identity it reports, the addresses it will
 * not spend quota on, and the words it puts in a log line -- which is the only
 * place a status code is ever shown to anybody.
 */
final class AbuseIpdbProviderTest extends AbstractTestCase
{
    /**
     * The name and slug are load-bearing, not decoration.
     *
     * The slug namespaces the verdict cache, and it is `abuseipdb` because
     * that is the prefix every file cached before 2.27.0 already has. Changing
     * it would orphan a day's worth of paid-for answers on upgrade.
     */
    public function testItIdentifiesItself(): void
    {
        $provider = new AbuseIpdbProvider(['api_key' => 'k']);

        $this->assertSame('AbuseIPDB', $provider->getName());
        $this->assertSame('abuseipdb', $provider->getSlug());
    }

    /**
     * No key is a reported problem, not a refusal to start.
     *
     * It is what lets the rule be added to a configuration before the key is
     * provisioned: the rule reports it once per request at debug and matches
     * nothing.
     */
    public function testAMissingKeyIsReportedRatherThanThrown(): void
    {
        $this->assertSame('no api_key configured', (new AbuseIpdbProvider())->getConfigurationProblem());
        $this->assertSame('no api_key configured', (new AbuseIpdbProvider(['api_key' => '  ']))->getConfigurationProblem());
        $this->assertNull((new AbuseIpdbProvider(['api_key' => 'k']))->getConfigurationProblem());
    }

    /**
     * Asked for a verdict without a key, it says so rather than calling.
     *
     * The rule asks `getConfigurationProblem()` first, so nothing reaches this
     * in practice. A provider is a public interface: somebody calling it
     * directly should get the answer, not a round trip that sends `Key: ` and
     * comes back 401.
     */
    public function testCheckingWithoutAKeyThrowsRatherThanCalling(): void
    {
        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/no api_key configured/');

        (new AbuseIpdbProvider())->check('203.0.113.5');
    }

    /**
     * Private and reserved space is never in the database.
     *
     * Looking it up spends quota to be told nothing, and the free tier is
     * 1,000 checks a day.
     */
    public function testItKnowsNothingAboutPrivateOrReservedSpace(): void
    {
        $provider = new AbuseIpdbProvider(['api_key' => 'k']);

        $this->assertTrue($provider->knowsAbout('203.0.113.5'));
        // A routable IPv6 address, deliberately not one from the documentation
        // range: PHP 8.1 counts `2001:db8::/32` as reserved and 8.4 does not,
        // so asserting on it would pin a difference between PHP versions
        // rather than anything about this provider.
        $this->assertTrue($provider->knowsAbout('2606:4700::1111'));
        $this->assertFalse($provider->knowsAbout('10.0.0.5'));
        $this->assertFalse($provider->knowsAbout('127.0.0.1'));
        $this->assertFalse($provider->knowsAbout('not-an-address'));
    }

    /**
     * A day for verdicts, five minutes for failures.
     *
     * The day is the quota; the five minutes is the difference between failing
     * open and making every request wait out a timeout while doing so.
     */
    public function testItsCacheLifetimesMatchItsQuota(): void
    {
        $provider = new AbuseIpdbProvider(['api_key' => 'k']);

        $this->assertSame(86400, $provider->getDefaultCacheTtl());
        $this->assertSame(300, $provider->getDefaultErrorCacheTtl());
    }

    /**
     * Failures are described in terms an operator can act on.
     *
     * "HTTP 429" is a fact; "the daily quota is exhausted" is the sentence that
     * stops somebody from spending an afternoon on it. This is the only place
     * a status code is ever shown.
     */
    public function testFailuresAreDescribedInTermsAnOperatorCanActOn(): void
    {
        $provider = new class (['api_key' => 'k']) extends AbuseIpdbProvider {
            public function exposedDescribeStatus(?int $status): string
            {
                return $this->describeStatus($status);
            }
        };

        $this->assertStringContainsString('API key', $provider->exposedDescribeStatus(401));
        $this->assertStringContainsString('quota', $provider->exposedDescribeStatus(429));
        $this->assertStringContainsString('invalid', $provider->exposedDescribeStatus(422));
        $this->assertStringContainsString('503', $provider->exposedDescribeStatus(503));
        $this->assertStringContainsString('no parseable status', $provider->exposedDescribeStatus(null));
    }

    /**
     * The status line is read out of what the stream wrapper hands back.
     *
     * A redirected response puts a status line per hop in `wrapper_data`; the
     * first is the one that matters. No status line at all is NULL rather than
     * an assumed 200, because assuming would turn a broken response into a
     * verdict.
     */
    public function testTheStatusLineIsReadFromWrapperHeaders(): void
    {
        $this->assertSame(200, HttpStatus::fromHeaders(['HTTP/1.1 200 OK', 'Content-Type: application/json']));
        $this->assertSame(429, HttpStatus::fromHeaders(['HTTP/2 429 Too Many Requests']));
        $this->assertNull(HttpStatus::fromHeaders(['Content-Type: application/json']));
        $this->assertNull(HttpStatus::fromHeaders([]));
    }
}
