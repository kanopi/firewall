<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Reputation\AbuseIpdbProvider;
use Kanopi\Firewall\Reputation\HttpReputationProvider;
use Kanopi\Firewall\Reputation\ReputationProviderFactory;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Resolving a provider name (#204).
 *
 * The load-bearing half is what happens to a name that resolves to nothing.
 * A silent fallback would leave a block rule matching nothing, which looks
 * exactly like a working rule finding nothing -- the failure mode the linter
 * and the rule diagnostics exist to stamp out.
 */
final class ReputationProviderFactoryTest extends AbstractTestCase
{
    /**
     * The built-in short names resolve.
     */
    public function testShortNamesResolveToTheFirstPartyProviders(): void
    {
        $this->assertInstanceOf(
            AbuseIpdbProvider::class,
            ReputationProviderFactory::create('abuseipdb', ['api_key' => 'k'])
        );

        $this->assertInstanceOf(
            HttpReputationProvider::class,
            ReputationProviderFactory::create('http', [
                'url' => 'https://example.com/?ip={ip}',
                'score_path' => 'score',
            ])
        );
    }

    /**
     * A class of one's own works, if it is a provider.
     */
    public function testAFullyQualifiedClassNameResolves(): void
    {
        $this->assertInstanceOf(
            TestReputationProvider::class,
            ReputationProviderFactory::create(TestReputationProvider::class)
        );
    }

    /**
     * A name that resolves to nothing is a startup failure, not a quiet no-op.
     */
    public function testAnUnknownProviderThrows(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/resolves to no class/');

        ReputationProviderFactory::create('spamhaus');
    }

    /**
     * A class that is not a provider is named as such.
     */
    public function testAClassThatIsNotAProviderThrows(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/does not implement/');

        ReputationProviderFactory::create(\stdClass::class);
    }
}
