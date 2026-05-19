<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\ChallengeProviderFactory;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

final class ChallengeProviderFactoryTest extends AbstractTestCase
{
    public function testResolvesMathShortName(): void
    {
        $provider = ChallengeProviderFactory::create('math', new TokenManager('secret-value'));

        $this->assertInstanceOf(MathChallengeProvider::class, $provider);
        $this->assertSame('math', $provider->getName());
    }

    public function testResolvesFqcn(): void
    {
        $provider = ChallengeProviderFactory::create(
            MathChallengeProvider::class,
            new TokenManager('secret-value')
        );

        $this->assertInstanceOf(MathChallengeProvider::class, $provider);
    }

    public function testThrowsOnUnknownClass(): void
    {
        $this->expectException(ConfigurationException::class);
        ChallengeProviderFactory::create('NotARealClass', new TokenManager('secret-value'));
    }

    public function testThrowsOnClassThatDoesNotImplementInterface(): void
    {
        $this->expectException(ConfigurationException::class);
        // Use any existing class that isn't a provider.
        ChallengeProviderFactory::create(TokenManager::class, new TokenManager('secret-value'));
    }
}
