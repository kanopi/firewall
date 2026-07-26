<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
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

    public function testResolvesAltchaShortName(): void
    {
        $provider = ChallengeProviderFactory::create('altcha', new TokenManager('secret-value'));

        $this->assertInstanceOf(AltchaChallengeProvider::class, $provider);
        $this->assertSame('altcha', $provider->getName());
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

    public function testForwardsOptionsToProvidersThatAcceptThem(): void
    {
        $provider = ChallengeProviderFactory::create(
            'altcha',
            new TokenManager('secret-value'),
            ['widget_src' => 'https://example.test/altcha.js', 'widget_integrity' => 'sha384-abc']
        );

        $html = $provider->renderInterstitial(
            Request::create('/secure'),
            ['submit_url' => '/_fw', 'redirect_to' => '/', 'ttl' => '60', 'header_name' => 'X-FW']
        );

        $this->assertStringContainsString('src="https://example.test/altcha.js"', $html);
        $this->assertStringContainsString('integrity="sha384-abc"', $html);
    }

    public function testSingleArgumentProvidersAreStillConstructable(): void
    {
        // MathChallengeProvider keeps the original one-parameter constructor,
        // standing in for any custom provider written against it. Passing
        // options must not break it.
        $provider = ChallengeProviderFactory::create(
            'math',
            new TokenManager('secret-value'),
            ['widget_src' => 'ignored']
        );

        $this->assertInstanceOf(MathChallengeProvider::class, $provider);
        $this->assertInstanceOf(ChallengeProviderInterface::class, $provider);
    }
}
