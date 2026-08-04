<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\ChallengeProviderFactory;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
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

    public function testResolvesTurnstileShortName(): void
    {
        $provider = ChallengeProviderFactory::create(
            'turnstile',
            new TokenManager('secret-value'),
            ['site_key' => 'site', 'secret_key' => 'secret']
        );

        $this->assertInstanceOf(TurnstileChallengeProvider::class, $provider);
        $this->assertSame('turnstile', $provider->getName());
    }

    public function testTurnstileMisconfigurationSurfacesAtCreation(): void
    {
        // Startup is the only good time to find out: the alternative is a
        // widget every visitor is guaranteed to fail.
        $this->expectException(ConfigurationException::class);

        ChallengeProviderFactory::create('turnstile', new TokenManager('secret-value'));
    }

    public function testProvidersMayDeclineTheTokenManager(): void
    {
        // Parameters are matched by declared type, so a provider with no
        // state of its own to sign receives only the options.
        $provider = ChallengeProviderFactory::create(
            OptionsOnlyProvider::class,
            new TokenManager('secret-value'),
            ['marker' => 'received']
        );

        $this->assertInstanceOf(OptionsOnlyProvider::class, $provider);
        $this->assertSame('received', $provider->marker());
    }

    public function testUntypedConstructorParametersStillReceiveTheTokenManager(): void
    {
        // Back-compat: a custom provider predating type-based injection may
        // not have declared a type at all.
        $tokenManager = new TokenManager('secret-value');

        $provider = ChallengeProviderFactory::create(UntypedProvider::class, $tokenManager);

        $this->assertInstanceOf(UntypedProvider::class, $provider);
        $this->assertSame($tokenManager, $provider->injected());
    }

    public function testProvidersWithNoConstructorAreConstructable(): void
    {
        $provider = ChallengeProviderFactory::create(
            NoConstructorProvider::class,
            new TokenManager('secret-value')
        );

        $this->assertInstanceOf(NoConstructorProvider::class, $provider);
    }
}

/**
 * Stands in for a provider that needs options but no TokenManager.
 */
class OptionsOnlyProvider implements ChallengeProviderInterface
{
    /**
     * @param array<string, mixed> $options
     *   Provider options.
     */
    public function __construct(private readonly array $options = [])
    {
    }

    public function marker(): string
    {
        return (string) ($this->options['marker'] ?? '');
    }

    public function getName(): string
    {
        return 'options-only';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        return '';
    }

    public function verifySolution(Request $request): bool
    {
        return false;
    }
}

/**
 * Stands in for a custom provider written without a parameter type.
 */
class UntypedProvider implements ChallengeProviderInterface
{
    /**
     * @param mixed $tokenManager
     *   Whatever the factory decided to inject.
     */
    public function __construct(private $tokenManager)
    {
    }

    public function injected(): mixed
    {
        return $this->tokenManager;
    }

    public function getName(): string
    {
        return 'untyped';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        return '';
    }

    public function verifySolution(Request $request): bool
    {
        return false;
    }
}

/**
 * Stands in for a provider with nothing to inject at all.
 */
class NoConstructorProvider implements ChallengeProviderInterface
{
    public function getName(): string
    {
        return 'no-constructor';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        return '';
    }

    public function verifySolution(Request $request): bool
    {
        return false;
    }
}
