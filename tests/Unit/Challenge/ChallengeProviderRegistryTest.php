<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\ChallengeProviderRegistry;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

final class ChallengeProviderRegistryTest extends AbstractTestCase
{
    private const SECRET = 'registry-test-secret-value';

    private const TURNSTILE_KEYS = [
        'site_key' => '1x00000000000000000000AA',
        'secret_key' => '1x0000000000000000000000000000000AA',
    ];

    public function testResolvesBuiltInByName(): void
    {
        $registry = $this->registry('math');

        $this->assertInstanceOf(MathChallengeProvider::class, $registry->get('math'));
    }

    public function testEmptyNameResolvesToTheDefault(): void
    {
        $registry = $this->registry('altcha');

        $this->assertInstanceOf(AltchaChallengeProvider::class, $registry->get(''));
        $this->assertSame('altcha', $registry->getDefaultName());
    }

    public function testTheSameNameResolvesToTheSameInstance(): void
    {
        // Memoisation is what lets both halves of the round trip ask for a
        // provider by name without paying for construction twice.
        $registry = $this->registry('math');

        $this->assertSame($registry->get('math'), $registry->get('math'));
    }

    public function testUnknownNameThrows(): void
    {
        $registry = $this->registry('math');

        $this->expectException(ConfigurationException::class);
        $registry->get('no-such-provider');
    }

    public function testNestedOptionsReachTheProviderTheyAreKeyedFor(): void
    {
        $registry = $this->registry('math', ['turnstile' => self::TURNSTILE_KEYS]);

        // Turnstile refuses to construct without its key pair, so getting an
        // instance back at all is the assertion that the nested block was
        // found.
        $this->assertInstanceOf(TurnstileChallengeProvider::class, $registry->get('turnstile'));
    }

    public function testFlatOptionsStillFeedTheDefaultProvider(): void
    {
        // The pre-existing shape: one provider, one flat options block.
        $registry = $this->registry('turnstile', self::TURNSTILE_KEYS);

        $this->assertSame(self::TURNSTILE_KEYS, $registry->optionsFor('turnstile'));
        $this->assertInstanceOf(TurnstileChallengeProvider::class, $registry->get('turnstile'));
    }

    public function testFlatOptionsAreNotHandedToAPluginNamedProvider(): void
    {
        // The flat block was written for whoever `challenge.provider` names.
        // Feeding another service's keys to Turnstile would look configured
        // right up until Cloudflare rejected every solution, so a
        // plugin-named provider gets nothing instead.
        $registry = $this->registry('math', ['site_key' => 'not-turnstiles', 'secret_key' => 'nor-this']);

        $this->assertSame([], $registry->optionsFor('turnstile'));

        $this->expectException(ConfigurationException::class);
        $registry->get('turnstile');
    }

    public function testNestedBlockWinsOverFlatKeysForTheDefaultProvider(): void
    {
        $registry = $this->registry('turnstile', [
            'site_key' => 'flat-and-stale',
            'turnstile' => self::TURNSTILE_KEYS,
        ]);

        $this->assertSame(self::TURNSTILE_KEYS, $registry->optionsFor('turnstile'));
    }

    public function testWarmUpBuildsEveryDeclaredProvider(): void
    {
        $registry = $this->registry('math', ['turnstile' => self::TURNSTILE_KEYS]);

        $registry->warmUp(['turnstile', 'turnstile', ' altcha ', '']);

        $this->assertTrue($registry->hasOverrides());
        $this->assertInstanceOf(TurnstileChallengeProvider::class, $registry->get('turnstile'));
        // Whitespace is trimmed on the way in, so the trimmed name resolves.
        $this->assertInstanceOf(AltchaChallengeProvider::class, $registry->get('altcha'));
    }

    public function testWarmUpFailsWhenADeclaredProviderCannotBeBuilt(): void
    {
        // The whole point of warming up: a plugin naming a provider whose
        // keys are missing is a configuration failure at startup, not a 500
        // for the first visitor to trip that rule.
        $registry = $this->registry('math');

        $this->expectException(ConfigurationException::class);
        $registry->warmUp(['turnstile']);
    }

    public function testWarmUpFailsOnAMisspelledProvider(): void
    {
        $registry = $this->registry('math');

        $this->expectException(ConfigurationException::class);
        $registry->warmUp(['recapcha']);
    }

    public function testNoOverridesWhenPluginsNameTheDefault(): void
    {
        // Naming the provider you were going to get anyway changes nothing,
        // so the firewall keeps its original pass-token ordering.
        $registry = $this->registry('math');

        $registry->warmUp(['math', 'math']);

        $this->assertFalse($registry->hasOverrides());
    }

    public function testNoOverridesBeforeWarmUp(): void
    {
        $this->assertFalse($this->registry('math')->hasOverrides());
    }

    /**
     * @param array<string, mixed> $providerOptions
     */
    private function registry(string $default, array $providerOptions = []): ChallengeProviderRegistry
    {
        return new ChallengeProviderRegistry(
            new TokenManager(self::SECRET, $default, $default),
            $default,
            $providerOptions
        );
    }
}
