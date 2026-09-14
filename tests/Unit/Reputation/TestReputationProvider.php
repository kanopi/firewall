<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationVerdict;

/**
 * A provider somebody wrote themselves, which is the point of the interface.
 *
 * Deliberately minimal: it implements the contract and nothing else, so it also
 * stands for "the smallest thing that can be a provider" -- if this needs more
 * than the interface to work with the rule, the interface is wrong.
 */
class TestReputationProvider implements ReputationProviderInterface
{
    /**
     * How many times it was asked.
     */
    public int $calls = 0;

    /**
     * @param array<int|string, mixed> $config
     *   The rule's config, unused beyond `score`.
     */
    public function __construct(private readonly array $config = [])
    {
    }

    public function getName(): string
    {
        return 'Test provider';
    }

    public function getSlug(): string
    {
        return 'test-provider';
    }

    public function getConfigurationProblem(): ?string
    {
        return is_string($this->config['problem'] ?? null) ? $this->config['problem'] : null;
    }

    public function knowsAbout(string $ip): bool
    {
        return true;
    }

    public function check(string $ip): ReputationVerdict
    {
        $this->calls++;

        return new ReputationVerdict((float) ($this->config['score'] ?? 0));
    }

    public function getDefaultCacheTtl(): int
    {
        return 60;
    }

    public function getDefaultErrorCacheTtl(): int
    {
        return 10;
    }
}
