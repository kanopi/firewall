<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Reputation\ReputationSubject;
use Kanopi\Firewall\Reputation\ReputationVerdict;
use Kanopi\Firewall\Reputation\SubjectAwareReputationProviderInterface;

/**
 * A provider that scores email addresses and nothing else (#341).
 *
 * `handles()` is asked per kind precisely so a provider can be specific about
 * what it knows. This one stands for the realistic case: a breach-corpus
 * service is not a phone-number service, and being asked about one should be a
 * configuration error rather than an answer about the wrong thing.
 */
class FussyReputationProvider implements SubjectAwareReputationProviderInterface
{
    /**
     * @param array<int|string, mixed> $config
     *   The rule's config, unused.
     */
    public function __construct(private readonly array $config = [])
    {
    }

    public function getName(): string
    {
        return 'Fussy service';
    }

    public function getSlug(): string
    {
        return 'fussy';
    }

    public function getConfigurationProblem(): ?string
    {
        return null;
    }

    public function knowsAbout(string $ip): bool
    {
        return true;
    }

    public function handles(ReputationSubject $subject): bool
    {
        return $subject->kind === 'post.email';
    }

    public function check(string $ip): ReputationVerdict
    {
        return $this->checkSubject(new ReputationSubject($ip));
    }

    public function checkSubject(ReputationSubject $subject): ReputationVerdict
    {
        return new ReputationVerdict(0.0);
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
