<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Firewall;

use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Claims every request is a challenge submission, with no provider configured.
 *
 * `isChallengeSubmission()` already returns FALSE when no provider is wired
 * up, so the guard at the top of `handleChallengeSubmission()` cannot be
 * reached through the real code path — the two conditions contradict each
 * other. That is exactly what makes the guard worth keeping and worth
 * testing: it is insurance against a subclass or a later change breaking the
 * invariant, and what it must do is return quietly rather than dereference a
 * null provider and turn a misconfiguration into a fatal error on every POST.
 */
class ProviderlessSubmissionFirewall extends EvaluatingFirewall
{
    /**
     * @param array<string, mixed> $config
     *   Firewall config.
     */
    public static function make(
        StorageInterface $storage,
        PluginManager $blockingPluginManager,
        PluginManager $bypassPluginManager,
        PluginManager $challengePluginManager,
        array $config = []
    ): self {
        return new self(
            $storage,
            $blockingPluginManager,
            $bypassPluginManager,
            $challengePluginManager,
            $config
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function isChallengeSubmission(Request $request): bool
    {
        return true;
    }
}
