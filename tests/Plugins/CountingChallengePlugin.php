<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A challenge plugin that records how often it was asked.
 *
 * Whether the challenge bucket is evaluated at all is otherwise invisible
 * from outside the firewall — a held pass token and an unmatched rule both
 * end in "request allowed". That distinction is exactly what per-plugin
 * providers change: with one provider a valid token can still short-circuit
 * the bucket, and once a plugin names its own the bucket has to run first so
 * the matched rule is known before its token can be judged.
 *
 * Extends the base class rather than implementing PluginInterface directly
 * so it reads `metadata.challenge_provider` like any first-party plugin.
 */
class CountingChallengePlugin extends AbstractPluginBase
{
    /**
     * Evaluations since the last reset, across every instance.
     */
    public static int $evaluations = 0;

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'counting-challenge';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Counts evaluations and matches anything under /counted.';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        self::$evaluations++;

        return str_starts_with($request->getPathInfo(), '/counted');
    }
}
