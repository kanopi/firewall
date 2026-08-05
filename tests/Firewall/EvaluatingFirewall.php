<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Firewall;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;

/**
 * A Firewall that evaluates instead of short-circuiting on CLI.
 *
 * `Firewall::evaluate()` returns early under PHP_SAPI === 'cli' for every mode
 * but `exception`, which put the `log` and `disabled` branches out of reach of
 * the unit suite entirely — the mode tests that appeared to cover them were
 * passing on that early return, asserting nothing about the behaviour they
 * named. Declining the bypass is the only way to run those paths from a CLI
 * test process.
 *
 * A named subclass rather than an anonymous one because `Firewall`'s
 * constructor is protected: reaching it needs a scope inside the hierarchy,
 * which `make()` provides.
 */
class EvaluatingFirewall extends Firewall
{
    /**
     * @param array<string, mixed> $config
     *   Firewall config, e.g. `['mode' => 'log']`.
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
    protected function shouldBypassForCli(): bool
    {
        return false;
    }
}
