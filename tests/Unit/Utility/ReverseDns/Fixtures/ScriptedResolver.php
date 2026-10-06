<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

/**
 * A resolver that answers from a script, and remembers what it was asked.
 *
 * Named, rather than anonymous, so configuration can name it the way a site names its own.
 */
final class ScriptedResolver implements ReverseDnsResolverInterface
{
    /**
     * Answers to reverse lookups, by address.
     *
     * @var array<string, LookupResult>
     */
    public static array $reverse = [];

    /**
     * Answers to forward lookups, by "hostname type".
     *
     * @var array<string, LookupResult>
     */
    public static array $forward = [];

    /**
     * Every lookup asked for, in order.
     *
     * @var list<string>
     */
    public static array $asked = [];

    /**
     * Options it was built with, most recent last.
     *
     * @var list<array<string, mixed>>
     */
    public static array $built = [];

    /**
     * @param array<string, mixed> $options
     *   Whatever configuration passed.
     */
    public function __construct(array $options = [])
    {
        self::$built[] = $options;
    }

    /**
     * Forget everything.
     */
    public static function reset(): void
    {
        self::$reverse = [];
        self::$forward = [];
        self::$asked = [];
        self::$built = [];
    }

    public function reverse(string $ip): LookupResult
    {
        self::$asked[] = 'reverse ' . $ip;

        return self::$reverse[$ip] ?? LookupResult::none();
    }

    public function forward(string $hostname, string $type): LookupResult
    {
        self::$asked[] = 'forward ' . $hostname . ' ' . $type;

        return self::$forward[$hostname . ' ' . $type] ?? LookupResult::none();
    }
}
