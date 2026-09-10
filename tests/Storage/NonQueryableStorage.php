<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A storage backend that cannot enumerate its own keys.
 *
 * Enumeration is a separate interface because not every store has it — the
 * Memcached example in the custom-storage guide cannot list keys at all. This
 * is that shape: a working backend that simply cannot answer "who is blocked",
 * which `BlockList` has to handle by declining rather than by fataling.
 *
 * Implements `StorageInterface` directly rather than extending a shipped base,
 * because every base in this package is queryable and the point here is not to
 * be.
 */
class NonQueryableStorage implements StorageInterface
{
    /** @var array<string, array<string, mixed>> */
    private array $records = [];

    /** @var array<string, array<int, int>> */
    private array $offenses = [];

    public function __construct(array $config = [])
    {
    }

    public function getKey(Request $request): string
    {
        return (string) $request->getClientIp();
    }

    public function set(string $key, array $value, int $expire = 0): bool
    {
        $this->records[$key] = $value + ['expire' => $expire > 0 ? time() + $expire : 0];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->records[$key]);

        return true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->records[$key] ?? $default;
    }

    public function reset(): bool
    {
        $this->records = [];
        $this->offenses = [];

        return true;
    }

    public function exists(string $key): bool
    {
        return isset($this->records[$key]);
    }

    public function expire(): bool
    {
        return true;
    }

    public function addToExpire(string $key, int $amount): bool
    {
        return true;
    }

    public function recordOffense(string $key): bool
    {
        $this->offenses[$key][] = time();

        return true;
    }

    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return count($this->offenses[$key] ?? []);
    }

    public function isBlocked(string $key): array|false
    {
        return $this->records[$key] ?? false;
    }

    public function getStorageData(Request $request, ?PluginInterface $plugin): array
    {
        return [];
    }
}
