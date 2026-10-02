<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Cache;

use Psr\Cache\CacheItemInterface;

/**
 * The item `RecordingCachePool` hands out, keeping the lifetime it was given.
 */
class RecordingCacheItem implements CacheItemInterface
{
    /**
     * Seconds from `expiresAfter()`, or null when none was set.
     */
    public ?int $lifetime = null;

    public function __construct(private readonly string $key, private bool $hit, private mixed $value)
    {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->value;
    }

    public function isHit(): bool
    {
        return $this->hit;
    }

    public function set(mixed $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function expiresAt(?\DateTimeInterface $expiration): static
    {
        $this->lifetime = $expiration instanceof \DateTimeInterface ? $expiration->getTimestamp() - time() : null;

        return $this;
    }

    public function expiresAfter(int|\DateInterval|null $time): static
    {
        $this->lifetime = $time instanceof \DateInterval
            ? (new \DateTimeImmutable())->add($time)->getTimestamp() - time()
            : $time;

        return $this;
    }
}
