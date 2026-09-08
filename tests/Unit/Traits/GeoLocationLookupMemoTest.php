<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use GeoIp2\Database\Reader;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Traits\GeoLocationTrait;

/**
 * The lookup memo's own guards (#6).
 *
 * `Asn` and `GeoLocation` both check their reader before calling in, so these
 * branches are unreachable through the plugins. They are reachable by anything
 * else that uses the trait, which is the point of them being there -- so they
 * are exercised against the trait directly rather than left untested.
 */
class GeoLocationLookupMemoTest extends AbstractTestCase
{
    /**
     * A fixture exposing the trait's protected lookup.
     */
    private function subject(Reader|null $reader, mixed $cache = null): object
    {
        return new class ($reader, $cache) {
            use GeoLocationTrait;

            /** @var array<string, mixed> */
            protected array $metadata = [];

            public function __construct(Reader|null $reader, mixed $cache = null)
            {
                $this->reader = $reader;

                if ($cache !== null) {
                    $this->metadata['cache'] = $cache;
                }
            }

            public function cached(string $ip, string $variable, callable $resolve): mixed
            {
                return $this->cachedValue($ip, $variable, $resolve);
            }

            public function ttl(): int
            {
                return $this->valueCacheTtl();
            }

            public function lookup(string $method, string $ip): ?object
            {
                return $this->lookupRecord($method, $ip);
            }

            /** @return array<string, object|null> */
            public function memo(): array
            {
                return $this->lookupMemo;
            }
        };
    }

    /**
     * With no reader there is nothing to look up.
     */
    public function testNoReaderYieldsNull(): void
    {
        $subject = $this->subject(null);

        $this->assertNull($subject->lookup('city', '198.51.100.1'));
    }

    /**
     * A reader that does not offer the method is not called blindly.
     *
     * `Reader` has `city()` and `asn()`; a web-service `Client` does not offer
     * every method a database reader does.
     */
    public function testAReaderWithoutTheMethodYieldsNull(): void
    {
        $subject = $this->subject($this->createMock(Reader::class));

        $this->assertNull($subject->lookup('noSuchLookup', '198.51.100.1'));
    }

    /**
     * A null result is memoised, so a second call does not retry.
     *
     * Nothing about the request changes between calls, so a retry would fail
     * identically while paying for it again.
     */
    public function testAFailedLookupIsRemembered(): void
    {
        $subject = $this->subject(null);

        $subject->lookup('city', '198.51.100.1');
        $subject->lookup('city', '198.51.100.1');

        $this->assertArrayHasKey('city:198.51.100.1', $subject->memo());
        $this->assertNull($subject->memo()['city:198.51.100.1']);
    }

    /**
     * An adaptor named by class is constructed, and its TTL honoured.
     */
    public function testAnAdaptorNamedByClassIsBuilt(): void
    {
        $subject = $this->subject(null, [
            'adaptor' => \Symfony\Component\Cache\Adapter\ArrayAdapter::class,
            'args' => [],
            'ttl' => 60,
        ]);

        $calls = 0;
        $resolve = function () use (&$calls): string {
            $calls++;

            return 'US';
        };

        $this->assertSame('US', $subject->cached('198.51.100.1', 'country', $resolve));
        $this->assertSame('US', $subject->cached('198.51.100.1', 'country', $resolve));
        $this->assertSame(1, $calls, 'The second call should come from the pool');
        $this->assertSame(60, $subject->ttl());
    }

    /**
     * A pool instance passed under `adaptor` is used as-is.
     *
     * YAML cannot carry an object, so this is the shape an override produces.
     */
    public function testAPoolInstanceUnderAdaptorIsUsed(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $subject = $this->subject(null, ['adaptor' => $pool]);

        $subject->cached('198.51.100.2', 'country', fn(): string => 'DE');

        $this->assertNotSame([], $pool->getValues(), 'The injected pool should have been written to');
    }

    /**
     * An adaptor that cannot be constructed leaves resolution working.
     */
    public function testAnAdaptorThatThrowsOnConstructionDegrades(): void
    {
        $subject = $this->subject(null, [
            'adaptor' => \Kanopi\Firewall\Tests\Plugins\ThrowingCachePool::class,
        ]);

        $this->assertSame('FR', $subject->cached('198.51.100.3', 'country', fn(): string => 'FR'));
    }

    /**
     * A pool that throws on use costs a lookup, not the value.
     */
    public function testAPoolThatThrowsOnUseDegrades(): void
    {
        $pool = new class implements \Psr\Cache\CacheItemPoolInterface {
            public function getItem(string $key): \Psr\Cache\CacheItemInterface
            {
                throw new class ('bad key') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {};
            }

            public function getItems(array $keys = []): iterable { return []; }
            public function hasItem(string $key): bool { return false; }
            public function clear(): bool { return true; }
            public function deleteItem(string $key): bool { return true; }
            public function deleteItems(array $keys): bool { return true; }
            public function save(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function saveDeferred(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function commit(): bool { return true; }
        };

        $subject = $this->subject(null, $pool);

        $this->assertSame('IT', $subject->cached('198.51.100.4', 'country', fn(): string => 'IT'));
    }

    /**
     * An object is returned but never stored.
     *
     * A cache is a shared store, and an object in a shared store is an object
     * somebody may deserialise.
     */
    public function testAnObjectValueIsNeverCached(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $subject = $this->subject(null, $pool);

        $object = new \stdClass();
        $calls = 0;
        $resolve = function () use ($object, &$calls): object {
            $calls++;

            return $object;
        };

        $this->assertSame($object, $subject->cached('198.51.100.5', 'record', $resolve));
        $this->assertSame($object, $subject->cached('198.51.100.5', 'record', $resolve));

        // Resolved twice: nothing object-shaped was stored to answer the second
        // call. Asserted through behaviour rather than by reading the pool,
        // because ArrayAdapter records a key on getItem() whether or not it is
        // ever saved.
        $this->assertSame(2, $calls, 'An object must never be served from the cache');
    }

    /**
     * A configuration with no adaptor turns caching off and says so.
     */
    public function testCacheWithoutAnAdaptorIsOff(): void
    {
        $subject = $this->subject(null, ['ttl' => 60]);

        $calls = 0;
        $resolve = function () use (&$calls): string {
            $calls++;

            return 'ES';
        };

        $subject->cached('198.51.100.6', 'country', $resolve);
        $subject->cached('198.51.100.6', 'country', $resolve);

        $this->assertSame(2, $calls, 'With no adaptor there is no cache to hit');
    }

    /**
     * An explicit false disables it, as does absence.
     */
    public function testCachingIsOffByDefaultAndCanBeDisabled(): void
    {
        foreach ([null, false] as $config) {
            $subject = $this->subject(null, $config);

            $calls = 0;
            $resolve = function () use (&$calls): string {
                $calls++;

                return 'PT';
            };

            $subject->cached('198.51.100.7', 'country', $resolve);
            $subject->cached('198.51.100.7', 'country', $resolve);

            $this->assertSame(2, $calls);
        }
    }
}
