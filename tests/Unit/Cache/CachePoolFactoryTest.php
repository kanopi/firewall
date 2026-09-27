<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Cache;

use Kanopi\Firewall\Cache\CachePoolException;
use Kanopi\Firewall\Cache\CachePoolFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

/**
 * One way to turn a cache setting into a pool (#394).
 *
 * Everything here runs without a cache server. Building a pool from a DSN against a real
 * Memcached and Redis is `CachePoolDsnIntegrationTest`.
 */
final class CachePoolFactoryTest extends TestCase
{
    public function testABuiltPoolIsUsedAsItIs(): void
    {
        $pool = new ArrayAdapter();

        $this->assertSame($pool, CachePoolFactory::create($pool, 'ns'));
        $this->assertSame($pool, CachePoolFactory::create(['adaptor' => $pool], 'ns'));
    }

    public function testAClassNameIsBuiltWithItsArguments(): void
    {
        $pool = CachePoolFactory::create([
            'adaptor' => FilesystemAdapter::class,
            'args' => ['fw-test', 0, sys_get_temp_dir() . '/fw-cache-factory-test'],
        ], 'ns');

        $this->assertInstanceOf(FilesystemAdapter::class, $pool);
    }

    /**
     * The adaptor on its own is shorthand for `{adaptor: ...}`.
     */
    public function testAStringIsShorthandForTheAdaptor(): void
    {
        $this->assertInstanceOf(ArrayAdapter::class, CachePoolFactory::create(ArrayAdapter::class, 'ns'));
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function provideSettingsNamingNoPool(): array
    {
        return [
            'nothing' => [null],
            'false' => [false],
            'true' => [true],
            'empty map' => [[]],
            'only a directory' => [['dir' => '/tmp']],
            'empty adaptor' => [['adaptor' => '']],
        ];
    }

    /**
     * No pool is named, which each caller treats as its own default.
     */
    #[DataProvider('provideSettingsNamingNoPool')]
    public function testASettingNamingNoPoolAnswersNull(mixed $setting): void
    {
        $this->assertNull(CachePoolFactory::create($setting, 'ns'));
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideAdaptorsThatAreNotPools(): array
    {
        return [
            'a class that does not exist' => [['adaptor' => 'App\\NoSuchPool'], 'is not a PSR-6 pool'],
            'a class that is not a pool' => [['adaptor' => \ArrayObject::class], 'is not a PSR-6 pool'],
            'a number' => [['adaptor' => 42], 'must be a pool class name, a DSN or a named connection'],
        ];
    }

    #[DataProvider('provideAdaptorsThatAreNotPools')]
    public function testAnAdaptorThatIsNotAPoolIsSaidSo(mixed $setting, string $message): void
    {
        try {
            CachePoolFactory::create($setting, 'ns');
            $this->fail('Expected a CachePoolException');
        } catch (CachePoolException $cachePoolException) {
            $this->assertTrue($cachePoolException->isNotAPool());
            $this->assertStringContainsString($message, $cachePoolException->getMessage());
        }
    }

    /**
     * A pool named correctly whose constructor refuses its arguments is unusable, which
     * is a different fact from naming no pool -- and the callers act on the difference.
     */
    public function testAPoolWhoseConstructorRefusesIsUnusable(): void
    {
        try {
            CachePoolFactory::create(['adaptor' => FilesystemAdapter::class, 'args' => ['bad{namespace}']], 'ns');
            $this->fail('Expected a CachePoolException');
        } catch (CachePoolException $cachePoolException) {
            $this->assertFalse($cachePoolException->isNotAPool());
            $this->assertInstanceOf(\Throwable::class, $cachePoolException->getPrevious());
        }
    }

    /**
     * A scheme is a DSN even when it is not one this can build, and is reported as an
     * unsupported scheme rather than as a class that does not exist.
     */
    public function testAnUnsupportedSchemeIsNamed(): void
    {
        try {
            CachePoolFactory::create('mongodb://cache.internal:27017', 'ns');
            $this->fail('Expected a CachePoolException');
        } catch (CachePoolException $cachePoolException) {
            $this->assertFalse($cachePoolException->isNotAPool());
            $this->assertStringContainsString('"mongodb" is not supported', $cachePoolException->getMessage());
            $this->assertStringContainsString('memcached://, redis://, rediss://', $cachePoolException->getMessage());
        }
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function provideAdaptors(): array
    {
        return [
            'memcached' => ['memcached://cache:11211', true],
            'redis' => ['redis://cache:6379', true],
            'rediss with auth' => ['rediss://user:pass@cache:6380', true],
            'unsupported but a scheme' => ['mongodb://cache', true],
            'a class name' => [ArrayAdapter::class, false],
            'a bare word' => ['cache', false],
        ];
    }

    #[DataProvider('provideAdaptors')]
    public function testADsnIsRecognisedByItsScheme(string $adaptor, bool $isDsn): void
    {
        $this->assertSame($isDsn, CachePoolFactory::isDsn($adaptor));
    }

    /**
     * Every warning about a pool names its adaptor, and a DSN may carry a password.
     *
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideAdaptorsToDescribe(): array
    {
        return [
            'password' => ['redis://:s3cret@cache:6379/0', 'redis://***@cache:6379/0'],
            'user and password' => ['rediss://firewall:s3cret@cache:6380', 'rediss://***@cache:6380'],
            'credentials in the query' => ['memcached://cache:11211?username=u&password=s3cret', 'memcached://cache:11211'],
            'no credentials' => ['memcached://cache:11211', 'memcached://cache:11211'],
            'a class name' => [ArrayAdapter::class, ArrayAdapter::class],
            'a pool' => [new ArrayAdapter(), ArrayAdapter::class],
            'nothing' => [null, 'null'],
        ];
    }

    #[DataProvider('provideAdaptorsToDescribe')]
    public function testADescriptionNeverCarriesCredentials(mixed $adaptor, string $expected): void
    {
        $described = CachePoolFactory::describe($adaptor);

        $this->assertSame($expected, $described);
        $this->assertStringNotContainsString('s3cret', $described);
    }

    /**
     * Run where the extension is absent, which is where the message matters: a missing
     * extension and an unreachable server are different fixes.
     */
    public function testAMissingMemcachedExtensionIsNamed(): void
    {
        if (extension_loaded('memcached')) {
            $this->markTestSkipped('Asserts what happens without ext-memcached, and it is loaded here.');
        }

        $this->expectException(CachePoolException::class);
        $this->expectExceptionMessage('the memcached extension is not installed on this host');

        CachePoolFactory::create('memcached://127.0.0.1:11211', 'ns');
    }

    public function testAMissingRedisExtensionIsNamed(): void
    {
        if (extension_loaded('redis') || class_exists(\Predis\Client::class)) {
            $this->markTestSkipped('Asserts what happens with no Redis client, and one is available here.');
        }

        $this->expectException(CachePoolException::class);
        $this->expectExceptionMessage('the redis extension is not installed on this host');

        CachePoolFactory::create('redis://127.0.0.1:6379', 'ns');
    }
}
