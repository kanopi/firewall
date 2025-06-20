<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Storage\FakeCustomStorage;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the StorageFactory class.
 */
class StorageFactoryTest extends TestCase
{
    /**
     * Tests that create() returns an instance of InMemoryStorage
     * when no configuration is provided (defaults to fallback).
     */
    public function testCreateReturnsDefaultInMemoryStorage(): void
    {
        $storage = StorageFactory::create();
        $this->assertInstanceOf(InMemoryStorage::class, $storage);
    }

    /**
     * Tests that create() returns InMemoryStorage when the type is null.
     * This simulates an explicit null type in the config array.
     */
    public function testCreateWithNullTypeDefaultsToInMemoryStorage(): void
    {
        $storage = StorageFactory::create(['type' => null]);
        $this->assertInstanceOf(InMemoryStorage::class, $storage);
    }

    /**
     * Tests that create() returns InMemoryStorage when the type is a non-existent class.
     * This confirms the fallback works on invalid class names.
     */
    public function testCreateWithNonexistentClassDefaultsToInMemoryStorage(): void
    {
        $storage = StorageFactory::create(['type' => 'NonExistent\FakeClass']);
        $this->assertInstanceOf(InMemoryStorage::class, $storage);
    }

    /**
     * Tests that create() returns InMemoryStorage when the given type is a class
     * that does exist but does not implement StorageInterface.
     */
    public function testCreateWithClassThatDoesNotImplementStorageInterface(): void
    {
        $storage = StorageFactory::create(['type' => \stdClass::class]);
        $this->assertInstanceOf(InMemoryStorage::class, $storage);
    }

    /**
     * Tests that create() returns a valid custom StorageInterface implementation
     * when the type is explicitly provided and valid.
     */
    public function testCreateWithValidCustomStorageType(): void
    {
        $storage = StorageFactory::create(['type' => FakeCustomStorage::class]);
        $this->assertInstanceOf(FakeCustomStorage::class, $storage);
    }

    /**
     * Tests that config is passed into the constructor of the custom class.
     */
    public function testCreatePassesConfigToStorage(): void
    {
        $config = ['foo' => 'bar'];
        $storage = StorageFactory::create([
            'type' => FakeCustomStorage::class,
            'config' => $config,
        ]);

        $this->assertSame($config, $storage->getConfig());
    }
}
