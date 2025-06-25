<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\LazyObjectRegistry;
use stdClass;
use RuntimeException;
use TypeError;

class LazyObjectRegistryTest extends AbstractTestCase
{
    /**
     * Tests that entries added to the registry are sorted in ascending order by priority.
     * The yielded order should reflect the priority values (lowest first).
     */
    public function testEntriesAreAddedAndSortedByPriority(): void
    {
        $registry = new LazyObjectRegistry();

        $registry->add('item1', fn() => (object)['id' => 'first'], 5);
        $registry->add('item2', fn() => (object)['id' => 'second'], 1);
        $registry->add('item3', fn() => (object)['id' => 'third'], 10);

        $names = [];
        foreach ($registry->getIterator() as $name => $object) {
            $names[] = $name;
        }

        $this->assertSame(['item2', 'item1', 'item3'], $names);
    }

    /**
     * Tests that factory functions are not executed until iteration occurs.
     * Ensures that factories are lazily invoked only when needed.
     */
    public function testFactoryIsCalledLazily(): void
    {
        $called = false;
        $registry = new LazyObjectRegistry();
        $registry->add('lazy', function () use (&$called) {
            $called = true;
            return new stdClass();
        });

        $this->assertFalse($called, 'Factory should not be called before iteration');

        foreach ($registry->getIterator() as $object) {
            break;
        }

        $this->assertTrue($called, 'Factory should be called during iteration');
    }

    /**
     * Tests that an object created by a factory is reused on subsequent iterations.
     * This verifies caching of the object instance within the registry.
     */
    public function testSameInstanceIsReturnedOnReiteration(): void
    {
        $registry = new LazyObjectRegistry();
        $registry->add('singleton', fn() => new stdClass());

        $first = null;
        foreach ($registry->getIterator() as $object) {
            $first = $object;
        }

        $second = null;
        foreach ($registry->getIterator() as $object) {
            $second = $object;
        }

        $this->assertSame($first, $second);
    }

    /**
     * Tests that when the registry is empty, iteration yields no values.
     * This confirms graceful handling of an empty state.
     */
    public function testEmptyRegistryYieldsNothing(): void
    {
        $registry = new LazyObjectRegistry();
        $this->assertSame([], iterator_to_array($registry->getIterator()));
    }

    /**
     * Tests that if a factory returns a non-object (e.g. string),
     * it can be caught as a logic error by the consumer if type enforcement is needed.
     * The registry itself does not enforce object return, so this is a user-side check.
     */
    public function testFactoryReturnsNonObject(): void
    {
        $registry = new LazyObjectRegistry();
        $registry->add('bad', fn() => 'not an object');

        $this->expectException(TypeError::class);

        foreach ($registry->getIterator() as $object) {
            if (!is_object($object)) {
                throw new TypeError('Factory must return object');
            }
        }
    }

    /**
     * Tests that multiple entries can share the same name.
     * The registry does not currently enforce name uniqueness.
     * This test confirms that all such entries are preserved and executed in order.
     */
    public function testDuplicateNamesAllowed(): void
    {
        $registry = new LazyObjectRegistry();

        $registry->add('duplicate', fn() => (object)['id' => 1], 2);
        $registry->add('duplicate', fn() => (object)['id' => 2], 1);

        $objects = [];
        foreach ($registry->getIterator() as $name => $object) {
            $objects[] = [$name, $object->id];
        }

        $this->assertCount(2, $objects);
        $this->assertSame([['duplicate', 2], ['duplicate', 1]], $objects);
    }
}
