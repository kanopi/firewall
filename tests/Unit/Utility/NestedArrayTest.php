<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\NestedArray;
use Kanopi\Firewall\Exception\ConfigurationException;

class NestedArrayTest extends AbstractTestCase
{
    /**
     * Tests that getValue() returns the correct nested value
     * and sets $key_exists to true when the path is valid.
     */
    public function testGetValueReturnsCorrectValue(): void
    {
        $array = ['a' => ['b' => ['c' => 42]]];
        $keyExists = false;

        $value = NestedArray::getValue($array, ['a', 'b', 'c'], $keyExists);
        $this->assertSame(42, $value);
        $this->assertTrue($keyExists);
    }

    /**
     * Tests that getValue() returns null and sets $key_exists to false
     * when part of the path does not exist in the array.
     */
    public function testGetValueReturnsNullWhenKeyMissing(): void
    {
        $array = ['x' => ['y' => 1]];
        $keyExists = false;

        $value = NestedArray::getValue($array, ['x', 'z'], $keyExists);
        $this->assertNull($value);
        $this->assertFalse($keyExists);
    }

    /**
     * Tests that setValue() can create nested keys in an empty array
     * and assign a value at the correct depth.
     */
    public function testSetValueCreatesNestedStructure(): void
    {
        $array = [];
        NestedArray::setValue($array, ['a', 'b', 'c'], 100);

        $this->assertSame(['a' => ['b' => ['c' => 100]]], $array);
    }

    /**
     * Tests that setValue() throws a LogicException when a
     * non-array value exists in the path and force is not enabled.
     */
    public function testSetValueThrowsWithoutForceOnNonArray(): void
    {
        $this->expectException(ConfigurationException::class);
        $array = ['a' => 'not-an-array'];

        NestedArray::setValue($array, ['a', 'b'], 'value');
    }

    /**
     * Tests that setValue() will convert a non-array to an array
     * when force is enabled, allowing deeper keys to be created.
     */
    public function testSetValueWithForceOverwritesNonArray(): void
    {
        $array = ['a' => 'not-an-array'];
        NestedArray::setValue($array, ['a', 'b'], 'value', true);

        $this->assertSame(['a' => ['b' => 'value']], $array);
    }

    /**
     * Tests that unsetValue() removes a value from a nested array
     * and correctly sets $key_existed to true.
     */
    public function testUnsetValueDeletesKey(): void
    {
        $array = ['x' => ['y' => ['z' => 'remove-me']]];
        $existed = false;

        NestedArray::unsetValue($array, ['x', 'y', 'z'], $existed);
        $this->assertTrue($existed);
        $this->assertSame(['x' => ['y' => []]], $array);
    }

    /**
     * Tests that unsetValue() does nothing when the path doesn't exist,
     * and sets $key_existed to false.
     */
    public function testUnsetValueFailsSilentlyIfPathMissing(): void
    {
        $array = ['x' => ['y' => []]];
        $existed = false;

        NestedArray::unsetValue($array, ['x', 'y', 'z'], $existed);
        $this->assertFalse($existed);
        $this->assertSame(['x' => ['y' => []]], $array);
    }

    /**
     * Tests that keyExists() returns true when the nested key exists.
     */
    public function testKeyExistsReturnsTrue(): void
    {
        $array = ['foo' => ['bar' => 'baz']];
        $this->assertTrue(NestedArray::keyExists($array, ['foo', 'bar']));
    }

    /**
     * Tests that keyExists() returns false when a nested key is missing.
     */
    public function testKeyExistsReturnsFalse(): void
    {
        $array = ['foo' => ['bar' => 'baz']];
        $this->assertFalse(NestedArray::keyExists($array, ['foo', 'baz']));
    }

    /**
     * Tests that mergeDeep() merges arrays recursively and overwrites
     * non-array values with later ones.
     */
    public function testMergeDeepMergesArraysCorrectly(): void
    {
        $a = ['foo' => ['bar' => ['x'], 'baz' => 'old']];
        $b = ['foo' => ['bar' => ['y'], 'baz' => 'new']];

        $expected = ['foo' => ['bar' => ['x', 'y'], 'baz' => 'new']];
        $this->assertSame($expected, NestedArray::mergeDeep($a, $b));
    }

    /**
     * Tests that mergeDeepArray() preserves integer keys when instructed to,
     * and merges arrays at those keys correctly.
     */
    public function testMergeDeepArrayPreservesIntegerKeys(): void
    {
        $arrays = [
            [10 => ['a'], 20 => ['x']],
            [10 => ['b'], 20 => ['y']],
        ];

        $result = NestedArray::mergeDeepArray($arrays, preserve_integer_keys: true);

        $this->assertSame(['b'], $result[10]);     // overwritten
        $this->assertSame(['y'], $result[20]); // merged
    }

    /**
     * Tests that mergeDeepArray() renumbers integer keys by default.
     */
    public function testMergeDeepArrayRenumbersIntegerKeysByDefault(): void
    {
        $arrays = [
            ['a'],
            ['b'],
        ];

        $this->assertSame(['a', 'b'], NestedArray::mergeDeepArray($arrays));
    }

    /**
     * Tests that filter() removes all falsy values recursively from a nested array.
     */
    public function testFilterRemovesFalsyValues(): void
    {
        $array = [
            'one' => 1,
            'zero' => 0,
            'empty' => '',
            'nested' => ['null' => null, 'false' => false, 'two' => 2],
        ];

        $expected = [
            'one' => 1,
            'nested' => ['two' => 2],
        ];

        $this->assertSame($expected, NestedArray::filter($array));
    }

    /**
     * Tests that filter() correctly applies a custom callable
     * and keeps only values that pass the callback condition.
     */
    public function testFilterUsesCustomCallback(): void
    {
        $array = ['a' => 1, 'b' => 2, 'c' => 3];
        $callback = fn($v) => $v > 1;

        $result = NestedArray::filter($array, $callback);
        $this->assertSame(['b' => 2, 'c' => 3], $result);
    }
}
