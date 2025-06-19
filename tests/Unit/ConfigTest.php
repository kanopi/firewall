<?php

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Config;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

class ConfigTest extends TestCase
{

    public function setUp(): void
    {
        parent::setUp();

        $data = ['example 1','example 2'];
        @file_put_contents('/tmp/example1.yml', Yaml::dump($data));
        @file_put_contents('/tmp/example2.yml', 'example');

        $invalidYaml = <<<YAML
        key1: value1
        key2
          - listItem1
          - listItem2
        YAML;
        @file_put_contents('/tmp/example3.yml', $invalidYaml);
    }

    public function tearDown(): void
    {
        parent::tearDown();
        @unlink('/tmp/example1.yml');
        @unlink('/tmp/example2.yml');
        @unlink('/tmp/example3.yml');
    }

    /**
     * Test Config::load()
     *
     * Confirms that when 1 array with multiple arrays are merged
     * together for the output.
     */
    public function testConfigLoadWithArrays(): void
    {
        // Test with static arrays
        $config = Config::load([['example 1', 'example 2'], ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(4, $config);
        $this->assertTrue(in_array('example 1', $config));
        $this->assertTrue(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when 1 array with a non-string/non-array item
     * is added it doesn't get merged in.
     */
    public function testConfigLoadWithNoStringOrArray(): void
    {
        $config = Config::load([null, ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(2, $config);
        $this->assertFalse(in_array('example 1', $config));
        $this->assertFalse(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when a string is added to the array it is loaded
     * and merged in with the rest of the array.
     */
    public function testConfigLoadWithFileAndArray(): void
    {
        $config = Config::load(['/tmp/example1.yml', ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(4, $config);
        $this->assertTrue(in_array('example 1', $config));
        $this->assertTrue(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when a string is added to the array and is not
     * a valid file it is discarded and not merged/processed with
     * the rest of the data.
     */
    public function testConfigLoadWithFileNotFoundAndArrays(): void
    {
        $config = Config::load(['/tmp/example.notfound', ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(2, $config);
        $this->assertFalse(in_array('example 1', $config));
        $this->assertFalse(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when a string is added to the array and is a
     * valid file but doesn't properly parse to a YAML array it is
     * discarded and not processed/merged with the rest of the data.
     */
    public function testConfigLoadWithFileNotValidYamlArrayAndArrays(): void
    {
        $config = Config::load(['/tmp/example2.yml',  ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(2, $config);
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when a string is added to the array and is a
     * valid file but doesn't properly parse to a YAML it is
     * discarded and not processed/merged with the rest of the data.
     */
    public function testConfigLoadWithFileNotValidYamlAndArrays(): void
    {
        $config = Config::load(['/tmp/example3.yml',  ['example 3', 'example 4']]);
        $this->assertIsArray($config);
        $this->assertCount(2, $config);
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when configuration is loaded and overrides are used
     * it properly can override the provided values.
     */
    public function testConfigLoadWithOverrides(): void
    {
        $config = Config::load(
            ['/tmp/example1.yml',  ['example 3', 'example 4']],
            [
                '[0]' => 'example new'
            ]
        );
        $this->assertIsArray($config);
        $this->assertFalse(in_array('example 1', $config));
        $this->assertTrue(in_array('example new', $config));
        $this->assertTrue(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when configuration is loaded and overrides are used
     * it properly can add the items.
     */
    public function testConfigLoadWithOverridesAdded(): void
    {
        $config = Config::load(
            ['/tmp/example1.yml',  ['example 3', 'example 4']],
            [
                '[a]' => 'example new'
            ]
        );
        $this->assertIsArray($config);
        $this->assertTrue(in_array('example new', $config));
        $this->assertTrue(in_array('example 1', $config));
        $this->assertTrue(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }

    /**
     * Test Config::load()
     *
     * Confirms that when an override is provided and it doesn't
     * evaluate properly an error is not thrown but ignored.
     */
    public function testConfigLoadWithOverridesNotValid(): void
    {
        $config = Config::load(
            ['/tmp/example1.yml',  ['example 3', 'example 4']],
            [
                'a' => 'example new'
            ]
        );
        $this->assertIsArray($config);
        $this->assertFalse(in_array('example new', $config));
        $this->assertTrue(in_array('example 1', $config));
        $this->assertTrue(in_array('example 2', $config));
        $this->assertTrue(in_array('example 3', $config));
        $this->assertTrue(in_array('example 4', $config));
    }
}