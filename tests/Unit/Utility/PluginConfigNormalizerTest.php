<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;

final class PluginConfigNormalizerTest extends AbstractTestCase
{
    /**
     * Test: bypass: section converts to response: allow.
     */
    public function testBypassConvertsToResponseAllow(): void
    {
        $config = [
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => -200,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertArrayHasKey('plugins', $result);
        $this->assertCount(1, $result['plugins']);
        $this->assertArrayNotHasKey('bypass', $result);

        $plugin = $result['plugins'][0];
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $plugin['plugin']);
        $this->assertEquals('allow', $plugin['response']);
        $this->assertEquals(-200, $plugin['weight']);
        $this->assertTrue($plugin['enable']);
        $this->assertEquals(['127.0.0.1'], $plugin['config']);
    }

    /**
     * Test: block: section converts to response: block.
     */
    public function testBlockConvertsToResponseBlock(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => -100,
                    'enable' => true,
                    'config' => ['192.168.1.100'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertArrayHasKey('plugins', $result);
        $this->assertCount(1, $result['plugins']);
        $this->assertArrayNotHasKey('block', $result);

        $plugin = $result['plugins'][0];
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $plugin['plugin']);
        $this->assertEquals('block', $plugin['response']);
        $this->assertEquals(-100, $plugin['weight']);
        $this->assertTrue($plugin['enable']);
        $this->assertEquals(['192.168.1.100'], $plugin['config']);
    }

    /**
     * Test: priority maps to weight.
     */
    public function testPriorityMapsToWeight(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => 50,
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertEquals(50, $result['plugins'][0]['weight']);
    }

    /**
     * Test: missing priority defaults to 0.
     */
    public function testMissingPriorityDefaultsToZero(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertEquals(0, $result['plugins'][0]['weight']);
    }

    /**
     * Test: mixed old and new format merging.
     */
    public function testMixedFormatMerging(): void
    {
        $config = [
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'block',
                    'weight' => -50,
                    'enable' => true,
                    'metadata' => [],
                    'config' => ['/admin'],
                ],
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => -200,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\RateLimit' => [
                    'priority' => 100,
                    'config' => [],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertCount(3, $result['plugins']);
        $this->assertArrayNotHasKey('bypass', $result);
        $this->assertArrayNotHasKey('block', $result);

        // First plugin from plugins: array preserved
        $this->assertEquals('Kanopi\Firewall\Plugins\Url', $result['plugins'][0]['plugin']);
        $this->assertEquals('block', $result['plugins'][0]['response']);

        // Second plugin from bypass: converted
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][1]['plugin']);
        $this->assertEquals('allow', $result['plugins'][1]['response']);

        // Third plugin from block: converted
        $this->assertEquals('Kanopi\Firewall\Plugins\RateLimit', $result['plugins'][2]['plugin']);
        $this->assertEquals('block', $result['plugins'][2]['response']);
    }

    /**
     * Test: multiple instances of the same plugin class.
     */
    public function testMultipleInstancesOfSamePlugin(): void
    {
        $config = [
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'allow',
                    'weight' => -200,
                    'config' => ['127.0.0.1'],
                ],
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'weight' => -100,
                    'config' => ['192.168.1.100'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertCount(2, $result['plugins']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][0]['plugin']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][1]['plugin']);
        $this->assertEquals('allow', $result['plugins'][0]['response']);
        $this->assertEquals('block', $result['plugins'][1]['response']);
    }

    /**
     * Test: metadata is preserved.
     */
    public function testMetadataPreserved(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\GeoLocation' => [
                    'priority' => 0,
                    'enable' => true,
                    'metadata' => [
                        'reader' => [
                            'db' => '/path/to/GeoLite2.mmdb',
                        ],
                    ],
                    'config' => ['US', 'CA'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertEquals([
            'reader' => [
                'db' => '/path/to/GeoLite2.mmdb',
            ],
        ], $result['plugins'][0]['metadata']);
    }

    /**
     * Test: config array is preserved.
     */
    public function testConfigPreserved(): void
    {
        $config = [
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'config' => ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertEquals(['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12'], $result['plugins'][0]['config']);
    }

    /**
     * Test: enable flag is preserved.
     */
    public function testEnablePreserved(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => false,
                    'config' => ['1.2.3.4'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertFalse($result['plugins'][0]['enable']);
    }

    /**
     * Test: missing enable defaults to true.
     */
    public function testMissingEnableDefaultsToTrue(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'config' => ['1.2.3.4'],
                ],
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertTrue($result['plugins'][0]['enable']);
    }

    /**
     * Test: empty bypass section handled.
     */
    public function testEmptyBypassSection(): void
    {
        $config = [
            'bypass' => [],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertArrayHasKey('plugins', $result);
        $this->assertEmpty($result['plugins']);
    }

    /**
     * Test: empty block section handled.
     */
    public function testEmptyBlockSection(): void
    {
        $config = [
            'block' => [],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertArrayHasKey('plugins', $result);
        $this->assertEmpty($result['plugins']);
    }

    /**
     * Test: missing sections handled (no bypass, no block, no plugins).
     */
    public function testMissingSectionsHandled(): void
    {
        $config = [
            'global' => [
                'mode' => 'block',
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertArrayHasKey('plugins', $result);
        $this->assertEmpty($result['plugins']);
        $this->assertEquals('block', $result['global']['mode']);
    }

    /**
     * Test: non-array plugin config is skipped.
     */
    public function testNonArrayPluginConfigSkipped(): void
    {
        $config = [
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => 'invalid',
            ],
        ];

        $result = PluginConfigNormalizer::normalize($config);

        $this->assertEmpty($result['plugins']);
    }

    /**
     * Test: partitionAndSort separates allow and block plugins.
     */
    public function testPartitionAndSortSeparatesPlugins(): void
    {
        $plugins = [
            [
                'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                'response' => 'allow',
                'weight' => 0,
                'enable' => true,
            ],
            [
                'plugin' => 'Kanopi\Firewall\Plugins\Url',
                'response' => 'block',
                'weight' => 0,
                'enable' => true,
            ],
        ];

        $result = PluginConfigNormalizer::partitionAndSort($plugins);

        $this->assertCount(1, $result['allow']);
        $this->assertCount(1, $result['block']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['allow'][0]['plugin']);
        $this->assertEquals('Kanopi\Firewall\Plugins\Url', $result['block'][0]['plugin']);
    }

    /**
     * Test: partitionAndSort sorts by weight (lower first).
     */
    public function testPartitionAndSortSortsByWeight(): void
    {
        $plugins = [
            [
                'plugin' => 'Plugin3',
                'response' => 'block',
                'weight' => 100,
                'enable' => true,
            ],
            [
                'plugin' => 'Plugin1',
                'response' => 'block',
                'weight' => -100,
                'enable' => true,
            ],
            [
                'plugin' => 'Plugin2',
                'response' => 'block',
                'weight' => 0,
                'enable' => true,
            ],
        ];

        $result = PluginConfigNormalizer::partitionAndSort($plugins);

        $this->assertEquals('Plugin1', $result['block'][0]['plugin']);
        $this->assertEquals('Plugin2', $result['block'][1]['plugin']);
        $this->assertEquals('Plugin3', $result['block'][2]['plugin']);
    }

    /**
     * Test: partitionAndSort filters disabled plugins.
     */
    public function testPartitionAndSortFiltersDisabled(): void
    {
        $plugins = [
            [
                'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                'response' => 'allow',
                'weight' => 0,
                'enable' => true,
            ],
            [
                'plugin' => 'Kanopi\Firewall\Plugins\Url',
                'response' => 'block',
                'weight' => 0,
                'enable' => false,
            ],
        ];

        $result = PluginConfigNormalizer::partitionAndSort($plugins);

        $this->assertCount(1, $result['allow']);
        $this->assertCount(0, $result['block']);
    }

    /**
     * Test: partitionAndSort defaults response to block.
     */
    public function testPartitionAndSortDefaultsToBlock(): void
    {
        $plugins = [
            [
                'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                'weight' => 0,
                'enable' => true,
            ],
        ];

        $result = PluginConfigNormalizer::partitionAndSort($plugins);

        $this->assertCount(0, $result['allow']);
        $this->assertCount(1, $result['block']);
    }

    /**
     * Test: partitionAndSort missing enable defaults to true.
     */
    public function testPartitionAndSortMissingEnableDefaultsToTrue(): void
    {
        $plugins = [
            [
                'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                'response' => 'allow',
                'weight' => 0,
            ],
        ];

        $result = PluginConfigNormalizer::partitionAndSort($plugins);

        $this->assertCount(1, $result['allow']);
    }

    /**
     * Test: full workflow from legacy format to partitioned plugins.
     */
    public function testFullWorkflow(): void
    {
        // Start with legacy format
        $config = [
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => -200,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\Url' => [
                    'priority' => -100,
                    'enable' => true,
                    'config' => ['/admin'],
                ],
                'Kanopi\Firewall\Plugins\RateLimit' => [
                    'priority' => 100,
                    'enable' => true,
                    'config' => [],
                ],
            ],
        ];

        // Normalize to new format
        $normalized = PluginConfigNormalizer::normalize($config);

        // Partition and sort
        $partitioned = PluginConfigNormalizer::partitionAndSort($normalized['plugins']);

        // Verify allow plugins (bypasses)
        $this->assertCount(1, $partitioned['allow']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $partitioned['allow'][0]['plugin']);

        // Verify block plugins (sorted by weight: -100 before 100)
        $this->assertCount(2, $partitioned['block']);
        $this->assertEquals('Kanopi\Firewall\Plugins\Url', $partitioned['block'][0]['plugin']);
        $this->assertEquals('Kanopi\Firewall\Plugins\RateLimit', $partitioned['block'][1]['plugin']);
    }
}
