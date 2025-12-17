<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Kanopi\Firewall\Tests\Plugins\TestablePlugin;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\TestHandler;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for AbstractPluginBase.
 */
final class AbstractPluginBaseTest extends AbstractTestCase
{
    protected function tearDown(): void
    {
        // Reset logger between tests
        $ref = new \ReflectionClass(LoggingFactory::class);
        $prop = $ref->getProperty('logger');
        $prop->setAccessible(true);
        $prop->setValue(null);
    }

    /**
     * Tests that getStatusCode returns default value (400) if not set in metadata.
     */
    public function testDefaultStatusCode(): void
    {
        $plugin = new TestablePlugin();
        $this->assertSame(400, $plugin->getStatusCode());
    }

    /**
     * Tests that getStatusCode returns custom value from metadata.
     */
    public function testCustomStatusCode(): void
    {
        $plugin = new TestablePlugin(['status_code' => 418]);
        $this->assertSame(418, $plugin->getStatusCode());
    }

    /**
     * Tests that getExpirationTime returns default value (0) if not set.
     */
    public function testDefaultExpirationTime(): void
    {
        $plugin = new TestablePlugin();
        $this->assertSame(0, $plugin->getExpirationTime());
    }

    /**
     * Tests that getExpirationTime returns custom value from metadata.
     */
    public function testCustomExpirationTime(): void
    {
        $plugin = new TestablePlugin(['default_expiration_time' => 900]);
        $this->assertSame(900, $plugin->getExpirationTime());
    }

    /**
     * Tests that multiple YAML files in metadata are merged with inline config.
     */
    public function testConfigMergesMultipleYamlFilesAndInline(): void
    {
        $file1 = __DIR__ . '/config1.yaml';
        $file2 = __DIR__ . '/config2.yaml';

        file_put_contents($file1, "featureA: true\n");
        file_put_contents($file2, "featureB: 'yes'\n");

        $plugin = new TestablePlugin(['config' => [$file1, $file2]], ['featureC' => 123]);

        $this->assertSame([
            'featureA' => true,
            'featureB' => 'yes',
            'featureC' => 123,
        ], $plugin->getRawConfig());

        unlink($file1);
        unlink($file2);
    }

    /**
     * Tests that a single YAML string path in metadata['config'] is normalized and merged.
     */
    public function testSingleYamlConfigIsMerged(): void
    {
        $file = __DIR__ . '/config-single.yaml';
        file_put_contents($file, "debug: true\n");

        $plugin = new TestablePlugin(['config' => $file], ['env' => 'test']);

        $this->assertSame([
            'debug' => true,
            'env' => 'test',
        ], $plugin->getRawConfig());

        unlink($file);
    }

    /**
     * Tests that LoggingTrait logs messages when triggered through AbstractPluginBase.
     */
    public function testLoggingTraitWritesLog(): void
    {
        $handler = new TestHandler();
        $logger = new Logger('test-log');
        $logger->pushHandler($handler);

        LoggingFactory::setLogger($logger);

        $plugin = new TestablePlugin();
        $plugin->triggerLog();

        $this->assertTrue($handler->hasInfoRecords());
        $this->assertTrue($handler->hasRecordThatContains('Testing log call', Level::Info));
    }

    /**
     * Tests AbstractPluginBase::__construct().
     *
     * Confirms that if a string is passed through to the $metadata["config"]
     * that if it looks like a URL it allows for it to load.
     */
    public function testMetadataConstructorWithUrl(): void
    {
        $config_url = "https://gist.githubusercontent.com/sean-e-dietrich/24f023f6e5ea0dc8eb5f631e95f60759/raw/1564049a49078eaf1e805b60b9d361b6d0400339/firewall.yaml";
        $metadata = [
            'config' => $config_url,
        ];
        $config = [];
        $plugin = new class ($metadata, $config) extends AbstractPluginBase {
            public function getName(): string
            {
                return 'test';
            }

            public function getDescription(): string
            {
                return '';
            }

            public function evaluate(Request $request): bool
            {
                return true;
            }

            public function getConfig(): array
            {
                return $this->config;
            }

            public function getFiles(): array
            {
                return $this->files;
            }
        };

        $this->assertIsArray($plugin->getFiles());
        $this->assertTrue(in_array($config_url, $plugin->getFiles(), true));
    }

    /**
     * Tests AbstractPluginBase::__construct().
     *
     * Confirms that if anything other than a string or array is passed through
     * to the metadata["config"] that it just turns it into an empty array.
     */
    public function testMetadataConstructorWithNonString(): void
    {
        $config_url = (object) [];
        $metadata = [
            'config' => $config_url,
        ];
        $config = [];
        $plugin = new class ($metadata, $config) extends AbstractPluginBase {
            public function getName(): string
            {
                return 'test';
            }

            public function getDescription(): string
            {
                return '';
            }

            public function evaluate(Request $request): bool
            {
                return true;
            }

            public function getConfig(): array
            {
                return $this->config;
            }

            public function getFiles(): array
            {
                return $this->files;
            }
        };

        $this->assertIsArray($plugin->getFiles());
        $this->assertTrue(empty($plugin->getFiles()));
    }
}
