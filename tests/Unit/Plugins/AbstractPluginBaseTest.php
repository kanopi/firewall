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
     * Tests that no provider is named unless metadata says so.
     */
    public function testNoChallengeProviderByDefault(): void
    {
        // NULL, not '', because the firewall reads it as "use whatever
        // challenge.provider names" — the behaviour every plugin had before
        // this key existed.
        $plugin = new TestablePlugin();
        $this->assertNull($plugin->getChallengeProviderName());
    }

    /**
     * Tests that metadata.challenge_provider names the plugin's provider.
     */
    public function testChallengeProviderComesFromMetadata(): void
    {
        $plugin = new TestablePlugin(['challenge_provider' => 'recaptcha']);
        $this->assertSame('recaptcha', $plugin->getChallengeProviderName());
    }

    /**
     * Tests that surrounding whitespace in the metadata value is trimmed.
     */
    public function testChallengeProviderIsTrimmed(): void
    {
        $plugin = new TestablePlugin(['challenge_provider' => "  altcha\n"]);
        $this->assertSame('altcha', $plugin->getChallengeProviderName());
    }

    /**
     * Tests values that name nothing usable fall back to the global provider.
     *
     * @param mixed $value
     *   The metadata value under test.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('unusableChallengeProviderProvider')]
    public function testUnusableChallengeProviderFallsBack(mixed $value): void
    {
        $plugin = new TestablePlugin(['challenge_provider' => $value]);
        $this->assertNull($plugin->getChallengeProviderName());
    }

    /**
     * @return array<string, array{0: mixed}>
     *   Keyed by what is wrong with the value.
     */
    public static function unusableChallengeProviderProvider(): array
    {
        return [
            'empty string' => [''],
            'whitespace only' => ['   '],
            'an array' => [['recaptcha']],
            'a boolean' => [true],
            'null' => [null],
        ];
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
     * Regression for #78: a plugin config file that cannot be read left the
     * plugin with an empty rule list — for a block plugin, one that matches
     * nothing — without saying so. The plugin now logs the failure.
     */
    public function testPluginLogsWhenConfigFileCannotBeLoaded(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $missing = sys_get_temp_dir() . '/fw78-plugin-missing-' . uniqid() . '.yaml';
        $plugin = new TestablePlugin(['config' => $missing], ['inline' => true]);

        // The inline config still applies — only the unreadable file is lost.
        $this->assertSame(['inline' => true], $plugin->getRawConfig());
        $this->assertTrue(
            $handler->hasRecordThatContains('Plugin config file failed to load', Level::Error),
            'Expected an error log naming the plugin config file that did not load.'
        );
    }

    /**
     * Regression for #78: a plugin whose config files all load says nothing
     * at error level.
     */
    public function testPluginLogsNoErrorWhenConfigFileLoads(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $file = __DIR__ . '/config-loads.yaml';
        file_put_contents($file, "featureA: true\n");

        try {
            new TestablePlugin(['config' => $file], ['inline' => true]);

            $this->assertFalse(
                $handler->hasRecordThatContains('Plugin config file failed to load', Level::Error),
                'The config file loaded — no error should be reported.'
            );
        } finally {
            unlink($file);
        }
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
