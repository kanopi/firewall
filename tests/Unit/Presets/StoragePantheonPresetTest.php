<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Presets;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;

/**
 * Tests that storage-pantheon.yml reads the connection out of PRESSFLOW_SETTINGS.
 *
 * Every token falls back under `safe:`, and the fallbacks are DDEV's own
 * credentials, so a token that cannot read the JSON still resolves -- to
 * `db`/`db`@`db:3306`. That works locally under DDEV and fails on Pantheon,
 * where storage then cannot connect and the firewall lets traffic through
 * (#446). Only checking that the preset loads would never notice.
 */
class StoragePantheonPresetTest extends AbstractTestCase
{
    /**
     * What Pantheon puts in PRESSFLOW_SETTINGS, trimmed to what the preset reads.
     */
    private const SETTINGS = [
        'databases' => [
            'default' => [
                'default' => [
                    'database' => 'pantheon',
                    'username' => 'pantheon',
                    'password' => 's3cret',
                    'host' => 'dbserver.abc123.drush.in',
                    'port' => 12345,
                    'driver' => 'mysql',
                ],
            ],
        ],
    ];

    private string|false $savedEnv = false;

    private mixed $savedServer = null;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        Config::clearLoadErrors();

        $this->savedEnv = getenv('PRESSFLOW_SETTINGS');
        $this->savedServer = $_SERVER['PRESSFLOW_SETTINGS'] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        putenv($this->savedEnv === false ? 'PRESSFLOW_SETTINGS' : 'PRESSFLOW_SETTINGS=' . $this->savedEnv);

        if ($this->savedServer === null) {
            unset($_SERVER['PRESSFLOW_SETTINGS']);
        } else {
            $_SERVER['PRESSFLOW_SETTINGS'] = $this->savedServer;
        }

        parent::tearDown();
    }

    /**
     * The connection the preset resolves to.
     *
     * @return array<string, mixed>
     */
    private function connection(): array
    {
        $config = Config::loadFile(dirname(__DIR__, 3) . '/presets/storage-pantheon.yml');

        $this->assertSame([], Config::getLoadErrors(), 'The preset itself must load cleanly.');

        $connection = $config['storage']['config']['connection'] ?? null;
        $this->assertIsArray($connection);

        return $connection;
    }

    /**
     * On Pantheon, every value comes from PRESSFLOW_SETTINGS.
     */
    public function testEveryValueIsReadFromPressflowSettings(): void
    {
        $json = (string) json_encode(self::SETTINGS);
        putenv('PRESSFLOW_SETTINGS=' . $json);
        $_SERVER['PRESSFLOW_SETTINGS'] = $json;

        $this->assertSame([
            'dbname' => 'pantheon',
            'user' => 'pantheon',
            'password' => 's3cret',
            'host' => 'dbserver.abc123.drush.in',
            'port' => 12345,
            'driver' => 'pdo_mysql',
        ], $this->connection());
    }

    /**
     * Off Pantheon, the fallbacks apply rather than the load failing.
     */
    public function testTheFallbacksApplyWhenTheVariableIsUnset(): void
    {
        putenv('PRESSFLOW_SETTINGS');
        unset($_SERVER['PRESSFLOW_SETTINGS']);

        $this->assertSame([
            'dbname' => 'db',
            'user' => 'db',
            'password' => 'db',
            'host' => 'db',
            'port' => '3306',
            'driver' => 'pdo_mysql',
        ], $this->connection());
    }
}
