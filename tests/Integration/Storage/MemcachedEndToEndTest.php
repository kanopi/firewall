<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Storage\MemcachedStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Memcached;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The firewall and its operator tools, with the block list on a real Memcached (#392).
 *
 * `MemcachedStorageIntegrationTest` calls the storage directly. This drives it the way a site
 * does: a rule blocks a client and a *separate* firewall -- a separate request, in effect --
 * refuses that client on the block list alone; a repeat hit extends the ban and is counted;
 * escalation reads the offense history back out of Memcached. Then `bin/firewall block` and
 * `bin/firewall doctor` are run as processes against the same server, which is how an
 * operator meets this backend.
 */
#[RequiresPhpExtension('memcached')]
final class MemcachedEndToEndTest extends IntegrationTestCase
{
    private string $prefix;

    private string $dir;

    private bool $reachable = false;

    protected function setUp(): void
    {
        parent::setUp();

        putenv('FIREWALL_BYPASS_CLI=1');
        $this->skipIfGroupDisabled('memcached');
        $this->prefix = 'fwtest:' . bin2hex(random_bytes(6)) . ':';

        $config = self::getMemcachedConfig();
        $probe = new Memcached();
        $probe->setOption(Memcached::OPT_CONNECT_TIMEOUT, 500);
        $probe->addServer((string) $config['host'], (int) $config['port']);

        if ($probe->getVersion() === false) {
            $this->markTestSkipped('No Memcached server reachable with the configured settings.');
        }

        $this->reachable = true;
        $this->dir = sys_get_temp_dir() . '/fw-memcached-e2e-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        if ($this->reachable) {
            $this->storage()->reset();

            foreach (glob($this->dir . '/*') ?: [] as $file) {
                @unlink($file);
            }

            @rmdir($this->dir);
        }

        parent::tearDown();
    }

    /**
     * @return array{type: string, config: array<string, mixed>}
     */
    private function storageConfig(): array
    {
        $config = self::getMemcachedConfig();

        return [
            'type' => MemcachedStorage::class,
            'config' => ['memcached' => [
                'host' => (string) $config['host'],
                'port' => (int) $config['port'],
                'prefix' => $this->prefix,
            ]],
        ];
    }

    private function storage(): MemcachedStorage
    {
        return new MemcachedStorage($this->storageConfig()['config']);
    }

    /**
     * A firewall on this run's block list.
     *
     * @param array<int, string> $blockedAddresses
     *   Addresses an IpAddress rule blocks. Empty for a firewall that can only refuse a
     *   client because the block list says so.
     * @param array<string, mixed> $global
     *   Extra `global:` settings.
     */
    private function firewall(array $blockedAddresses = [], array $global = []): Firewall
    {
        $plugins = $blockedAddresses === [] ? [] : [[
            'plugin' => IpAddress::class,
            'response' => 'block',
            'enable' => true,
            'metadata' => ['default_expiration_time' => 600],
            'config' => $blockedAddresses,
        ]];

        return Firewall::create([[
            'global' => ['mode' => 'exception'] + $global,
            'storage' => $this->storageConfig(),
            'plugins' => $plugins,
        ]]);
    }

    private function request(string $ip, string $path = '/'): Request
    {
        return Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
    }

    private function assertRefused(Firewall $firewall, Request $request, string $message): void
    {
        try {
            $firewall->evaluate($request);
            $this->fail($message);
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }
    }

    // -----------------------------------------------------------------------
    // The request path
    // -----------------------------------------------------------------------

    /**
     * The whole point of a shared block list: a ban earned on one request is enforced on
     * the next by a firewall that has no rule against the client at all.
     */
    public function testABlockedClientIsRefusedOnItsNextRequest(): void
    {
        $this->assertRefused($this->firewall(['203.0.113.5']), $this->request('203.0.113.5', '/wp-login.php'), 'The rule should block');

        $record = $this->storage()->find('203.0.113.5')['203.0.113.5'] ?? null;
        $this->assertNotNull($record, 'The block is in Memcached');
        $this->assertSame('/wp-login.php', $record['value']['request']['path'] ?? null);
        $this->assertEqualsWithDelta(time() + 600, $record['expire'], 5);

        // A second firewall with no rules: only the block list can refuse.
        $this->assertRefused($this->firewall(), $this->request('203.0.113.5', '/'), 'The block list should refuse a known client');
        $this->assertTrue($this->firewall()->evaluate($this->request('198.51.100.7')), 'Anyone else is let through');
    }

    /**
     * A blocked client that keeps coming back has its ban extended and each attempt
     * counted -- `addToExpire()` and `recordOffense()`, from the request path.
     */
    public function testARepeatHitExtendsTheBanAndIsCounted(): void
    {
        $this->assertRefused($this->firewall(['203.0.113.5']), $this->request('203.0.113.5'), 'The rule should block');
        $before = $this->storage()->find('203.0.113.5')['203.0.113.5'];

        $this->assertRefused(
            $this->firewall([], ['add_to_expire' => 900]),
            $this->request('203.0.113.5'),
            'The block list should refuse the repeat'
        );

        $after = $this->storage()->find('203.0.113.5')['203.0.113.5'];
        $this->assertSame($before['expire'] + 900, $after['expire']);
        $this->assertSame($before['offenses'] + 1, $after['offenses']);
    }

    /**
     * Escalation reads the offense history back out of Memcached: history that outlived
     * the first ban turns the second into a permanent one.
     */
    public function testEscalationReadsTheHistoryThatOutlivedTheBan(): void
    {
        $escalation = ['blocking_escalation' => [
            ['window' => 3600, 'offense' => 0],
            ['window' => 3600, 'offense' => 1, 'duration' => 0],
        ]];

        $first = Firewall::create([[
            'global' => ['mode' => 'exception'] + $escalation,
            'storage' => $this->storageConfig(),
            'plugins' => [[
                'plugin' => IpAddress::class,
                'response' => 'block',
                'enable' => true,
                'metadata' => ['default_expiration_time' => 1],
                'config' => ['203.0.113.5'],
            ]],
        ]]);

        $this->assertRefused($first, $this->request('203.0.113.5'), 'First offence');
        $this->assertGreaterThan(0, $this->storage()->find('203.0.113.5')['203.0.113.5']['expire'], 'A first offence is temporary');

        // Let Memcached drop the first ban. The offense history stays behind.
        sleep(2);
        $this->assertSame([], $this->storage()->find('203.0.113.5'));
        $this->assertSame(1, $this->storage()->countOffenses('203.0.113.5'));

        $this->assertRefused($first, $this->request('203.0.113.5'), 'Second offence');
        $this->assertSame(0, $this->storage()->find('203.0.113.5')['203.0.113.5']['expire'], 'Escalated to permanent');
    }

    // -----------------------------------------------------------------------
    // The operator tools
    // -----------------------------------------------------------------------

    private function configFile(): string
    {
        $path = $this->dir . '/firewall.yml';
        file_put_contents($path, Yaml::dump([
            'global' => ['mode' => 'block'],
            'plugins' => [],
            'storage' => $this->storageConfig(),
        ], 6));

        return $path;
    }

    /**
     * Run one of the bin/ commands as a process.
     *
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runCommand(string $command, array $args): array
    {
        // display_errors=stderr: the CI image prints "Module ... is already
        // loaded" on every PHP start, which would otherwise corrupt stdout.
        $process = proc_open(
            array_merge([PHP_BINARY, '-d', 'display_errors=stderr', dirname(__DIR__, 3) . '/bin/' . $command], $args),
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        $this->assertIsResource($process, 'Could not start bin/' . $command);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    /**
     * @return array<string, mixed>
     */
    private function json(array $result): array
    {
        $decoded = json_decode($result['stdout'], true);
        $this->assertIsArray($decoded, 'stdout is JSON: ' . $result['stdout'] . $result['stderr']);

        return $decoded;
    }

    private function seed(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['request' => ['path' => '/wp-login.php']], 600);
        $storage->set('203.0.113.99', ['request' => ['path' => '/xmlrpc.php']], 600);
        $storage->set('198.51.100.7', ['request' => ['path' => '/']], 0);
    }

    /**
     * `--list`, `--find`, `--show` and `--lift` all answer from the real server.
     */
    public function testFirewallBlockListsFindsShowsAndLifts(): void
    {
        $this->seed();
        $config = $this->configFile();

        $list = $this->json($this->runCommand('firewall block', [$config, '--list', '--json']));
        $this->assertSame(3, $list['count']);
        $this->assertSame(MemcachedStorage::class, $list['backend']['class']);
        $this->assertTrue($list['backend']['queryable']);
        $this->assertNull($list['backend']['gap']);
        $this->assertNull($list['warning']);

        $find = $this->json($this->runCommand('firewall block', [$config, '--find=203.0.113.0/24', '--json']));
        $this->assertEqualsCanonicalizing(['203.0.113.5', '203.0.113.99'], array_keys($find['records']));

        $show = $this->json($this->runCommand('firewall block', [$config, '--show=203.0.113.5', '--json']));
        $this->assertTrue($show['blocked']);
        $this->assertCount(1, $show['offenses']);

        $dryRun = $this->json($this->runCommand('firewall block', [$config, '--lift=203.0.113.0/24', '--dry-run', '--json']));
        $this->assertSame(0, $dryRun['removed']);
        $this->assertTrue($this->storage()->exists('203.0.113.5'), 'A dry run removes nothing');

        $lift = $this->json($this->runCommand('firewall block', [$config, '--lift=203.0.113.0/24', '--json']));
        $this->assertSame(2, $lift['removed']);
        $this->assertFalse($this->storage()->exists('203.0.113.5'));
        $this->assertSame(0, $this->storage()->countOffenses('203.0.113.5'));
        $this->assertTrue($this->storage()->exists('198.51.100.7'), 'Outside the range, untouched');
    }

    /**
     * An evicted shard reaches the operator: a warning on stderr and in the JSON, while a
     * single address is still found.
     */
    public function testFirewallBlockWarnsWhenTheIndexHasLostAShard(): void
    {
        $this->seed();
        $config = $this->configFile();
        $this->evictShardOf('203.0.113.5');

        $text = $this->runCommand('firewall block', [$config, '--find=203.0.113.0/24']);
        $this->assertSame(0, $text['code'], $text['stderr']);
        $this->assertStringContainsString('Results may be incomplete', $text['stderr']);

        $show = $this->json($this->runCommand('firewall block', [$config, '--show=203.0.113.5', '--json']));
        $this->assertTrue($show['blocked'], 'An exact address does not depend on the index');
        $this->assertNotNull($show['backend']['gap']);
    }

    /**
     * The doctor says nothing about a healthy index, and warns about a damaged one.
     */
    public function testFirewallDoctorReportsAGapOnlyWhenThereIsOne(): void
    {
        $this->seed();
        $config = $this->configFile();

        $healthy = $this->runCommand('firewall doctor', [$config, '--json']);
        $this->assertNotContains('Block list searches may be incomplete', $this->titles($healthy));
        $this->assertStringNotContainsString('Failed to initialize Memcached storage', $healthy['stderr'] . $healthy['stdout']);

        $this->evictShardOf('203.0.113.5');

        $damaged = $this->runCommand('firewall doctor', [$config, '--json']);
        $finding = array_values(array_filter(
            $this->json($damaged)['findings'],
            static fn(array $f): bool => $f['title'] === 'Block list searches may be incomplete'
        ));

        $this->assertCount(1, $finding);
        $this->assertSame('warning', $finding[0]['status']);
        $this->assertStringContainsString('index shards', (string) $finding[0]['detail']);
    }

    /**
     * @return array<int, string>
     */
    private function titles(array $result): array
    {
        return array_column($this->json($result)['findings'], 'title');
    }

    private function evictShardOf(string $key): void
    {
        $config = self::getMemcachedConfig();
        $memcached = new Memcached();
        $memcached->addServer((string) $config['host'], (int) $config['port']);
        $memcached->delete($this->prefix . 'index:' . (crc32($key) % MemcachedStorage::INDEX_SHARDS));
    }
}
