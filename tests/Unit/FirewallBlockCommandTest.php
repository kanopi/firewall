<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Storage\FileStorage;

/**
 * `bin/firewall-block` (#291).
 *
 * A subprocess, like the other command tests: the exit codes are the contract,
 * and so is the stdout/stderr split that keeps `--json` parseable.
 */
final class FirewallBlockCommandTest extends AbstractTestCase
{
    private const EXIT_OK = 0;
    private const EXIT_UNANSWERABLE = 1;
    private const EXIT_USAGE = 2;

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-block-cmd-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runBlock(array $args): array
    {
        $command = array_merge(
            [PHP_BINARY, '-d', 'display_errors=stderr', dirname(__DIR__, 2) . '/bin/firewall-block'],
            $args
        );
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($command, $descriptors, $pipes);

        $this->assertIsResource($process, 'Could not start bin/firewall-block');

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    private function config(string $storageType = FileStorage::class): string
    {
        $path = $this->dir . '/config.yml';
        $yaml = "global: { mode: block }\nplugins: []\nstorage:\n  type: '" . $storageType . "'\n";

        if ($storageType === FileStorage::class) {
            $yaml .= "  config: { storage_file: '" . $this->dir . "/blocked.data' }\n";
        }

        file_put_contents($path, $yaml);

        return $path;
    }

    private function seed(): void
    {
        $storage = new FileStorage(['storage_file' => $this->dir . '/blocked.data']);
        $storage->set('203.0.113.5', ['request' => ['path' => '/wp-login.php']], 3600);
        $storage->set('198.51.100.20', ['request' => ['path' => '/']], 0);
        $storage->recordOffense('203.0.113.5');
    }

    /**
     * Listing names every block and the backend it read them from.
     *
     * The backend matters: an answer of "nothing blocked" means something
     * different depending on where it was looked for.
     */
    public function testListingShowsBlocksAndNamesTheBackend(): void
    {
        $this->seed();

        $result = $this->runBlock([$this->config(), '--list']);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertStringContainsString('203.0.113.5', $result['stdout']);
        $this->assertStringContainsString('198.51.100.20', $result['stdout']);
        $this->assertStringContainsString('FileStorage', $result['stdout']);
    }

    /**
     * A range narrows the list.
     */
    public function testFindNarrowsToARange(): void
    {
        $this->seed();

        $result = $this->runBlock([$this->config(), '--find=203.0.113.0/24']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('203.0.113.5', $result['stdout']);
        $this->assertStringNotContainsString('198.51.100.20', $result['stdout']);
    }

    /**
     * An address that is not blocked says so rather than printing nothing.
     */
    public function testShowingAnUnblockedAddressSaysSo(): void
    {
        $this->seed();

        $result = $this->runBlock([$this->config(), '--show=192.0.2.1']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('is not blocked', $result['stdout']);
    }

    /**
     * `--dry-run` removes nothing.
     *
     * Lifting is not reversible — the record is gone and the offence history
     * with it — so seeing what would go has to be possible without doing it.
     */
    public function testDryRunRemovesNothing(): void
    {
        $this->seed();
        $config = $this->config();

        $dry = $this->runBlock([$config, '--lift=203.0.113.5', '--dry-run']);

        $this->assertSame(self::EXIT_OK, $dry['code']);
        $this->assertStringContainsString('Nothing was removed', $dry['stdout']);
        $this->assertStringContainsString(
            '203.0.113.5',
            $this->runBlock([$config, '--list'])['stdout'],
            'It is still blocked'
        );
    }

    /**
     * Lifting removes the block and reports the count.
     */
    public function testLiftingRemovesTheBlock(): void
    {
        $this->seed();
        $config = $this->config();

        $result = $this->runBlock([$config, '--lift=203.0.113.5']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('1 record removed', $result['stdout']);
        $this->assertStringNotContainsString('203.0.113.5', $this->runBlock([$config, '--list'])['stdout']);
    }

    /**
     * A backend that cannot enumerate exits 1 and says why.
     *
     * Distinct from "nothing is blocked", which is an answer.
     */
    public function testANonQueryableBackendExitsOne(): void
    {
        $result = $this->runBlock([$this->config(\Kanopi\Firewall\Tests\Storage\NonQueryableStorage::class), '--list']);

        $this->assertSame(self::EXIT_UNANSWERABLE, $result['code']);
        $this->assertStringContainsString('cannot enumerate', $result['stderr']);
    }

    /**
     * A store that dies with the process warns, on stderr.
     *
     * Otherwise "nothing blocked" reads as "your customer is fine" when it
     * means "I looked somewhere that has never held anything".
     */
    public function testAnInMemoryStoreWarnsWithoutCorruptingStdout(): void
    {
        $result = $this->runBlock([
            $this->config(\Kanopi\Firewall\Storage\InMemoryStorage::class),
            '--list',
            '--json',
        ]);

        $this->assertSame(self::EXIT_OK, $result['code']);

        $decoded = json_decode($result['stdout'], true);

        $this->assertIsArray($decoded, 'stdout stays parseable: ' . $result['stdout']);
        $this->assertFalse($decoded['backend']['durable']);
        $this->assertStringContainsString('does not outlive the process', (string) $decoded['warning']);
    }

    /**
     * `--json` is parseable and carries the records.
     */
    public function testJsonOutputIsParseable(): void
    {
        $this->seed();

        $result = $this->runBlock([$this->config(), '--list', '--json']);
        $decoded = json_decode($result['stdout'], true);

        $this->assertIsArray($decoded, $result['stdout']);
        $this->assertSame(2, $decoded['count']);
        $this->assertArrayHasKey('203.0.113.5', $decoded['records']);
    }

    /**
     * Two actions at once is a usage error rather than a guess.
     *
     * `--lift` with `--find` reads as "lift what this finds", which is not what
     * it would do — and guessing is the wrong instinct for a command that
     * deletes things.
     */
    public function testTwoActionsIsAUsageError(): void
    {
        $result = $this->runBlock([$this->config(), '--list', '--find=203.0.113.5']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('Choose one of', $result['stderr']);
    }

    /**
     * The remaining usage failures.
     */
    public function testUsageFailures(): void
    {
        $this->assertSame(self::EXIT_USAGE, $this->runBlock([])['code'], 'No config');
        $this->assertSame(self::EXIT_USAGE, $this->runBlock(['/nope.yml'])['code'], 'Missing config');
        $this->assertSame(self::EXIT_USAGE, $this->runBlock([$this->config(), '--dry-run'])['code'], 'dry-run alone');
        $this->assertSame(self::EXIT_USAGE, $this->runBlock([$this->config(), '--nonsense'])['code'], 'Unknown option');
    }

    /**
     * `--help` explains itself and exits 0.
     */
    public function testHelpExitsZero(): void
    {
        $result = $this->runBlock(['--help']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('firewall-block', $result['stdout']);
    }
}
