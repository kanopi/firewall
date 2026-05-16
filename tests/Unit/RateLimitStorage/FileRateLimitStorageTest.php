<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

require_once __DIR__ . '/../../Traits/NamespaceOverrides.php';

class FileRateLimitStorageTest extends AbstractTestCase
{
    protected string $tempFile;

    protected function setUp(): void
    {
        parent::setUp();
        // Create a temporary file for testing
        $this->tempFile = tempnam(sys_get_temp_dir(), 'ratelimit_test_');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }

        if (file_exists($this->tempFile . '.lock')) {
            unlink($this->tempFile . '.lock');
        }
    }

    /**
     * Test that requests are recorded and persisted to file.
     */
    public function testRecordAndPersistRequest(): void
    {
        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);
        $now = time();

        $storage->recordRequest('user:123', $now);

        $this->assertFileExists($this->tempFile);
        $data = $this->loadFromFile($this->tempFile);

        $this->assertArrayHasKey('user:123', $data);
        $this->assertContains($now, $data['user:123']);

        file_put_contents($this->tempFile, '');
        $GLOBALS['simulate_fwrite_failure'] = true;
        $GLOBALS['simulate_file_put_contents_failure'] = true;
        $storage->recordRequest('user:123', $now);

        clearstatcache();
        $size = filesize($this->tempFile);
        $GLOBALS['simulate_file_put_contents_failure'] = false;
        $this->assertEquals(0, $size, 'File Size on failure');
    }

    /**
     * Test that requests are correctly loaded from file.
     */
    public function testLoadFromFile(): void
    {
        $now = time();
        $initialData = ['ip:1.2.3.4' => [$now - 10, $now]];
        $this->persistToFile($initialData, $this->tempFile);

        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);

        $this->assertSame(2, $storage->countRequests('ip:1.2.3.4', $now - 20, $now + 1));
    }

    /**
     * Test that non-existent file does not cause failure.
     */
    public function testNonExistentFileIsHandled(): void
    {
        unlink($this->tempFile);
        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);

        $this->assertSame(0, $storage->countRequests('nonexistent:key', 0, time()));
    }

    /**
     * Test that invalid JSON does not cause a crash.
     */
    public function testInvalidJsonIsHandled(): void
    {
        file_put_contents($this->tempFile, '{invalid-json');

        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);

        $this->assertSame(0, $storage->countRequests('corrupt:key', 0, time()));
    }

    /**
     * Test that empty file is treated as empty dataset.
     */
    public function testEmptyFileHandled(): void
    {
        file_put_contents($this->tempFile, '');

        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);

        $this->assertSame(0, $storage->countRequests('key', 0, time()));
    }

    /**
     * Regression for #59: recordRequest() now wraps load → mutate → save
     * with an exclusive flock against a sidecar `.lock` file. Asserting
     * the lock file exists after a recordRequest call pins the contract;
     * the pre-fix code didn't lock and could race-bypass the rate limit
     * (both racing requests read N, both pass the check, both write N+1).
     */
    public function testRecordRequestCreatesSidecarLockFile(): void
    {
        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);
        $storage->recordRequest('ip:9.9.9.9', time());

        $this->assertFileExists($this->tempFile . '.lock');
    }

    /**
     * Regression for #59: when flock() fails, the call still has to land
     * the write. Tested via the namespace override.
     */
    public function testRecordRequestFallsBackWhenFlockFails(): void
    {
        $storage = new FileRateLimitStorage(['file' => $this->tempFile]);
        $now = time();

        $GLOBALS['simulate_flock_failure'] = true;
        try {
            $storage->recordRequest('user:42', $now);
        } finally {
            $GLOBALS['simulate_flock_failure'] = false;
        }

        $this->assertSame(1, $storage->countRequests('user:42', $now - 1, $now + 1));
    }
}
