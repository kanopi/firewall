<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

require_once __DIR__ . '/../../RateLimitStorage/NamespaceOverrides.php';

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
        $data = json_decode(file_get_contents($this->tempFile), true);

        $this->assertArrayHasKey('user:123', $data);
        $this->assertContains($now, $data['user:123']);

        file_put_contents($this->tempFile, '');
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
        file_put_contents($this->tempFile, json_encode($initialData));

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
}
