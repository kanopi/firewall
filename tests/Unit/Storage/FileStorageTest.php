<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use RuntimeException;

require_once __DIR__ . '/../../Traits/NamespaceOverrides.php';

/**
 * Unit tests for FileStorage class.
 */
class FileStorageTest extends AbstractTestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        parent::setUp();
        // Create a temporary file to use for testing
        $this->tempFile = tempnam(sys_get_temp_dir(), 'filestorage_test_');

        $GLOBALS['simulate_is_readable_failure'] = false;
        $GLOBALS['simulate_is_writeable_failure'] = false;
        $GLOBALS['simulate_fwrite_failure'] = false;
        $GLOBALS['simulate_fopen_failure'] = false;
        $GLOBALS['simulate_fgets_failure'] = false;
        $GLOBALS['simulate_flock_failure'] = false;
    }

    protected function tearDown(): void
    {
        // Restore permissions so it can be cleaned up after test
        @chmod($this->tempFile, 0600);
        @unlink($this->tempFile);
        // Lock sidecar from any flock-using write path
        @unlink($this->tempFile . '.lock');
    }

    /**
     * Tests that FileStorage constructor throws if file is not writable.
     */
    public function testConstructorThrowsIfFileNotWritable(): void
    {
        $unwritableFile = '/root/forbidden_file';

        $this->expectException(RuntimeException::class);
        new FileStorage(['storage_file' => $unwritableFile]);
    }

    /**
     * Tests that data is loaded from file on construction.
     */
    public function testDataLoadsFromFile(): void
    {
        $this->persistToFile([
            '127.0.0.1' => ['value' => ['event_id' => 'data'], 'expire' => 0],
        ], $this->tempFile);

        $storage = new FileStorage(['storage_file' => $this->tempFile]);

        $request = $this->getRequest('127.0.0.1', 'data');
        $this->assertSame('data', $storage->get($request->getClientIp())['event_id']);
    }

    /**
     * Tests that corrupted file content does not crash and results in empty store.
     */
    public function testCorruptDataInFileDoesNotCrash(): void
    {
        file_put_contents($this->tempFile, 'not-serialized-data');

        $storage = new FileStorage(['storage_file' => $this->tempFile]);

        $request = $this->getRequest();
        $this->assertFalse($storage->exists($request->getClientIp()));
    }

    /**
     * Tests that set() persists data to file.
     */
    public function testSetPersistsToFile(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null));

        $reloaded = new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertSame('abc', $reloaded->get($request->getClientIp())['event_id']);
    }

    /**
     * Tests that delete() removes data and persists to file.
     */
    public function testDeletePersistsToFile(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null));

        $this->assertTrue($storage->delete($request->getClientIp()));

        $reloaded = new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertFalse($reloaded->exists($request->getClientIp()));
    }

    /**
     * Tests that reset() clears all data and persists to file.
     */
    public function testResetPersistsToFile(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null));
        $storage->reset();

        $reloaded = new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertFalse($reloaded->exists($request->getClientIp()));
    }

    /**
     * Tests that addToExpire() updates expiration and persists the change.
     */
    public function testAddToExpirePersists(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null), 2);
        $storage->addToExpire($request->getClientIp(), 5);

        $reloaded = new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertSame('abc', $reloaded->get($request->getClientIp())['event_id']);
    }

    /**
     * Tests that addToExpire fails for keys with no expiration.
     */
    public function testAddToExpireFailsIfNoExpiration(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null), 0);

        $this->assertFalse($storage->addToExpire($request->getClientIp(), 5));
    }

    /**
     * Tests that file is touched and created if it does not exist.
     */
    public function testConstructorCreatesFileIfNotExists(): void
    {
        unlink($this->tempFile); // Delete to simulate fresh creation
        $this->assertFalse(file_exists($this->tempFile));

        new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertFileExists($this->tempFile);
    }

    /**
     * Tests that a failed file write triggers the logger error call.
     */
    public function testSetLogsErrorOnWriteFailure(): void
    {
        $GLOBALS['simulate_fwrite_failure'] = true;
        $GLOBALS['simulate_file_put_contents_failure'] = true;

        LoggingFactory::setLogger(LoggingFactory::create([
            [
                'class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class
            ]
        ]));

        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), ['value' => 1]);

        $GLOBALS['simulate_fwrite_failure'] = false;
        $GLOBALS['simulate_file_put_contents_failure'] = false;

        // ✅ Assert that an error log was generated
        $this->assertTrue(
            LoggingFactory::logger()->getHandlers()[0]->hasErrorContaining('Failed to write to storage'),
            'Expected error message was not logged'
        );
    }

    /**
     * Tests that FileStorage throws if the file exists but is not readable/writable.
     */
    public function testConstructorThrowsIfFileNotWritableToLoad(): void
    {
        $GLOBALS['simulate_is_writeable_failure'] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("must be writeable");

        new FileStorage(['storage_file' => $this->tempFile]);

        $GLOBALS['simulate_is_writeable_failure'] = false;
    }

    /**
     * Tests that FileStorage throws if the file exists but is not readable/writable.
     */
    public function testConstructorThrowsIfFileNotReadableToLoad(): void
    {
        $GLOBALS['simulate_is_readable_failure'] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("must be readable");

        new FileStorage(['storage_file' => $this->tempFile]);

        $GLOBALS['simulate_is_readable_failure'] = false;
    }

    /**
     * Test Count Offenses.
     */
    public function testFileStorageCountOffenses(): void
    {
        $tempOffenseFile = tempnam(sys_get_temp_dir(), 'filestorage_offense_test_');
        $tempStorageFile = tempnam(sys_get_temp_dir(), 'filestorage_test_');

        $storage = new FileStorage(['storage_file' => $tempStorageFile, 'offense_file' => $tempOffenseFile]);
        $request = $this->getRequest();
        $this->assertEquals(0, $storage->countOffenses($request->getClientIp()));

        $storage->recordOffense($request->getClientIp());
        $this->assertEquals(1, $storage->countOffenses($request->getClientIp()));

        @unlink($tempStorageFile);
        @unlink($tempOffenseFile);
    }

    /**
     * Regression for #59: a sidecar `.lock` file should exist next to the
     * data file after any write path. Pre-fix the read-modify-write
     * sequence didn't lock at all, so concurrent writers could lose data.
     */
    public function testSetCreatesSidecarLockFile(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();
        $storage->set($request->getClientIp(), $storage->getStorageData($request, null));

        $this->assertFileExists($this->tempFile . '.lock');
    }

    /**
     * Regression for #59: when `flock()` itself fails (e.g. NFS without lock
     * daemon support), the call must not throw — fall back to running the
     * action and log a warning. We simulate the failure via the namespace
     * override and verify the write still lands.
     */
    public function testSetFallsBackWhenFlockFails(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();

        $GLOBALS['simulate_flock_failure'] = true;
        try {
            $this->assertTrue(
                $storage->set($request->getClientIp(), $storage->getStorageData($request, null))
            );
        } finally {
            $GLOBALS['simulate_flock_failure'] = false;
        }

        // Even without a lock, the write still has to persist.
        $reloaded = new FileStorage(['storage_file' => $this->tempFile]);
        $this->assertSame('abc', $reloaded->get($request->getClientIp())['event_id']);
    }

    /**
     * Regression for #59: when the lock file itself can't be opened, the
     * call must not throw. Use the fopen-failure shim from
     * NamespaceOverrides.
     */
    public function testSetFallsBackWhenLockFileCannotBeOpened(): void
    {
        $storage = new FileStorage(['storage_file' => $this->tempFile]);
        $request = $this->getRequest();

        $GLOBALS['simulate_fopen_failure'] = true;
        try {
            $this->assertTrue(
                $storage->set($request->getClientIp(), $storage->getStorageData($request, null))
            );
        } finally {
            $GLOBALS['simulate_fopen_failure'] = false;
        }
    }
}
