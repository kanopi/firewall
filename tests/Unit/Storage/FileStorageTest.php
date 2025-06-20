<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\FileStorage;
use PHPUnit\Framework\TestCase;
use RuntimeException;

require_once __DIR__ . '/../../Storage/NamespaceOverrides.php';

/**
 * Unit tests for FileStorage class.
 */
class FileStorageTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        // Create a temporary file to use for testing
        $this->tempFile = tempnam(sys_get_temp_dir(), 'filestorage_test_');
    }

    protected function tearDown(): void
    {
        // Restore permissions so it can be cleaned up after test
        @chmod($this->tempFile, 0600);
        @unlink($this->tempFile);
    }

    /**
     * Tests that FileStorage constructor throws if 'file' is missing.
     */
    public function testConstructorThrowsIfFileMissing(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Missing or invalid 'file' path in configuration.");

        new FileStorage([]);
    }

    /**
     * Tests that FileStorage constructor throws if file is not writable.
     */
    public function testConstructorThrowsIfFileNotWritable(): void
    {
        $unwritableFile = '/root/forbidden_file';

        $this->expectException(RuntimeException::class);
        new FileStorage(['file' => $unwritableFile]);
    }

    /**
     * Tests that data is loaded from file on construction.
     */
    public function testDataLoadsFromFile(): void
    {
        $data = serialize([
            'mykey' => ['value' => 'data', 'expire' => 0],
        ]);
        file_put_contents($this->tempFile, $data);

        $storage = new FileStorage(['file' => $this->tempFile]);
        $this->assertSame('data', $storage->get('mykey'));
    }

    /**
     * Tests that corrupted file content does not crash and results in empty store.
     */
    public function testCorruptDataInFileDoesNotCrash(): void
    {
        file_put_contents($this->tempFile, 'not-serialized-data');

        $storage = new FileStorage(['file' => $this->tempFile]);
        $this->assertFalse($storage->exists('mykey'));
    }

    /**
     * Tests that set() persists data to file.
     */
    public function testSetPersistsToFile(): void
    {
        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('test', 'persisted');

        $reloaded = new FileStorage(['file' => $this->tempFile]);
        $this->assertSame('persisted', $reloaded->get('test'));
    }

    /**
     * Tests that delete() removes data and persists to file.
     */
    public function testDeletePersistsToFile(): void
    {
        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('todelete', 'value');

        $this->assertTrue($storage->delete('todelete'));

        $reloaded = new FileStorage(['file' => $this->tempFile]);
        $this->assertFalse($reloaded->exists('todelete'));
    }

    /**
     * Tests that reset() clears all data and persists to file.
     */
    public function testResetPersistsToFile(): void
    {
        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('one', 'value');
        $storage->reset();

        $reloaded = new FileStorage(['file' => $this->tempFile]);
        $this->assertFalse($reloaded->exists('one'));
    }

    /**
     * Tests that addToExpire() updates expiration and persists the change.
     */
    public function testAddToExpirePersists(): void
    {
        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('session', 'data', 2);
        $storage->addToExpire('session', 5);

        $reloaded = new FileStorage(['file' => $this->tempFile]);
        $this->assertSame('data', $reloaded->get('session'));
    }

    /**
     * Tests that addToExpire fails for keys with no expiration.
     */
    public function testAddToExpireFailsIfNoExpiration(): void
    {
        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('static', 'value', 0);

        $this->assertFalse($storage->addToExpire('static', 5));
    }

    /**
     * Tests that file is touched and created if it does not exist.
     */
    public function testConstructorCreatesFileIfNotExists(): void
    {
        unlink($this->tempFile); // Delete to simulate fresh creation
        $this->assertFalse(file_exists($this->tempFile));

        new FileStorage(['file' => $this->tempFile]);
        $this->assertFileExists($this->tempFile);
    }

    /**
     * Tests that a failed file write triggers the logger error call.
     */
    public function testSetLogsErrorOnWriteFailure(): void
    {
        $GLOBALS['simulate_file_put_contents_failure'] = true;

        LoggingFactory::setLogger(LoggingFactory::create([
            [
                'class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class
            ]
        ]));

        $storage = new FileStorage(['file' => $this->tempFile]);
        $storage->set('badwrite', 'fail');

        $GLOBALS['simulate_file_put_contents_failure'] = false;

        // ✅ Assert that an error log was generated
        $this->assertTrue(
            LoggingFactory::logger()->getHandlers()[0]->hasErrorContaining('Failed to write to file'),
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

        new FileStorage(['file' => $this->tempFile]);
    }

    /**
     * Tests that FileStorage throws if the file exists but is not readable/writable.
     */
    public function testConstructorThrowsIfFileNotReadableToLoad(): void
    {
        $GLOBALS['simulate_is_readable_failure'] = true;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("must be readable");

        new FileStorage(['file' => $this->tempFile]);
    }

}
