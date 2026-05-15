<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;

/**
 * Coverage attribute intentionally omitted: `#[CoversTrait(FileTrait::class)]`
 * and `#[CoversClass(FileTrait::class)]` both trigger loading of
 * `SebastianBergmann\CodeUnit\TraitUnit`, which has a `final readonly`
 * declaration that the `dg/bypass-finals` PHPUnit extension rewrites
 * incompatibly on PHP 8.4, producing a fatal "non-readonly class extends
 * readonly class" when the file storage tests run earlier in the suite
 * and force the parent `CodeUnit` to be loaded with `readonly` intact.
 * PHPUnit still attributes coverage to the trait via the lines it
 * actually exercises.
 */
class FileTraitTest extends TestCase
{
    private string $tempFile;

    /**
     * Anonymous-class fixture that exposes the trait's protected methods.
     */
    private object $subject;

    protected function setUp(): void
    {
        parent::setUp();

        LoggingFactory::setLogger(LoggingFactory::create([
            ['class' => TestLogHandler::class],
        ]));

        $this->tempFile = tempnam(sys_get_temp_dir(), 'filetrait_test_');

        $this->subject = new class () {
            use FileTrait;

            /** @return array<mixed> */
            public function load(string $path): array
            {
                return $this->loadFromFile($path);
            }

            /** @param array<mixed> $data */
            public function save(array $data, string $path): bool
            {
                return $this->persistToFile($data, $path);
            }

            public function validate(string $path): string
            {
                return $this->validateFilePath($path);
            }
        };
    }

    protected function tearDown(): void
    {
        @unlink($this->tempFile);
    }

    public function testRoundTripJsonEncodedData(): void
    {
        $payload = [
            '203.0.113.1' => ['value' => ['event_id' => 'abc'], 'expire' => 0],
            '203.0.113.2' => ['value' => ['event_id' => 'def'], 'expire' => 0],
        ];

        $this->assertTrue($this->subject->save($payload, $this->tempFile));
        $this->assertSame($payload, $this->subject->load($this->tempFile));
    }

    public function testPersistedFileContainsValidJsonNotSerializeMagic(): void
    {
        $this->subject->save(['key' => ['expire' => 0]], $this->tempFile);

        $raw = file_get_contents($this->tempFile);
        $this->assertIsString($raw);

        // A `serialize()`-encoded array would start with "a:" and any embedded
        // object would start with "O:". Neither must appear in the persisted
        // representation.
        $this->assertStringStartsNotWith('a:', $raw);
        $this->assertStringNotContainsString('O:', $raw);

        // It must be valid JSON that decodes to an array.
        $decoded = json_decode($raw, true);
        $this->assertIsArray($decoded);
    }

    /**
     * Security regression: a serialized payload sitting in the storage file
     * (the only thing pre-fix `unserialize()` would have happily consumed)
     * must now be rejected without instantiating any object.
     */
    public function testLegacySerializePayloadIsRejectedWithoutObjectInstantiation(): void
    {
        // Define a canary class so we can prove its constructor / __wakeup
        // is never called during the load. The class itself is harmless;
        // a real attacker would target a class with a side-effecting
        // __wakeup or __destruct.
        if (!class_exists(FileTraitObjectInjectionCanary::class, false)) {
            eval(<<<'PHP'
                namespace Kanopi\Firewall\Tests\Unit\Traits;
                class FileTraitObjectInjectionCanary {
                    public static int $instantiations = 0;
                    public string $cmd = '';
                    public function __construct() { self::$instantiations++; }
                    public function __wakeup(): void { self::$instantiations++; }
                }
                PHP);
        }

        FileTraitObjectInjectionCanary::$instantiations = 0;

        $maliciousObject = new FileTraitObjectInjectionCanary();
        $maliciousObject->cmd = 'pwned';
        $serializedPayload = serialize(['203.0.113.1' => $maliciousObject]);

        // Construction in serialize() bumps the counter; reset after planting.
        FileTraitObjectInjectionCanary::$instantiations = 0;

        file_put_contents($this->tempFile, $serializedPayload);

        $result = $this->subject->load($this->tempFile);

        $this->assertSame([], $result, 'Serialized payload must be ignored');
        $this->assertSame(
            0,
            FileTraitObjectInjectionCanary::$instantiations,
            'No object may be instantiated while loading the storage file'
        );

        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasWarningContaining('Failed to decode storage file as JSON'),
            'A decode failure should be logged at warning level'
        );
    }

    public function testGarbageContentsIsTreatedAsEmptyStore(): void
    {
        file_put_contents($this->tempFile, 'not-json-and-not-serialized');

        $this->assertSame([], $this->subject->load($this->tempFile));
    }

    public function testNonArrayJsonContentsIsRejected(): void
    {
        file_put_contents($this->tempFile, json_encode('just a string'));

        $this->assertSame([], $this->subject->load($this->tempFile));

        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasWarningContaining('not an array'),
            'A non-array JSON document should be rejected with a warning'
        );
    }

    public function testEmptyFileLoadsAsEmptyStore(): void
    {
        file_put_contents($this->tempFile, '');

        $this->assertSame([], $this->subject->load($this->tempFile));
    }

    public function testMissingFileLoadsAsEmptyStore(): void
    {
        unlink($this->tempFile);

        $this->assertSame([], $this->subject->load($this->tempFile));
    }

    public function testIntegerKeysAreFilteredOut(): void
    {
        // JSON allows numeric keys but `loadFromFile()` only keeps strings —
        // a defense-in-depth filter against numeric-key collision tricks.
        file_put_contents(
            $this->tempFile,
            json_encode([
                '203.0.113.1' => ['expire' => 0],
                0 => ['expire' => 0],
                '203.0.113.2' => ['expire' => 0],
            ])
        );

        $loaded = $this->subject->load($this->tempFile);

        $this->assertArrayHasKey('203.0.113.1', $loaded);
        $this->assertArrayHasKey('203.0.113.2', $loaded);
        $this->assertArrayNotHasKey(0, $loaded);
    }

    public function testPersistFailureOnUnwritableTargetIsLogged(): void
    {
        // /root is not writable for the test user; persistToFile() should
        // log an error and return false rather than throwing.
        $result = $this->subject->save(['k' => 1], '/root/no-permission/file.json');

        $this->assertFalse($result);

        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasErrorContaining('Failed to write to storage file'),
            'A write failure should be logged at error level'
        );
    }

    public function testPersistFailureOnUnencodableDataIsLogged(): void
    {
        // Resources cannot be JSON-encoded; persistToFile() should log and
        // return false rather than emit a warning.
        $resource = fopen('php://memory', 'r');
        $this->assertNotFalse($resource);

        $result = $this->subject->save(['fp' => $resource], $this->tempFile);
        fclose($resource);

        $this->assertFalse($result);

        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasErrorContaining('Failed to encode data for storage file'),
            'A JSON encoding failure should be logged at error level'
        );
    }

    /**
     * Security regression: a freshly-created storage file must not be
     * readable by group or other. Prior to the fix, files were created via
     * `touch()` under the process umask — typically 022, producing 0644
     * files that leaked block-list and rate-limit state to any local user.
     */
    public function testNewlyCreatedFileIsChmod0600(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $this->markTestSkipped('POSIX file permissions are meaningless on Windows.');
        }

        $target = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'filetrait_perms_' . uniqid() . '.json';
        $this->assertFileDoesNotExist($target);

        try {
            $this->subject->validate($target);

            $this->assertFileExists($target);
            $perms = fileperms($target) & 0777;
            $this->assertSame(
                0600,
                $perms,
                sprintf('Expected new storage file to be 0600, got 0%o', $perms)
            );
        } finally {
            @chmod($target, 0600);
            @unlink($target);
        }
    }

    /**
     * Existing files that are group- or world-readable are tightened to
     * remove those bits. Defense in depth for installs upgrading from a
     * version that created `0644` files.
     */
    public function testExistingFileWithLoosePermsIsTightened(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $this->markTestSkipped('POSIX file permissions are meaningless on Windows.');
        }

        chmod($this->tempFile, 0644);
        $before = fileperms($this->tempFile) & 0777;
        $this->assertSame(0644, $before);

        $this->subject->validate($this->tempFile);

        $after = fileperms($this->tempFile) & 0777;
        $this->assertSame(
            0,
            $after & 0077,
            sprintf('Group/other bits should be stripped, got 0%o', $after)
        );
    }

    /**
     * `defaultStoragePath()` must:
     *   * not return a path under bare `/tmp` (predictable filename),
     *   * include a per-install fingerprint segment,
     *   * create a 0700-mode subdirectory when first invoked.
     */
    public function testDefaultStoragePathLandsInPerInstallSubdirectory(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $this->markTestSkipped('POSIX file permissions are meaningless on Windows.');
        }

        $defaultRef = new \ReflectionMethod($this->subject, 'defaultStoragePath');
        $defaultRef->setAccessible(true);

        // Wipe the per-install subdirectory first so the test exercises
        // the mkdir branch — otherwise repeat runs hit the "already
        // exists" branch and leave the create path uncovered.
        $probe = $defaultRef->invoke($this->subject, 'probe.json');
        $directory = dirname($probe);
        if (is_dir($directory)) {
            foreach (glob($directory . '/*') ?: [] as $f) {
                @unlink($f);
            }

            @rmdir($directory);
        }

        $this->assertDirectoryDoesNotExist($directory, 'precondition: dir must be absent so mkdir runs');

        $path = $defaultRef->invoke($this->subject, 'storage_data.json');

        $this->assertIsString($path);
        $this->assertStringStartsWith(sys_get_temp_dir(), $path);
        $this->assertStringContainsString('kanopi-firewall-', $path);
        $this->assertStringEndsWith('storage_data.json', $path);

        // The pre-fix default of '/tmp/storage_data.data' is no longer in use.
        $this->assertNotSame('/tmp/storage_data.data', $path);
        $this->assertNotSame('/tmp/storage_data.json', $path);

        $this->assertDirectoryExists($directory);

        $dirPerms = fileperms($directory) & 0777;
        $this->assertSame(
            0,
            $dirPerms & 0077,
            sprintf('Default storage directory should be 0700, got 0%o', $dirPerms)
        );

        // Second call should hit the "directory already exists" branch
        // without trying to mkdir again — verify by checking the path
        // round-trips and the dir is still 0700.
        $secondPath = $defaultRef->invoke($this->subject, 'storage_data.json');
        $this->assertSame($path, $secondPath);
        $this->assertSame($dirPerms, fileperms($directory) & 0777);
    }
}
