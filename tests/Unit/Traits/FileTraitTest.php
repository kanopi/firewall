<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(FileTrait::class)]
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
}
