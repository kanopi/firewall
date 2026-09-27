<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Cache;

use Kanopi\Firewall\Cache\NoObjectsMarshaller;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Cache values come back as values, never as objects (#394).
 *
 * A pool built from a DSN reads from a server other things can write to. Whatever writes
 * there should not get to choose which class this process instantiates.
 */
final class NoObjectsMarshallerTest extends TestCase
{
    /**
     * @return array<string, array{0: mixed}>
     */
    public static function provideValuesThisLibraryCaches(): array
    {
        return [
            'a verdict' => [true],
            'a refusal' => [false],
            'a country code' => ['NZ'],
            'an unresolved lookup' => [null],
            'a rate-limit window' => [[1790000000, 1790000001, 1790000002]],
            'a regex corpus entry' => [['regex' => '(?:Googlebot)', 'name' => 'Googlebot', 'nested' => ['a' => ['b' => 'c']]]],
            'a number' => [3.14],
        ];
    }

    #[DataProvider('provideValuesThisLibraryCaches')]
    public function testValuesRoundTrip(mixed $value): void
    {
        $marshaller = new NoObjectsMarshaller();
        $serialized = $marshaller->marshall(['key' => $value], $failed);

        $this->assertSame([], $failed);
        $this->assertSame($value, $marshaller->unmarshall($serialized['key']));
    }

    /**
     * Written by something else to the same server: not instantiated, and not returned.
     */
    public function testAnObjectWrittenByAnotherWriterIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('held an object');

        (new NoObjectsMarshaller())->unmarshall(serialize(new \ArrayObject(['gadget'])));
    }

    public function testAnObjectNestedInAnArrayIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);

        (new NoObjectsMarshaller())->unmarshall(serialize(['safe' => 1, 'deep' => [new \stdClass()]]));
    }

    public function testGarbageIsRefused(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('could not be unserialised');

        (new NoObjectsMarshaller())->unmarshall('not serialised at all');
    }

    /**
     * Reported to the adapter as a failed write, as Symfony's own marshaller does.
     */
    public function testAValueThatCannotBeSerialisedIsReportedAsFailed(): void
    {
        $serialized = (new NoObjectsMarshaller())->marshall(['ok' => 1, 'closure' => static fn (): int => 1], $failed);

        $this->assertSame(['closure'], $failed);
        $this->assertSame(['ok'], array_keys($serialized));
    }
}
