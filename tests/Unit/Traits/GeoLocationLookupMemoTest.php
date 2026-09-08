<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use GeoIp2\Database\Reader;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Traits\GeoLocationTrait;

/**
 * The lookup memo's own guards (#6).
 *
 * `Asn` and `GeoLocation` both check their reader before calling in, so these
 * branches are unreachable through the plugins. They are reachable by anything
 * else that uses the trait, which is the point of them being there -- so they
 * are exercised against the trait directly rather than left untested.
 */
class GeoLocationLookupMemoTest extends AbstractTestCase
{
    /**
     * A fixture exposing the trait's protected lookup.
     */
    private function subject(Reader|null $reader): object
    {
        return new class ($reader) {
            use GeoLocationTrait;

            public function __construct(Reader|null $reader)
            {
                $this->reader = $reader;
            }

            public function lookup(string $method, string $ip): ?object
            {
                return $this->lookupRecord($method, $ip);
            }

            /** @return array<string, object|null> */
            public function memo(): array
            {
                return $this->lookupMemo;
            }
        };
    }

    /**
     * With no reader there is nothing to look up.
     */
    public function testNoReaderYieldsNull(): void
    {
        $subject = $this->subject(null);

        $this->assertNull($subject->lookup('city', '198.51.100.1'));
    }

    /**
     * A reader that does not offer the method is not called blindly.
     *
     * `Reader` has `city()` and `asn()`; a web-service `Client` does not offer
     * every method a database reader does.
     */
    public function testAReaderWithoutTheMethodYieldsNull(): void
    {
        $subject = $this->subject($this->createMock(Reader::class));

        $this->assertNull($subject->lookup('noSuchLookup', '198.51.100.1'));
    }

    /**
     * A null result is memoised, so a second call does not retry.
     *
     * Nothing about the request changes between calls, so a retry would fail
     * identically while paying for it again.
     */
    public function testAFailedLookupIsRemembered(): void
    {
        $subject = $this->subject(null);

        $subject->lookup('city', '198.51.100.1');
        $subject->lookup('city', '198.51.100.1');

        $this->assertArrayHasKey('city:198.51.100.1', $subject->memo());
        $this->assertNull($subject->memo()['city:198.51.100.1']);
    }
}
