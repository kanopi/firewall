<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

class IpAddressTest extends AbstractTestCase
{

    /**
     * Tests getName() returns correct name.
     */
    public function testGetName(): void
    {
        $plugin = new IpAddress();
        $this->assertEquals('IP Address', $plugin->getName());
    }

    /**
     * Tests getDescription() returns expected text.
     */
    public function testGetDescription(): void
    {
        $plugin = new IpAddress();
        $this->assertEquals('Evaluate IP Addresses and see in the provided list', $plugin->getDescription());
    }

    /**
     * Tests evaluate() returns true when IP is directly listed.
     */
    public function testEvaluateWithDirectMatch(): void
    {
        $plugin = new IpAddress([], ['192.168.1.1']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '192.168.1.1']);
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() returns true for CIDR match.
     */
    public function testEvaluateWithCidrMatch(): void
    {
        $plugin = new IpAddress([], ['192.168.1.0/24']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '192.168.1.55']);
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() returns true for range match.
     */
    public function testEvaluateWithRangeMatch(): void
    {
        $plugin = new IpAddress([], ['192.168.1.10-192.168.1.20']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '192.168.1.15']);
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() returns false when IP not in list.
     */
    public function testEvaluateReturnsFalseWhenNoMatch(): void
    {
        $plugin = new IpAddress([], ['192.168.1.10-192.168.1.20']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() with invalid CIDR input.
     */
    public function testEvaluateWithInvalidCidr(): void
    {
        $plugin = new IpAddress([], ['invalid/abc']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() with malformed IP range input.
     */
    public function testEvaluateWithInvalidRange(): void
    {
        $plugin = new IpAddress([], ['invalid-range']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() handles IPv6 direct match.
     */
    public function testEvaluateWithIpv6(): void
    {
        $plugin = new IpAddress([], ['::1']);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '::1']);
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Tests isInBlock() returns false for mismatched IP versions.
     */
    public function testIsInBlockWithMismatchedVersions(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, '127.0.0.1', '::1/128'));
    }

    /**
     * Tests a family mismatch is not reported as a problem.
     *
     * A dual-stack list holds both families by design, so every request that
     * reaches it compares against entries it cannot possibly match. Reporting
     * each of those at warning made a correct list look broken and buried the
     * records that mattered: Uptime Robot's published list is 206 entries,
     * half of them IPv6, so one IPv4 client produced 103 warnings per request.
     */
    public function testFamilyMismatchIsNotWarned(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = new IpAddress([], ['192.0.2.0/24', '2001:db8:bad::/48']);
        $this->assertFalse($plugin->evaluate($this->getRequest('198.51.100.7')));

        $this->assertFalse(
            $handler->hasWarningRecords(),
            'A list holding both families must not warn about the family that cannot match.',
        );
        $this->assertTrue(
            $handler->hasRecordThatContains('IP type mismatch in CIDR check', Level::Debug),
            'The mismatch stays available at debug, for tracing why a rule did not match.',
        );
    }

    /**
     * Tests configuration that can never work is still reported.
     *
     * The counterpart to the test above: the point of moving the family
     * mismatch to debug is that these three stay at warning. A CIDR with no
     * slash, an unparseable address and an out-of-range prefix are not
     * arithmetic that came out false, they are entries that will never match
     * anything, and their author wants to know.
     */
    #[DataProvider('malformedEntryProvider')]
    public function testMalformedEntriesAreStillWarned(string $entry): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = new IpAddress([], [$entry]);
        $this->assertFalse($plugin->evaluate($this->getRequest('198.51.100.7')));

        $this->assertTrue(
            $handler->hasWarningRecords(),
            sprintf('Expected a warning for the unusable entry "%s".', $entry),
        );
    }

    /**
     * Supplies entries that cannot ever match.
     *
     * @return array<string, array{string}>
     *   Test cases.
     */
    public static function malformedEntryProvider(): array
    {
        return [
            'unparseable address' => ['not-an-address/24'],
            'prefix out of range' => ['192.0.2.0/300'],
            'prefix not a number' => ['192.0.2.0/two'],
        ];
    }

    /**
     * Tests inRange() handles out-of-range scenarios.
     */
    public function testInRangeOutOfRange(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, '192.168.1.25', '192.168.1.10-192.168.1.20'));
    }

    /**
     * Tests inRange() with invalid IPs.
     */
    public function testInRangeWithInvalidIps(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, 'not.an.ip', 'abc-def'));
    }

    /**
     * Tests isInBlock() with valid IPv4 CIDR block.
     */
    public function testIsInBlockWithValidIpv4(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertTrue($method->invoke($instance, '10.0.0.5', '10.0.0.0/24'));
    }

    /**
     * Tests isInBlock() with invalid CIDR block.
     */
    public function testIsInBlockWithInvalidCidr(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, '10.0.0.5', 'invalidcidr'));
    }

    /**
     * Tests isInBlock fails when full byte segments differ.
     */
    public function testIsInBlockFailsOnFullByteMismatch(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        // 192.168.1.1 vs subnet 192.168.2.0/24
        $this->assertFalse($method->invoke($instance, '192.168.1.1', '192.168.2.0/24'));
    }

    /**
     * Tests isInBlock succeeds when remaining bits match.
     */
    public function testIsInBlockSucceedsOnPartialBitMatch(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        // 192.168.1.1 vs 192.168.1.0/31 => only one bit difference
        $this->assertTrue($method->invoke($instance, '192.168.1.1', '192.168.1.0/31'));
    }

    /**
     * Tests isInBlock fails when remaining bits differ.
     */
    public function testIsInBlockFailsOnPartialBitMismatch(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        // 192.168.1.3 vs 192.168.1.0/30 covers .0 to .3
        // .4 is outside of this range
        $this->assertFalse($method->invoke($instance, '192.168.1.4', '192.168.1.0/30'));
    }

    /**
     * Tests isInBlock with no remaining bits (prefix length divisible by 8).
     */
    public function testIsInBlockSkipsPartialBitComparison(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertTrue($method->invoke($instance, '192.168.1.200', '192.168.1.0/24'));
    }

    /**
     * Tests isInBlock with prefixLength = 0 (matches everything).
     */
    public function testIsInBlockAlwaysMatchesWithPrefixZero(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        // /0 matches all IPv4 addresses
        $this->assertTrue($method->invoke($instance, '123.123.123.123', '0.0.0.0/0'));
    }

    /**
     * Tests isInBlock fails if CIDR is malformed.
     */
    public function testIsInBlockWithMalformedCidrFails(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, '10.0.0.1', 'invalid'));
    }

    /**
     * Tests isInBlock handles IPv6 with partial match success.
     */
    public function testIsInBlockWithIpv6Match(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertTrue($method->invoke($instance, '2001:db8::1', '2001:db8::/64'));
    }

    /**
     * Tests isInBlock with IPv6 mismatch in full byte.
     */
    public function testIsInBlockWithIpv6FullByteMismatch(): void
    {
        $ref = new \ReflectionClass(IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $instance = new IpAddress();

        $this->assertFalse($method->invoke($instance, '2001:db9::1', '2001:db8::/64'));
    }

    /**
     * Tests inRange returns false if start IP is an empty string.
     */
    public function testInRangeFailsWithEmptyStartIp(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        $this->assertFalse($method->invoke($plugin, '192.168.1.5', '-192.168.1.10'));
    }

    /**
     * Tests inRange returns false if start IP is '0'.
     */
    public function testInRangeFailsWithStartIpZero(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        $this->assertFalse($method->invoke($plugin, '192.168.1.5', '0-192.168.1.10'));
    }

    /**
     * Tests inRange returns false if end IP is an empty string.
     */
    public function testInRangeFailsWithEmptyEndIp(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        $this->assertFalse($method->invoke($plugin, '192.168.1.5', '192.168.1.1-'));
    }

    /**
     * Tests inRange returns false if end IP is '0'.
     */
    public function testInRangeFailsWithEndIpZero(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('inRange');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        $this->assertFalse($method->invoke($plugin, '192.168.1.5', '192.168.1.1-0'));
    }

    /**
     * Regression for #63: out-of-range and non-numeric IPv4 prefix lengths.
     *
     * Pre-fix `isInBlock` did `(int) $prefixLength` and trusted the result,
     * so `/33`, `/-1`, and `/abc` produced nonsense byte/bit math and could
     * either trivially match or trivially not match — a wrong-allowlist
     * configuration adjacency.
     */
    public function testIsInBlockRejectsOutOfRangeIpv4Prefix(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        // /33 is out of range for IPv4 (max 32).
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/33'));
        // /300 — pre-fix produced odd matches via integer overflow into byte math.
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/300'));
        // Negative — ctype_digit on "-1" is false (leading sign).
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/-1'));
        // Non-numeric.
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/abc'));
        // Empty prefix after the slash.
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/'));
        // Decimal prefix length.
        $this->assertFalse($method->invoke($plugin, '10.0.0.5', '10.0.0.0/24.5'));
    }

    /**
     * Regression for #63: IPv6 prefix length must be 0..128.
     */
    public function testIsInBlockRejectsOutOfRangeIpv6Prefix(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        // /129 exceeds the IPv6 maximum (128).
        $this->assertFalse($method->invoke($plugin, '2001:db8::1', '2001:db8::/129'));
        // /200 also above max.
        $this->assertFalse($method->invoke($plugin, '2001:db8::1', '2001:db8::/200'));
    }

    /**
     * Regression for #63: boundary prefix lengths (/32 and /128) still work.
     */
    public function testIsInBlockAcceptsBoundaryPrefixLengths(): void
    {
        $ref = new \ReflectionClass(\Kanopi\Firewall\Plugins\IpAddress::class);
        $method = $ref->getMethod('isInBlock');
        $method->setAccessible(true);
        $plugin = new \Kanopi\Firewall\Plugins\IpAddress();

        // /32 is the single-host case for IPv4.
        $this->assertTrue($method->invoke($plugin, '10.0.0.5', '10.0.0.5/32'));
        $this->assertFalse($method->invoke($plugin, '10.0.0.6', '10.0.0.5/32'));
        // /128 is the single-host case for IPv6.
        $this->assertTrue($method->invoke($plugin, '2001:db8::1', '2001:db8::1/128'));
        $this->assertFalse($method->invoke($plugin, '2001:db8::2', '2001:db8::1/128'));
    }
}

