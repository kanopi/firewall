<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\Crs;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the CRS plugin's adapter behavior against kanopi/crs-engine.
 *
 * The engine itself is exhaustively tested in its own package — this suite
 * focuses on what the firewall plugin contributes: Symfony Request -> DTO
 * mapping, configuration plumbing, status/expiration accessors, and the
 * bool return contract of evaluate().
 *
 * Tests skip themselves if the engine's bundled rules haven't been generated
 * (vendor install pulls the rules cache in, but a fresh dev clone without
 * `composer install` won't have them).
 */
class CrsTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (!is_file(__DIR__ . '/../../../vendor/kanopi/crs-engine/rules/compiled.php')) {
            $this->markTestSkipped('CRS engine rules not available — run `composer install` to pull them.');
        }
    }

    public function testGetName(): void
    {
        $this->assertSame('CRS', (new Crs())->getName());
    }

    public function testGetDescription(): void
    {
        $this->assertStringContainsString('OWASP', (new Crs())->getDescription());
    }

    public function testDefaultStatusCodeIs403(): void
    {
        $this->assertSame(403, (new Crs())->getStatusCode());
    }

    public function testCustomStatusCodeFromConfig(): void
    {
        $plugin = new Crs([], ['block_status' => 451]);
        $this->assertSame(451, $plugin->getStatusCode());
    }

    public function testDefaultExpirationIsOneHour(): void
    {
        $this->assertSame(3600, (new Crs())->getExpirationTime());
    }

    public function testCustomExpirationFromConfig(): void
    {
        $plugin = new Crs([], ['block_duration' => 7200]);
        $this->assertSame(7200, $plugin->getExpirationTime());
    }

    public function testBenignRequestPasses(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['q' => 'hello world']);
        $this->assertTrue($plugin->evaluate($request));
        $this->assertNotNull($plugin->getLastVerdict());
        $this->assertFalse($plugin->getLastVerdict()->isBlocked());
    }

    public function testSqliRequestBlocks(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertFalse($plugin->evaluate($request));
        $verdict = $plugin->getLastVerdict();
        $this->assertNotNull($verdict);
        $this->assertTrue($verdict->isBlocked());
        $this->assertNotNull($verdict->blockingRuleId);
    }

    public function testXssRequestBlocks(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['c' => '<script>alert(1)</script>']);
        $this->assertFalse($plugin->evaluate($request));
    }

    public function testScannerUserAgentBlocks(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request([], ['HTTP_USER_AGENT' => 'sqlmap/1.5.2#stable (http://sqlmap.org)']);
        $this->assertFalse($plugin->evaluate($request));
    }

    public function testMonitorModeNeverBlocks(): void
    {
        $plugin = new Crs([], ['paranoia' => 1, 'mode' => 'monitor']);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertTrue($plugin->evaluate($request), 'monitor mode should not block even on SQLi');
        $this->assertNotEmpty($plugin->getLastVerdict()->matchedRules, 'rule should still have matched');
    }

    public function testDisabledRulesAreSkipped(): void
    {
        // Disable everything that would normally catch this payload — should pass.
        $plugin = new Crs([], [
            'paranoia' => 1,
            'disabled_categories' => ['sqli', 'rce', 'scanner'],
        ]);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Build a Symfony Request shaped like a normal browser would send.
     */
    private function request(array $queryArgs, array $serverOverrides = []): Request
    {
        return new Request(
            query: $queryArgs,
            server: array_merge([
                'REMOTE_ADDR'      => '203.0.113.10',
                'REQUEST_METHOD'   => 'GET',
                'REQUEST_URI'      => '/?' . http_build_query($queryArgs),
                'SERVER_PROTOCOL'  => 'HTTP/1.1',
                'HTTP_HOST'        => 'example.com',
                'HTTP_USER_AGENT'  => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'HTTP_ACCEPT'      => 'text/html,application/xhtml+xml',
                'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.5',
            ], $serverOverrides),
        );
    }
}
