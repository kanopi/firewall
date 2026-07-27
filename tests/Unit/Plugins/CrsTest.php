<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\Crs;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the CRS plugin's adapter behavior against kanopi/crs-engine.
 *
 * The engine itself is exhaustively tested in its own package — this suite
 * focuses on what the firewall plugin contributes: Symfony Request -> DTO
 * mapping, configuration plumbing, status/expiration accessors, and the
 * bool return contract of evaluate().
 *
 * That contract is "did this plugin match", not "should the request pass" —
 * see PluginInterface::evaluate(). A payload CRS blocks makes evaluate()
 * return TRUE. PluginPolarityTest enforces the same convention across every
 * shipped plugin.
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

    protected function tearDown(): void
    {
        // Reset the process-wide logger so a handler installed by one test
        // does not collect records from the next.
        $prop = (new \ReflectionClass(LoggingFactory::class))->getProperty('logger');
        $prop->setAccessible(true);
        $prop->setValue(null, null);

        parent::tearDown();
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

    public function testBenignRequestDoesNotMatch(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['q' => 'hello world']);
        $this->assertFalse($plugin->evaluate($request), 'a benign request must not match');
        $this->assertNotNull($plugin->getLastVerdict());
        $this->assertFalse($plugin->getLastVerdict()->isBlocked());
    }

    public function testSqliRequestMatches(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertTrue($plugin->evaluate($request), 'SQLi must match so `response:` is applied');
        $verdict = $plugin->getLastVerdict();
        $this->assertNotNull($verdict);
        $this->assertTrue($verdict->isBlocked());
        $this->assertNotNull($verdict->blockingRuleId);
    }

    public function testXssRequestMatches(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request(['c' => '<script>alert(1)</script>']);
        $this->assertTrue($plugin->evaluate($request));
    }

    public function testScannerUserAgentMatches(): void
    {
        $plugin = new Crs([], ['paranoia' => 1]);
        $request = $this->request([], ['HTTP_USER_AGENT' => 'sqlmap/1.5.2#stable (http://sqlmap.org)']);
        $this->assertTrue($plugin->evaluate($request));
    }

    public function testMonitorModeNeverMatches(): void
    {
        // Monitor mode scores and logs but never sets a blocking verdict, so
        // the plugin must report no match and let the request through.
        $plugin = new Crs([], ['paranoia' => 1, 'mode' => 'monitor']);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertFalse($plugin->evaluate($request), 'monitor mode must not block, even on SQLi');
        $this->assertNotEmpty($plugin->getLastVerdict()->matchedRules, 'rule should still have matched');
    }

    public function testDisabledRulesAreSkipped(): void
    {
        // Disable everything that would normally catch this payload — with no
        // rule left to fire, the plugin must report no match.
        $plugin = new Crs([], [
            'paranoia' => 1,
            'disabled_categories' => ['sqli', 'rce', 'scanner'],
        ]);
        $request = $this->request(['id' => '1 UNION SELECT password FROM users']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * #93: the engine reads exactly two thresholds, keyed by CRS severity
     * names that read as though there were one per severity. `inbound` and
     * `outbound` are the honest names, and they map onto those two keys.
     */
    public function testCanonicalThresholdNamesMapToEngineKeys(): void
    {
        $plugin = $this->thresholdProbe(['inbound' => 9, 'outbound' => 7]);
        $this->assertSame(['critical' => 9, 'error' => 7], $plugin->thresholds());
    }

    public function testLegacySeverityThresholdNamesStillWork(): void
    {
        $plugin = $this->thresholdProbe(['critical' => 9, 'error' => 7]);
        $this->assertSame(['critical' => 9, 'error' => 7], $plugin->thresholds());
    }

    public function testCanonicalThresholdNameWinsOverLegacySpelling(): void
    {
        // Config migrated one key at a time must not depend on write order.
        $this->assertSame(
            ['critical' => 9, 'error' => 4],
            $this->thresholdProbe(['critical' => 3, 'inbound' => 9])->thresholds(),
        );
        $this->assertSame(
            ['critical' => 9, 'error' => 4],
            $this->thresholdProbe(['inbound' => 9, 'critical' => 3])->thresholds(),
        );
    }

    public function testOmittedThresholdsFallBackToDefaults(): void
    {
        $this->assertSame(['critical' => 5, 'error' => 4], $this->thresholdProbe([])->thresholds());
        $this->assertSame(['critical' => 9, 'error' => 4], $this->thresholdProbe(['inbound' => 9])->thresholds());
    }

    /**
     * #93: `warning` and `notice` were documented, accepted, and read
     * nowhere. They are still accepted — dropping them would break existing
     * config — but the plugin now says they do nothing.
     */
    public function testInertThresholdKeysAreIgnoredAndReported(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->thresholdProbe([
            'critical' => 5,
            'error'    => 4,
            'warning'  => 3,
            'notice'   => 2,
        ]);

        $this->assertSame(['critical' => 5, 'error' => 4], $plugin->thresholds());
        $this->assertTrue(
            $handler->hasRecordThatContains('CRS anomaly_thresholds keys are ignored', Level::Warning),
            'Keys the engine never reads must be reported, not silently accepted.',
        );

        $record = $handler->getRecords()[count($handler->getRecords()) - 1];
        $this->assertSame(['warning', 'notice'], $record->context['ignored']);
    }

    public function testSupportedThresholdKeysAloneLogNoWarning(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $this->thresholdProbe(['inbound' => 5, 'outbound' => 4])->thresholds();

        $this->assertFalse(
            $handler->hasRecordThatContains('CRS anomaly_thresholds keys are ignored', Level::Warning),
            'Config using only the supported keys must stay quiet.',
        );
    }

    public function testNonNumericThresholdFallsBackToTheDefault(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->thresholdProbe(['inbound' => 'high']);

        $this->assertSame(['critical' => 5, 'error' => 4], $plugin->thresholds());
        $this->assertTrue(
            $handler->hasRecordThatContains('CRS anomaly threshold is not a number', Level::Warning),
        );
    }

    public function testNonArrayThresholdsAreIgnoredAndReported(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->thresholdProbe(5);

        $this->assertSame(['critical' => 5, 'error' => 4], $plugin->thresholds());
        $this->assertTrue(
            $handler->hasRecordThatContains('CRS anomaly_thresholds must be a mapping', Level::Warning),
        );
    }

    /**
     * #93, the consequential half: a rule carrying a block / deny / drop
     * action rejects on first match without consulting the score, so raising
     * the threshold is not the false-positive lever it looks like. Pinning
     * that here so the behaviour the README now describes cannot drift away
     * from it silently.
     */
    public function testRaisingTheThresholdDoesNotDisarmBlockingRules(): void
    {
        foreach ([5, 50, 500] as $threshold) {
            $plugin = new Crs([], [
                'paranoia' => 1,
                'mode' => 'block',
                'anomaly_thresholds' => ['inbound' => $threshold],
            ]);

            $this->assertTrue(
                $plugin->evaluate($this->request(['id' => "1' UNION SELECT 1,2,3--"])),
                sprintf('SQLi is rejected on match, so threshold %d must change nothing', $threshold),
            );
        }
    }

    /**
     * Monitor mode does not rescue the threshold either: nothing blocks
     * there, so both sides of the threshold comparison produce the same
     * verdict.
     *
     * Together with the test above this pins the README's claim that the
     * threshold is inert against the bundled rule set. If the engine ever
     * routes blocking through the anomaly-evaluation rules (949110 / 959100)
     * the way stock CRS does, these two tests fail — which is the signal to
     * revisit that section, not to weaken the tests.
     */
    public function testThresholdDoesNotChangeMonitorModeVerdicts(): void
    {
        $payload = ['q' => '/etc/passwd'];

        $strict = new Crs([], ['paranoia' => 1, 'mode' => 'monitor', 'anomaly_thresholds' => ['inbound' => 1]]);
        $lax    = new Crs([], ['paranoia' => 1, 'mode' => 'monitor', 'anomaly_thresholds' => ['inbound' => 100000]]);

        $strict->evaluate($this->request($payload));
        $lax->evaluate($this->request($payload));

        $this->assertSame($strict->getLastVerdict()->action, $lax->getLastVerdict()->action);
        $this->assertSame($strict->getLastVerdict()->totalScore, $lax->getLastVerdict()->totalScore);
    }

    /**
     * Expose the normalised thresholds the plugin hands the engine.
     */
    private function thresholdProbe(mixed $configured): Crs
    {
        return new class ([], ['anomaly_thresholds' => $configured]) extends Crs {
            /**
             * @return array<string, int>
             */
            public function thresholds(): array
            {
                return $this->anomalyThresholds();
            }
        };
    }

    public function testSingleFileUploadIsAdaptedToEngineDto(): void
    {
        // Cover the single-UploadedFile branch in adaptRequest().
        $tmp = tempnam(sys_get_temp_dir(), 'crs-test-');
        file_put_contents($tmp, 'benign upload contents');

        try {
            $request = new Request(
                files: ['avatar' => new UploadedFile($tmp, 'avatar.jpg', 'image/jpeg', null, true)],
                server: $this->browserServer(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/upload']),
            );

            $plugin = new Crs([], ['paranoia' => 1]);
            $this->assertFalse($plugin->evaluate($request), 'a benign upload must not match');
        } finally {
            @unlink($tmp);
        }
    }

    public function testArrayOfUploadedFilesIsFlattened(): void
    {
        // Cover the multi-upload-under-one-field branch: Symfony returns
        // an array of UploadedFile for `<input multiple>`.
        $tmpA = tempnam(sys_get_temp_dir(), 'crs-test-');
        $tmpB = tempnam(sys_get_temp_dir(), 'crs-test-');
        file_put_contents($tmpA, 'a');
        file_put_contents($tmpB, 'b');

        try {
            $request = new Request(
                files: [
                    'photos' => [
                        new UploadedFile($tmpA, 'one.jpg', 'image/jpeg', null, true),
                        new UploadedFile($tmpB, 'two.jpg', 'image/jpeg', null, true),
                    ],
                ],
                server: $this->browserServer(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/upload']),
            );

            $plugin = new Crs([], ['paranoia' => 1]);
            $this->assertFalse($plugin->evaluate($request), 'benign uploads must not match');
        } finally {
            @unlink($tmpA);
            @unlink($tmpB);
        }
    }

    /**
     * Build a Symfony Request shaped like a normal browser would send.
     */
    private function request(array $queryArgs, array $serverOverrides = []): Request
    {
        return new Request(
            query: $queryArgs,
            server: $this->browserServer(array_merge(
                ['REQUEST_URI' => '/?' . http_build_query($queryArgs)],
                $serverOverrides,
            )),
        );
    }

    /**
     * Browser-shaped $_SERVER bag so requests look legitimate to CRS rules
     * that check Host / User-Agent / Accept headers (e.g. rule 920280 fails
     * a request without Host).
     */
    private function browserServer(array $overrides = []): array
    {
        return array_merge([
            'REMOTE_ADDR'          => '203.0.113.10',
            'REQUEST_METHOD'       => 'GET',
            'REQUEST_URI'          => '/',
            'SERVER_PROTOCOL'      => 'HTTP/1.1',
            'HTTP_HOST'            => 'example.com',
            'HTTP_USER_AGENT'      => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'HTTP_ACCEPT'          => 'text/html,application/xhtml+xml',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.5',
        ], $overrides);
    }
}
