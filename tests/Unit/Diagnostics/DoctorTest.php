<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Diagnostics;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;
use Symfony\Component\HttpFoundation\Request;

/**
 * Diagnosing a real environment (#211).
 *
 * Every check here runs against something real -- a directory that does or does
 * not exist, a file with an mtime, a database that is or is not reachable --
 * because that is what separates this from the config linter (#216). A mocked
 * filesystem would test the mock.
 */
class DoctorTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-doctor-' . uniqid();
        mkdir($this->dir, 0700, true);
        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        DegradedBackends::reset();
        parent::tearDown();
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<int, Diagnosis>
     */
    private function diagnose(array $config): array
    {
        return (new Doctor([$config]))->run();
    }

    /**
     * @param array<int, Diagnosis> $findings
     *
     * @return array<int, string>
     */
    private function titles(array $findings, ?string $status = null): array
    {
        $matching = $status === null
            ? $findings
            : array_filter($findings, static fn(Diagnosis $d): bool => $d->status === $status);

        return array_values(array_map(static fn(Diagnosis $d): string => $d->title, $matching));
    }

    /**
     * @return array<string, mixed>
     */
    private function workingConfig(): array
    {
        return [
            'global' => ['mode' => 'block'],
            'storage' => [
                'type' => 'Kanopi\\Firewall\\Storage\\FileStorage',
                'config' => ['storage_file' => $this->dir . '/blocked.data'],
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'config' => ['203.0.113.5'],
                ],
            ],
        ];
    }

    /**
     * A working installation reports no errors.
     */
    public function testAWorkingInstallationHasNoErrors(): void
    {
        $findings = $this->diagnose($this->workingConfig());

        $this->assertSame([], $this->titles($findings, Diagnosis::ERROR));
        $this->assertContains('Config loads', $this->titles($findings));
        $this->assertContains('Every configured rule is running', $this->titles($findings));
    }

    /**
     * A storage directory that does not exist is an error, naming the path.
     */
    public function testAMissingStorageDirectoryIsReported(): void
    {
        $config = $this->workingConfig();
        $config['storage']['config']['storage_file'] = '/nonexistent/dir/blocked.data';

        $errors = $this->titles($this->diagnose($config), Diagnosis::ERROR);

        $this->assertContains('Storage directory for storage_file does not exist', $errors);
    }

    /**
     * A storage directory that cannot be written is an error.
     */
    public function testAnUnwritableStorageDirectoryIsReported(): void
    {
        $locked = $this->dir . '/locked';
        mkdir($locked, 0500);

        $config = $this->workingConfig();
        $config['storage']['config']['storage_file'] = $locked . '/blocked.data';

        $errors = $this->titles($this->diagnose($config), Diagnosis::ERROR);

        @chmod($locked, 0700);
        @rmdir($locked);

        $this->assertContains('Storage path for storage_file is not writable', $errors);
    }

    /**
     * A rule that cannot be constructed is reported as not running.
     */
    public function testARuleThatCannotBeConstructedIsReported(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][] = [
            'plugin' => \Kanopi\Firewall\Tests\Plugins\TestThrowingPlugin::class,
            'response' => 'block',
            'enable' => true,
        ];

        $errors = $this->titles($this->diagnose($config), Diagnosis::ERROR);

        $this->assertNotSame([], array_filter(
            $errors,
            static fn(string $t): bool => str_contains($t, 'is not running')
        ), 'The rule that threw is named');
    }

    /**
     * A backend running blind is reported, separately from a failed rule.
     */
    public function testADegradedBackendIsReported(): void
    {
        DegradedBackends::record('block list', 'Some\\RedisStorage', 'Connection refused');

        $errors = $this->titles($this->diagnose($this->workingConfig()), Diagnosis::ERROR);

        $this->assertContains('The block list is running without its store', $errors);
    }

    /**
     * A missing GeoIP database is an error, because the rules cannot match.
     */
    public function testAMissingGeoIpDatabaseIsAnError(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][0]['metadata'] = ['reader' => ['type' => 'reader', 'db' => '/nope/GeoLite2-City.mmdb']];

        $this->assertContains('GeoIP database not found', $this->titles($this->diagnose($config), Diagnosis::ERROR));
    }

    /**
     * A stale GeoIP database is a warning, because it still answers.
     */
    public function testAStaleGeoIpDatabaseIsAWarningAndAFreshOneIsNot(): void
    {
        $database = $this->dir . '/GeoLite2-City.mmdb';
        file_put_contents($database, 'x');

        $config = $this->workingConfig();
        $config['plugins'][0]['metadata'] = ['reader' => ['type' => 'reader', 'db' => $database]];

        $this->assertSame(
            [],
            array_filter(
                $this->titles($this->diagnose($config), Diagnosis::WARNING),
                static fn(string $t): bool => str_contains($t, 'GeoIP')
            ),
            'A database written moments ago is not stale'
        );

        touch($database, time() - (95 * 86400));

        $this->assertContains(
            'GeoIP database is 95 days old',
            $this->titles($this->diagnose($config), Diagnosis::WARNING)
        );
    }

    /**
     * A configuration the firewall refuses to start with is an error.
     *
     * `create()` throws on a wiring it will not run — an empty challenge secret
     * here. In production that is a fatal at boot.
     */
    public function testAConfigurationTheFirewallRefusesIsAnError(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][0]['response'] = 'challenge';
        $config['challenge'] = ['secret' => ''];

        $this->assertContains(
            'The firewall refuses to start with this configuration',
            $this->titles($this->diagnose($config), Diagnosis::ERROR)
        );
    }

    /**
     * A database that cannot be reached is reported, not thrown.
     */
    public function testAnUnreachableDatabaseIsReported(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
            'response' => 'block',
            'enable' => true,
            'metadata' => [
                'storage' => [
                    'type' => 'Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage',
                    'config' => ['connection' => [
                        'driver' => 'pdo_mysql',
                        'host' => '127.0.0.1',
                        'port' => 59999,
                        'dbname' => 'nope',
                        'user' => 'u',
                        'password' => 'p',
                    ]],
                ],
            ],
            'config' => [],
        ];

        $errors = $this->titles($this->diagnose($config), Diagnosis::ERROR);

        $this->assertNotSame([], array_filter(
            $errors,
            static fn(string $t): bool => str_contains($t, 'could not be reached')
        ));
    }

    /**
     * A database-backed store that is reachable reports its schema as current.
     */
    public function testAReachableDatabaseReportsItsSchema(): void
    {
        $config = $this->workingConfig();
        $config['storage'] = [
            'type' => 'Kanopi\\Firewall\\Storage\\DatabaseStorage',
            'config' => ['connection' => ['driver' => 'pdo_sqlite', 'path' => $this->dir . '/fw.sqlite']],
        ];

        $findings = $this->diagnose($config);

        $this->assertContains('Database schema is current', $this->titles($findings));
        $this->assertSame([], $this->titles($findings, Diagnosis::ERROR));
    }

    /**
     * A config file that could not be read is an error, not a silent partial run.
     */
    public function testAConfigThatFailedToLoadIsAnError(): void
    {
        $findings = (new Doctor([$this->dir . '/does-not-exist.yml']))->run();

        $this->assertNotSame([], array_filter(
            $this->titles($findings, Diagnosis::ERROR),
            static fn(string $t): bool => str_contains($t, 'Config file failed to load')
        ));
    }

    /**
     * A source that has never been fetched is a warning.
     */
    public function testAnUnfetchedSourceIsAWarning(): void
    {
        $list = $this->dir . '/list.txt';
        file_put_contents($list, "203.0.113.9\n");

        $config = $this->workingConfig();
        $config['plugins'][0]['metadata'] = ['sources' => [$list]];

        $warnings = $this->titles($this->diagnose($config), Diagnosis::WARNING);

        $this->assertContains('Rule source has never been fetched', $warnings);
    }

    /**
     * A source declaration that is not valid is an error.
     */
    public function testAnInvalidSourceDeclarationIsAnError(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][0]['metadata'] = ['sources' => [['no_upstream' => true]]];

        $this->assertContains(
            'Rule source declaration is not valid',
            $this->titles($this->diagnose($config), Diagnosis::ERROR)
        );
    }

    /**
     * Trusted proxies cannot be settled from a terminal, and it says so.
     *
     * The sharpest edge in the product, and the one thing a CLI run cannot
     * verify: `setTrustedProxies()` is called by the host application's
     * bootstrap, which a command-line process never runs. Reporting `ok` here
     * would read as confirmation the site is not spoofable.
     */
    public function testTrustedProxiesAreReportedAsUnverifiableFromTheCli(): void
    {
        $this->assertSame('cli', PHP_SAPI, 'This test only means anything under the CLI SAPI');

        $findings = $this->diagnose($this->workingConfig());
        $proxy = array_values(array_filter(
            $findings,
            static fn(Diagnosis $d): bool => str_contains($d->title, 'Trusted proxies')
        ));

        $this->assertCount(1, $proxy);
        $this->assertSame(Diagnosis::WARNING, $proxy[0]->status);
        $this->assertStringContainsString('command line', $proxy[0]->title);
    }

    /**
     * Configured proxies are reported as configured, whatever the SAPI.
     */
    public function testConfiguredTrustedProxiesAreReported(): void
    {
        $original = Request::getTrustedProxies();
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR);

        try {
            $findings = $this->diagnose($this->workingConfig());

            $this->assertContains('Trusted proxies configured', $this->titles($findings));
        } finally {
            Request::setTrustedProxies($original, Request::HEADER_X_FORWARDED_FOR);
        }
    }

    /**
     * In a web context with no proxies and behind_proxy asserted, it is an error.
     *
     * The sharpest failure the firewall has: every IP-based rule spoofable
     * through a forged header. Reached through the SAPI seam, because the suite
     * is the CLI SAPI by definition and this branch would otherwise be the
     * least-tested path in the file.
     */
    public function testAssertedProxiesWithNoneConfiguredIsAnErrorOutsideTheCli(): void
    {
        $original = Request::getTrustedProxies();
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        try {
            $config = $this->workingConfig();
            $config['global']['behind_proxy'] = true;

            $findings = (new WebContextDoctor([$config]))->run();

            $this->assertContains(
                'Trusted proxies not configured, and behind_proxy asserts there is one',
                $this->titles($findings, Diagnosis::ERROR)
            );
        } finally {
            Request::setTrustedProxies($original, Request::HEADER_X_FORWARDED_FOR);
        }
    }

    /**
     * In a web context with no proxies and nothing asserted, it is a warning.
     *
     * Correct for an application with nothing in front of it, which is why this
     * is not an error.
     */
    public function testNoProxiesAndNothingAssertedIsAWarningOutsideTheCli(): void
    {
        $original = Request::getTrustedProxies();
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        try {
            $findings = (new WebContextDoctor([$this->workingConfig()]))->run();

            $this->assertContains(
                'No trusted proxies configured',
                $this->titles($findings, Diagnosis::WARNING)
            );
        } finally {
            Request::setTrustedProxies($original, Request::HEADER_X_FORWARDED_FOR);
        }
    }

    /**
     * A config that loaded but degraded is a warning, not an error.
     *
     * An unresolvable `%config(...)%` reference leaves the literal token in
     * place, so the config loads and something downstream reads a token where
     * it wanted a value.
     */
    public function testAConfigWarningIsReported(): void
    {
        $config = $this->workingConfig();

        // Deliberately not a path. An unresolvable reference leaves the literal
        // token in place, so putting one in `offense_file` makes FileStorage
        // create a file named `%config(...)%` in the working directory — which
        // this test did, in the repository root, until it did not.
        $config['global']['unresolvable'] = '%config(nowhere.at.all)%';

        $warnings = $this->titles($this->diagnose($config), Diagnosis::WARNING);

        $this->assertNotSame([], array_filter(
            $warnings,
            static fn(string $t): bool => str_contains($t, 'Config loaded with a warning')
        ));
    }

    /**
     * A table behind the declared schema is a warning naming what is missing.
     */
    public function testATableBehindTheSchemaIsReported(): void
    {
        $path = $this->dir . '/behind.sqlite';
        $connection = \Doctrine\DBAL\DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $path]);
        $connection->executeStatement(
            'CREATE TABLE firewall_rate_limit_storage (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, '
            . 'rule VARCHAR(255) NOT NULL, timestamp INTEGER DEFAULT 0 NOT NULL)'
        );

        $config = $this->workingConfig();
        $config['plugins'][] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['storage' => [
                'type' => 'Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage',
                'config' => ['connection' => ['driver' => 'pdo_sqlite', 'path' => $path]],
            ]],
            'config' => [],
        ];

        $warnings = $this->titles($this->diagnose($config), Diagnosis::WARNING);

        $this->assertNotSame([], array_filter(
            $warnings,
            static fn(string $t): bool => str_contains($t, 'behind the declared schema')
        ));
    }

    /**
     * A log handler declared in the config is checked too.
     */
    public function testALogHandlerTableIsChecked(): void
    {
        $config = $this->workingConfig();
        $config['logger'] = [[
            'class' => 'Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler',
            'args' => [[
                'table' => 'firewall_log',
                'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->dir . '/log.sqlite'],
            ]],
        ]];

        $findings = $this->diagnose($config);

        $this->assertContains('Database schema is current', $this->titles($findings));
        $this->assertSame([], $this->titles($findings, Diagnosis::ERROR));
    }

    /**
     * An empty path or database is skipped rather than reported.
     *
     * `storage_file: ""` is a config mistake the loader already reports; this
     * check has nothing useful to add about it and should not invent a second
     * complaint.
     */
    public function testEmptyPathsAreSkipped(): void
    {
        $config = $this->workingConfig();
        $config['storage']['config']['offense_file'] = '';
        $config['plugins'][0]['metadata'] = ['reader' => ['type' => 'reader', 'db' => '']];

        $titles = $this->titles($this->diagnose($config));

        $this->assertSame([], array_filter($titles, static fn(string $t): bool => str_contains($t, 'offense_file')));
        $this->assertSame([], array_filter($titles, static fn(string $t): bool => str_contains($t, 'GeoIP')));
    }

    /**
     * A source that has been fetched reports as fresh, and as stale past its ttl.
     */
    public function testAFetchedSourceReportsFreshThenStale(): void
    {
        $list = $this->dir . '/list.txt';
        file_put_contents($list, "203.0.113.9\n");

        $config = $this->workingConfig();
        $config['plugins'][0]['metadata'] = ['sources' => [['upstream' => $list, 'ttl' => 3600]]];

        // The first run finds nothing cached, then builds the rules -- which is
        // what fetches. The second run sees what the first left behind.
        $this->diagnose($config);

        $this->assertContains('1 rule source cached and fresh', $this->titles($this->diagnose($config)));

        $stale = $this->workingConfig();
        $stale['plugins'][0]['metadata'] = ['sources' => [['upstream' => $list, 'ttl' => 0]]];

        $this->assertContains(
            'Rule source cache is stale',
            $this->titles($this->diagnose($stale), Diagnosis::WARNING)
        );
    }

    /**
     * Junk among the plugins and handlers is stepped over, not tripped on.
     *
     * A hand-edited config can hold a stray scalar where a map belongs, and a
     * `logger:` list usually holds handlers that are not this package's. A
     * diagnostic that fataled on either would be useless in exactly the
     * situation it is run for.
     */
    public function testMalformedEntriesAreSkipped(): void
    {
        $config = $this->workingConfig();
        $config['plugins'][] = 'not a plugin map';
        $config['plugins'][] = 42;
        $config['logger'] = [
            ['class' => 'Monolog\\Handler\\NullHandler', 'args' => []],
            'not a handler map',
        ];

        $findings = $this->diagnose($config);

        // It survived, which is the point: a diagnostic is run because a config
        // is suspect. The stray scalar makes Firewall::create() throw a
        // TypeError rather than an Exception (#281), so this also pins the
        // `\Throwable` catch that keeps the command usable until that is fixed.
        $this->assertContains('Config loads', $this->titles($findings));
        $this->assertContains(
            'The firewall refuses to start with this configuration',
            $this->titles($findings, Diagnosis::ERROR)
        );
    }

    /**
     * The tally counts each status.
     */
    public function testTheTallyCountsEachStatus(): void
    {
        $this->assertSame(
            ['ok' => 2, 'warning' => 1, 'error' => 0],
            Doctor::tally([Diagnosis::ok('a'), Diagnosis::ok('b'), Diagnosis::warning('c')])
        );

        $this->assertSame(['ok' => 0, 'warning' => 0, 'error' => 0], Doctor::tally([]));
    }
}

/**
 * A Doctor that believes it is serving a request.
 *
 * The suite runs under the CLI SAPI, so the web-context branches of the
 * trusted-proxy check are unreachable without this.
 */
final class WebContextDoctor extends Doctor
{
    protected function isCommandLine(): bool
    {
        return false;
    }
}
