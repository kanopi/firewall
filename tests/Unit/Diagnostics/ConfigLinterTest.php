<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Diagnostics;

use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Static analysis of a configuration (#216).
 *
 * The counterpart to `DoctorTest`. Nothing here touches the environment,
 * because none of these answers depend on it: a rule that cannot match cannot
 * match on any machine.
 */
class ConfigLinterTest extends AbstractTestCase
{
    /**
     * @param array<string, mixed> $config
     *
     * @return array<int, Diagnosis>
     */
    private function lint(array $config): array
    {
        return (new ConfigLinter([$config]))->run();
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
    private function goodConfig(): array
    {
        return [
            'global' => ['mode' => 'block'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                'response' => 'block',
                'enable' => true,
                'metadata' => ['name' => 'admin-paths'],
                'config' => ['path:/wp-admin'],
            ]],
        ];
    }

    /**
     * A configuration with nothing wrong says so, and says what it looked at.
     */
    public function testACleanConfigReportsWhatWasInspected(): void
    {
        $findings = $this->lint($this->goodConfig());

        $this->assertSame([], $this->titles($findings, Diagnosis::ERROR));
        $this->assertSame([], $this->titles($findings, Diagnosis::WARNING));
        $this->assertContains('1 rule inspected', $this->titles($findings));
    }

    /**
     * A rule naming a variable that does not exist cannot match.
     *
     * #173 already detects this at construction; the linter's contribution is
     * answering before a firewall is running, from the config alone.
     */
    public function testAnUnknownVariableIsAnError(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = ['nonsense.thing:x'];

        $errors = $this->titles($this->lint($config), Diagnosis::ERROR);

        $this->assertSame(['Rule "admin-paths" contains something that cannot match'], $errors);
    }

    /**
     * A wildcard in an exact-match rule matches literally, and never matches.
     *
     * `path:/wp-admin/*` reads like a glob and is not one. Nothing about it
     * looks wrong -- the variable is valid, so #173's inspection passes it.
     */
    public function testAWildcardInAnExactMatchIsAWarning(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = ['path:/wp-admin/*'];

        $warnings = $this->titles($this->lint($config), Diagnosis::WARNING);

        $this->assertSame(
            ['Rule "admin-paths" compares exactly against a value containing *'],
            $warnings
        );
    }

    /**
     * The `@operator` forms mean what they say and are left alone.
     */
    public function testAWildcardIsNotFlaggedWhenAnOperatorIsUsed(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = ['path@regex:/^\\/wp-admin\\/.*$/', 'path@contains:*'];

        $this->assertSame([], $this->titles($this->lint($config), Diagnosis::WARNING));
    }

    /**
     * Two rules given the same name.
     */
    public function testDuplicateNamesAreReported(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][] = $config['plugins'][0];

        $this->assertContains(
            'Two rules are named "admin-paths"',
            $this->titles($this->lint($config), Diagnosis::WARNING)
        );
    }

    /**
     * Two unnamed rules of the same class are not a duplicate-name problem.
     *
     * They both resolve to the class name, which is the default and #182's
     * business, not a mistake in this configuration.
     */
    public function testUnnamedRulesAreNotReportedAsDuplicates(): void
    {
        $config = $this->goodConfig();
        unset($config['plugins'][0]['metadata']);
        $config['plugins'][] = $config['plugins'][0];

        $this->assertSame([], array_filter(
            $this->titles($this->lint($config), Diagnosis::WARNING),
            static fn(string $t): bool => str_contains($t, 'named')
        ));
    }

    /**
     * A rule list with nothing in it can never match.
     */
    public function testAnEmptyRuleListIsReported(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = [];

        $this->assertContains(
            'Rule "admin-paths" has an empty rule list',
            $this->titles($this->lint($config), Diagnosis::WARNING)
        );
    }

    /**
     * An empty list is fine when the rules come from a source.
     */
    public function testAnEmptyRuleListIsFineWithSources(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = [];
        $config['plugins'][0]['metadata']['sources'] = ['/tmp/list.txt'];

        $this->assertSame([], array_filter(
            $this->titles($this->lint($config), Diagnosis::WARNING),
            static fn(string $t): bool => str_contains($t, 'empty rule list')
        ));
    }

    /**
     * A disabled rule with an empty list is not a problem.
     */
    public function testADisabledRuleWithNoRulesIsNotReported(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = [];
        $config['plugins'][0]['enable'] = false;

        $this->assertSame([], array_filter(
            $this->titles($this->lint($config), Diagnosis::WARNING),
            static fn(string $t): bool => str_contains($t, 'empty rule list')
        ));
    }

    /**
     * An allow rule matching every address makes everything after it dead.
     *
     * The one shadowing case reported, because it is the one that needs no
     * interpretation: allow rules are consulted first, and `0.0.0.0/0` matches
     * every client there is.
     */
    public function testAnAllowAllRuleShadowsEverythingAfterIt(): void
    {
        $config = $this->goodConfig();
        array_unshift($config['plugins'], [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'allow',
            'weight' => -100,
            'enable' => true,
            'metadata' => ['name' => 'everyone'],
            'config' => ['0.0.0.0/0'],
        ]);

        $this->assertContains(
            'Rule "everyone" allows every request',
            $this->titles($this->lint($config), Diagnosis::ERROR)
        );
    }

    /**
     * A narrow allow rule shadows nothing.
     *
     * The check must not fire on the ordinary case, which is an allow list
     * ahead of the block rules — that is how the firewall is meant to be used.
     */
    public function testANarrowAllowRuleIsNotShadowing(): void
    {
        $config = $this->goodConfig();
        array_unshift($config['plugins'], [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'allow',
            'weight' => -100,
            'enable' => true,
            'metadata' => ['name' => 'office'],
            'config' => ['198.51.100.0/24'],
        ]);

        $this->assertSame([], $this->titles($this->lint($config), Diagnosis::ERROR));
    }

    /**
     * An allow-all with nothing after it is not shadowing anything.
     */
    public function testAnAllowAllWithNothingAfterItIsNotReported(): void
    {
        $config = [
            'global' => ['mode' => 'block'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                'response' => 'allow',
                'enable' => true,
                'config' => ['0.0.0.0/0'],
            ]],
        ];

        $this->assertSame([], $this->titles($this->lint($config), Diagnosis::ERROR));
    }

    /**
     * A configuration with no rules at all allows everything.
     */
    public function testAConfigWithNoRulesIsAWarning(): void
    {
        $findings = $this->lint(['global' => ['mode' => 'block'], 'plugins' => []]);

        $this->assertSame(['No rules are configured'], $this->titles($findings, Diagnosis::WARNING));
    }

    /**
     * A config file that could not be read is an error.
     */
    public function testAConfigThatFailedToLoadIsAnError(): void
    {
        $findings = (new ConfigLinter([sys_get_temp_dir() . '/definitely-not-here-' . uniqid() . '.yml']))->run();

        $this->assertNotSame([], array_filter(
            $this->titles($findings, Diagnosis::ERROR),
            static fn(string $t): bool => str_contains($t, 'failed to load')
        ));
    }

    /**
     * Junk among the plugins is stepped over.
     */
    public function testMalformedEntriesAreSkipped(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][] = 'not a plugin map';
        $config['plugins'][] = ['plugin' => 'Not\\A\\Real\\Class', 'config' => []];
        $config['plugins'][] = ['plugin' => \stdClass::class, 'config' => []];

        $findings = $this->lint($config);

        $this->assertNotSame([], $findings, 'It produced a report rather than dying');
    }

    /**
     * Every odd shape a hand-edited config can hold is stepped over.
     *
     * A linter is run on configs somebody is unsure about, so the shapes below
     * are its working conditions rather than edge cases: a name that is not a
     * string, `config:` written as a scalar, a rule that is not a string, an
     * entry with no class, a class that does not exist, one that is not a
     * plugin, and one whose constructor throws.
     */
    public function testEveryMalformedShapeIsSteppedOver(): void
    {
        $config = [
            'global' => ['mode' => 'block'],
            'plugins' => [
                // A name that is not a string, and rules that are not strings.
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => ['name' => 123],
                    'config' => [42, ['nested' => true], 'path:/ok'],
                ],
                // `config:` as a scalar, and a name explicitly set to empty --
                // which is not a name, so it is not two rules sharing one.
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => ['name' => ''],
                    'config' => 'not a list',
                ],
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => ['name' => ''],
                    'config' => ['path:/also-ok'],
                ],
                // An allow rule whose class has no known catch-all form.
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\UserAgent',
                    'response' => 'allow',
                    'enable' => true,
                    'config' => ['bot'],
                ],
                // No class at all, a class that does not exist, and one that is
                // not a plugin.
                ['response' => 'block', 'enable' => true, 'config' => []],
                ['plugin' => 'Not\\A\\Real\\Class', 'config' => []],
                ['plugin' => \stdClass::class, 'config' => []],
                // A plugin whose constructor throws: the doctor's question,
                // not the linter's.
                ['plugin' => \Kanopi\Firewall\Tests\Plugins\TestThrowingPlugin::class, 'config' => []],
            ],
        ];

        $findings = $this->lint($config);

        $this->assertNotSame([], $findings, 'It produced a report rather than dying');

        // Some of these *are* reported, and correctly: a rule of `42` or a
        // nested map cannot match anything, which is the linter doing its job
        // rather than tripping over the shape. What matters is that it reached
        // the end and said something about each plugin it could read.
        $this->assertNotSame(
            [],
            array_filter(
                $this->titles($findings, Diagnosis::ERROR),
                static fn(string $t): bool => str_contains($t, 'cannot match')
            ),
            'A rule that is not a rule is reported rather than skipped silently'
        );

        $this->assertSame(
            [],
            array_filter(
                $this->titles($findings, Diagnosis::WARNING),
                static fn(string $t): bool => str_contains($t, 'Two rules are named')
            ),
            'Two rules with an empty name are not two rules sharing a name'
        );
    }

    /**
     * A rule list written as a map is left alone.
     *
     * `config:` is a list. Written as a map -- `config: { a: "path:/x" }` --
     * the rule inspection cannot read it as rules, and guessing at the shape
     * would produce complaints about a config whose real problem is elsewhere.
     */
    public function testARuleListWrittenAsAMapIsSkipped(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][0]['config'] = ['first' => 'nonsense.thing:x'];

        $this->assertSame(
            [],
            array_filter(
                $this->titles($this->lint($config), Diagnosis::ERROR),
                static fn(string $t): bool => str_contains($t, 'cannot match')
            ),
            'A keyed map is not inspected as a rule list'
        );
    }

    /**
     * A class that cannot be instantiated at all is skipped.
     *
     * `AbstractPluginBase` passes both earlier checks -- it exists, and it
     * implements the interface -- and then cannot be reflected into an
     * instance. Naming a base class in `plugins:` is an ordinary mistake, and
     * the linter has to survive it rather than fatal on the reflection.
     */
    public function testAnAbstractPluginClassIsSkipped(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][] = [
            'plugin' => \Kanopi\Firewall\Plugins\AbstractPluginBase::class,
            'response' => 'block',
            'enable' => true,
            'config' => ['nonsense.thing:x'],
        ];

        $findings = $this->lint($config);

        $this->assertNotSame([], $findings, 'It produced a report rather than dying');
        $this->assertSame(
            [],
            array_filter(
                $this->titles($findings, Diagnosis::ERROR),
                static fn(string $t): bool => str_contains($t, 'cannot match')
            ),
            'Its rules are left uninspected rather than wrongly condemned'
        );
    }

    /**
     * A plugin whose declared variables are not a list is declined.
     *
     * `knownRuleVariables()` is reached by reflection, so nothing enforces its
     * return type at the call site — a plugin outside this package can return
     * anything. Declining leaves its rules uninspected, which is the safe
     * direction: the alternative is condemning valid rules on the strength of
     * a value that was never a variable list.
     */
    public function testAPluginWithUnreadableVariablesIsDeclined(): void
    {
        $config = $this->goodConfig();
        $config['plugins'][] = [
            'plugin' => \Kanopi\Firewall\Tests\Plugins\TestOddVariablesPlugin::class,
            'response' => 'block',
            'enable' => true,
            'config' => ['nonsense.thing:x'],
        ];

        $this->assertSame(
            [],
            array_filter(
                $this->titles($this->lint($config), Diagnosis::ERROR),
                static fn(string $t): bool => str_contains($t, 'cannot match')
            )
        );
    }

    /**
     * Linting touches nothing.
     *
     * It read #173's rule inspection by *constructing* each plugin, and
     * constructing a plugin touches the environment: a rate limit rule builds
     * its storage backend, which opens a connection and creates its table.
     *
     * So `--lint` against a production config, run from a laptop, created
     * tables in that production database -- from a command documented as
     * saying nothing about the environment and reasonably expected to be safe
     * to run against anything.
     */
    public function testLintingDoesNotCreateADatabase(): void
    {
        $database = sys_get_temp_dir() . '/fw-lint-sideeffect-' . uniqid() . '.sqlite';

        $this->lint([
            'global' => ['mode' => 'block'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
                'response' => 'block',
                'enable' => true,
                'metadata' => ['storage' => [
                    'type' => 'Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage',
                    'config' => ['connection' => ['driver' => 'pdo_sqlite', 'path' => $database]],
                ]],
                'config' => [],
            ]],
        ]);

        $this->assertFileDoesNotExist($database, 'Linting must not build storage backends');

        @unlink($database);
    }

    /**
     * Nor does it fetch a rule source.
     *
     * The same cause: building a plugin loads its `metadata.sources`. A linter
     * that pulled every remote list somebody had configured would be a poor
     * thing to run in a loop, or against somebody else's config.
     */
    public function testLintingDoesNotFetchSources(): void
    {
        $list = sys_get_temp_dir() . '/fw-lint-list-' . uniqid() . '.txt';
        file_put_contents($list, "203.0.113.9\n");

        $cache = sys_get_temp_dir() . '/kanopi-firewall-sources';
        $before = is_dir($cache) ? count(glob($cache . '/*') ?: []) : 0;

        $this->lint([
            'global' => ['mode' => 'block'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                'response' => 'block',
                'enable' => true,
                'metadata' => ['sources' => [$list]],
                'config' => [],
            ]],
        ]);

        $after = is_dir($cache) ? count(glob($cache . '/*') ?: []) : 0;

        $this->assertSame($before, $after, 'Linting must not fetch rule sources');

        @unlink($list);
    }

    /**
     * The linter leaves the application's logger as it found it.
     *
     * It no longer swaps one in -- rule inspection is read without building a
     * plugin at all -- but the guarantee is worth keeping asserted, because the
     * cheap way back to constructing them brings the logger swap with it.
     */
    public function testTheLoggerIsRestored(): void
    {
        $before = \Kanopi\Firewall\Logging\LoggingFactory::logger();

        $this->lint($this->goodConfig());

        $this->assertSame($before, \Kanopi\Firewall\Logging\LoggingFactory::logger());
    }
}
