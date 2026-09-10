<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `bin/firewall-rule` (#290).
 *
 * Driven as a real subprocess, like the other command tests: the exit code is
 * part of the contract, and so is the stdout/stderr split that keeps `--json`
 * parseable.
 *
 * The assertion this file exists for is the one about the *other* file: after
 * every action, the hand-written config must come back byte for byte. That is
 * the whole reason the command owns a second file rather than editing the one
 * it was pointed at.
 */
final class FirewallRuleCommandTest extends AbstractTestCase
{
    private const EXIT_OK = 0;
    private const EXIT_REFUSED = 1;
    private const EXIT_USAGE = 2;

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-rule-' . uniqid('', true);
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * A config with comments worth keeping, and one rule the operator wrote.
     */
    private const HANDWRITTEN = <<<'YML'
    # A comment that matters.
    configs:
      - "firewall-managed.yml"

    global:
      # why this is log
      mode: log

    storage:
      type: 'Kanopi\Firewall\Storage\InMemoryStorage'

    plugins:
      - plugin: "Kanopi\\Firewall\\Plugins\\Url"
        response: block
        enable: true
        metadata: { name: xmlrpc }   # trailing note
        config: ['path:/xmlrpc.php']
    YML;

    /**
     * Lay down a config whose managed file already exists, so the include is
     * not dangling.
     */
    private function project(): string
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, self::HANDWRITTEN . "\n");
        $this->runRule(['init', $config]);

        return $config;
    }

    /**
     * Run the script and capture stdout, stderr and the exit code separately.
     *
     * `runRule()`, not `run()`: `TestCase::run()` is final, and overriding it
     * is a fatal error rather than a failing test.
     *
     * @param array<int, string> $args
     *   Arguments after the script name.
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runRule(array $args): array
    {
        $command = array_merge(
            [PHP_BINARY, '-d', 'display_errors=stderr', dirname(__DIR__, 2) . '/bin/firewall-rule'],
            $args,
        );

        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);

        $this->assertIsResource($process, 'Could not start bin/firewall-rule');

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    // -----------------------------------------------------------------------
    // The promise
    // -----------------------------------------------------------------------

    /**
     * The reason this feature has the shape it has.
     *
     * A parse-and-dump would leave the config semantically identical and
     * strip every comment in it. Byte-for-byte is the only assertion that
     * catches that.
     */
    public function testTheHandWrittenConfigIsNeverTouched(): void
    {
        $config = $this->project();
        $before = (string) file_get_contents($config);

        $this->runRule(['add', $config, '--ip=203.0.113.0/24', '--name=scraper']);
        $this->runRule(['disable', 'scraper', $config]);
        $this->runRule(['enable', 'scraper', $config]);
        $this->runRule(['remove', 'scraper', $config]);
        $this->runRule(['list', $config]);

        $this->assertSame($before, (string) file_get_contents($config));
        $this->assertStringContainsString('# why this is log', (string) file_get_contents($config));
    }

    // -----------------------------------------------------------------------
    // init
    // -----------------------------------------------------------------------

    /**
     * `init` writes the file and says which line to add, in that order --
     * a `configs:` entry naming a missing file empties the whole document.
     */
    public function testInitCreatesTheFileAndExplainsTheOrdering(): void
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, "global: { mode: log }\n");

        $result = $this->runRule(['init', $config]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertFileExists($this->dir . '/firewall-managed.yml');
        $this->assertStringContainsString('configs:', $result['stdout']);
        $this->assertStringContainsString('- "firewall-managed.yml"', $result['stdout']);
        $this->assertStringContainsString('now that the file exists', $result['stdout']);
    }

    /**
     * Running it twice does not clobber the rules in it.
     */
    public function testInitIsIdempotent(): void
    {
        $config = $this->project();
        $this->runRule(['add', $config, '--ip=203.0.113.1', '--name=keep']);

        $result = $this->runRule(['init', $config]);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('already exists', $result['stdout']);
        $this->assertStringContainsString('keep', (string) file_get_contents($this->dir . '/firewall-managed.yml'));
    }

    // -----------------------------------------------------------------------
    // add
    // -----------------------------------------------------------------------

    public function testAddWritesARuleTheFirewallCanSee(): void
    {
        $config = $this->project();

        $result = $this->runRule([
            'add',
            $config,
            '--ip=198.51.100.0/24',
            '--response=allow',
            '--name=office',
            '--weight=-100',
        ]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stdout'] . $result['stderr']);
        $this->assertStringContainsString('Added allow office', $result['stdout']);

        $listed = $this->runRule(['list', $config, '--json']);
        $rules = json_decode($listed['stdout'], true)['rules'];

        $this->assertSame(['xmlrpc', 'office'], array_column($rules, 'name'));
        $this->assertSame([false, true], array_column($rules, 'managed'));
        $this->assertSame(-100, $rules[1]['weight']);
    }

    /**
     * The check that separates "the command worked" from "the rule is in
     * force". Nothing includes the managed file here, so the rule exists on
     * disk and will never be evaluated -- and saying nothing about that during
     * an incident would be the worst thing this could do.
     */
    public function testARuleNothingIncludesIsReportedAndExitsNonZero(): void
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, "global: { mode: log }\n");

        $result = $this->runRule(['add', $config, '--ip=203.0.113.1', '--name=orphan']);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertStringContainsString('the firewall will not see it', $result['stdout']);
        $this->assertStringContainsString('configs:', $result['stdout']);
        $this->assertFileExists($this->dir . '/firewall-managed.yml');

        $json = $this->runRule(['add', $config, '--ip=203.0.113.2', '--name=orphan2', '--json']);
        $this->assertFalse(json_decode($json['stdout'], true)['in_force']);
    }

    /**
     * `--path` writes the plugin's own syntax, so the rule means what it looks
     * like.
     */
    public function testPathShorthandProducesAUrlRule(): void
    {
        $config = $this->project();

        $result = $this->runRule(['add', $config, '--path=/xmlrpc.php', '--name=no-xmlrpc', '--json']);
        $decoded = json_decode($result['stdout'], true);

        $this->assertSame(\Kanopi\Firewall\Plugins\Url::class, $decoded['plugin']);
        $this->assertSame(['path:/xmlrpc.php'], $decoded['config']);
    }

    /**
     * A generated name is still a name. An unnamed rule is one the log cannot
     * tell from every other rule of its class (#182), and one this command
     * could never find again to remove.
     */
    public function testAnUnnamedRuleGetsAName(): void
    {
        $config = $this->project();

        $result = $this->runRule(['add', $config, '--ip=203.0.113.9', '--json']);
        $name = json_decode($result['stdout'], true)['name'];

        $this->assertIsString($name);
        $this->assertNotSame('', $name);
        $this->assertSame(self::EXIT_OK, $this->runRule(['remove', $name, $config])['code']);
    }

    public function testDryRunWritesNothing(): void
    {
        $config = $this->project();
        $managed = $this->dir . '/firewall-managed.yml';
        $before = (string) file_get_contents($managed);

        $result = $this->runRule(['add', $config, '--ip=203.0.113.1', '--name=nope', '--dry-run']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('Would add', $result['stdout']);
        $this->assertSame($before, (string) file_get_contents($managed));
    }

    /**
     * @param array<int, string> $args
     *   The arguments that should be refused.
     * @param string $expected
     *   The fragment stderr must carry.
     */
    #[DataProvider('badUsage')]
    public function testUsageErrors(array $args, string $expected): void
    {
        $config = $this->project();

        $result = $this->runRule(array_merge([$args[0], $config], array_slice($args, 1)));

        $this->assertSame(self::EXIT_USAGE, $result['code'], $result['stdout']);
        $this->assertStringContainsString($expected, $result['stderr']);
    }

    /**
     * @return array<string, array{array<int, string>, string}>
     */
    public static function badUsage(): array
    {
        return [
            'add with nothing to match' => [['add', '--name=x'], 'needs at least one --rule='],
            'an unknown response' => [['add', '--ip=1.1.1.1', '--response=maybe'], 'Unknown --response'],
            'an unknown plugin' => [['add', '--rule=x', '--plugin=banana'], 'Unknown --plugin'],
            'an unknown option' => [['list', '--wat'], 'Unknown option'],
            // The first bare word is the rule name, so this consumed the
            // config and would otherwise report "no managed rule is named
            // firewall.yml" -- true, and no help at all.
            'remove with the config where the name goes' => [['remove'], 'takes a rule name before'],
        ];
    }

    public function testAnUnknownActionIsRefused(): void
    {
        $result = $this->runRule(['frobnicate', $this->project()]);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('Unknown action', $result['stderr']);
    }

    public function testAMissingConfigIsRefused(): void
    {
        $result = $this->runRule(['list', $this->dir . '/absent.yml']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('not found', $result['stderr']);
    }

    public function testNoConfigAtAllIsRefused(): void
    {
        $result = $this->runRule(['list']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('at least one configuration file', $result['stderr']);
    }

    public function testHelp(): void
    {
        foreach ([[], ['--help'], ['help']] as $args) {
            $result = $this->runRule($args);

            $this->assertSame(self::EXIT_OK, $result['code']);
            $this->assertStringContainsString('firewall-rule ACTION', $result['stdout']);
        }

        // --help after an action, which is where somebody who has started
        // typing will reach for it.
        $result = $this->runRule(['add', '--help']);
        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('--response=NAME', $result['stdout']);
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    /**
     * The refusal that has to be legible. "No managed rule of that name" is
     * true and useless on its own -- the rule plainly exists.
     */
    public function testChangingAHandWrittenRuleIsRefusedByName(): void
    {
        $config = $this->project();

        $result = $this->runRule(['disable', 'xmlrpc', $config]);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertStringContainsString('is one of your own rules', $result['stderr']);
        $this->assertStringContainsString('destroy its comments', $result['stderr']);
    }

    public function testChangingSomethingThatDoesNotExistSaysSo(): void
    {
        $result = $this->runRule(['disable', 'nowhere', $this->project()]);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertStringContainsString('no managed rule is named "nowhere"', $result['stderr']);
    }

    public function testADuplicateNameIsRefused(): void
    {
        $config = $this->project();
        $this->runRule(['add', $config, '--ip=1.1.1.1', '--name=twice']);

        $result = $this->runRule(['add', $config, '--ip=2.2.2.2', '--name=twice']);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertStringContainsString('already exists', $result['stderr']);
    }

    /**
     * Pointed at a file it did not write, it refuses rather than replacing it.
     * This is the guard on the whole feature: `--managed=firewall.yml` by
     * accident would otherwise do exactly the damage the design avoids.
     */
    public function testItRefusesToAdoptAFileItDidNotWrite(): void
    {
        $config = $this->project();
        $before = (string) file_get_contents($config);

        $result = $this->runRule(['add', $config, '--managed=' . $config, '--ip=1.1.1.1', '--name=x']);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertStringContainsString('was not written by this command', $result['stderr']);
        $this->assertSame($before, (string) file_get_contents($config));
    }

    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------

    /**
     * A dangling include empties the whole document, so a listing that just
     * said "no rules are configured" would describe a working firewall with
     * nothing in it. It has to say what failed.
     */
    public function testADanglingIncludeIsReportedRatherThanShownAsEmpty(): void
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, "configs:\n  - \"missing.yml\"\nglobal: { mode: log }\n");

        $result = $this->runRule(['list', $config]);

        $this->assertStringContainsString('did not load cleanly', $result['stderr']);
        $this->assertStringContainsString('missing.yml', $result['stderr']);
        $this->assertStringContainsString('empties the whole document', $result['stderr']);
        $this->assertStringContainsString('firewall-rule init', $result['stderr']);
    }

    public function testAnEmptyConfigListsNothing(): void
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, "global: { mode: log }\n");

        $result = $this->runRule(['list', $config]);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('No rules are configured', $result['stdout']);
    }

    public function testDisableShowsAsOffInTheListing(): void
    {
        $config = $this->project();
        $this->runRule(['add', $config, '--ip=1.1.1.1', '--name=temporary']);

        $this->runRule(['disable', 'temporary', $config]);

        $listed = $this->runRule(['list', $config]);
        $this->assertMatchesRegularExpression('/managed\s+block\s+off\s+0\s+temporary/', $listed['stdout']);

        $this->runRule(['enable', 'temporary', $config]);
        $listed = $this->runRule(['list', $config]);
        $this->assertMatchesRegularExpression('/managed\s+block\s+on\s+0\s+temporary/', $listed['stdout']);
    }

    /**
     * `--managed=` puts the file somewhere else, which is what a project with
     * a config directory needs.
     */
    public function testTheManagedPathCanBeChosen(): void
    {
        $config = $this->dir . '/firewall.yml';
        file_put_contents($config, "configs:\n  - \"elsewhere.yml\"\nglobal: { mode: log }\n");

        $elsewhere = $this->dir . '/elsewhere.yml';
        $this->runRule(['init', $config, '--managed=' . $elsewhere]);

        $result = $this->runRule(['add', $config, '--managed=' . $elsewhere, '--ip=1.1.1.1', '--name=here', '--json']);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertSame($elsewhere, json_decode($result['stdout'], true)['managed_file']);
    }
}
