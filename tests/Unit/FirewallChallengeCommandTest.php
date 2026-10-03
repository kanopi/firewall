<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;

use Kanopi\Firewall\Challenge\TokenManager;
use Symfony\Component\HttpFoundation\Request;

/**
 * `bin/firewall challenge` (#368).
 *
 * A subprocess, like the other command tests: the exit codes are the contract,
 * and so is the stdout/stderr split that keeps `--json` parseable.
 */
final class FirewallChallengeCommandTest extends AbstractTestCase
{
    use RunsFirewallCommands;

    private const EXIT_OK = 0;
    private const EXIT_UNANSWERABLE = 1;
    private const EXIT_USAGE = 2;

    private const SECRET = 'firewall-challenge-command-secret';

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-challenge-cmd-' . uniqid();
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

    public function testInspectingAPassNamesTheAddressAndTheNonce(): void
    {
        $result = $this->runChallenge([$this->config(), '--inspect=' . $this->mint()]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertStringContainsString('address:  10.0.0.50', $result['stdout']);
        $this->assertStringContainsString('provider: math', $result['stdout']);
        $this->assertMatchesRegularExpression('/nonce:    [0-9a-f]{32}/', $result['stdout']);
    }

    /**
     * The backend is named for the same reason `bin/firewall block` names it:
     * a revocation is only worth anything against the store the site reads.
     */
    public function testTheBackendIsAlwaysNamed(): void
    {
        $result = $this->runChallenge([$this->config(), '--inspect=' . $this->mint()]);

        $this->assertStringContainsString('backend: Kanopi\Firewall\Storage\FileStorage', $result['stdout']);
    }

    /**
     * A revocation written while `challenge.revocable` is off is recorded and
     * never read. Saying so beats letting somebody believe it took effect.
     */
    public function testItWarnsWhenTheFirewallWouldNotConsultTheList(): void
    {
        $off = $this->runChallenge([$this->config(false), '--inspect=' . $this->mint()]);
        $on = $this->runChallenge([$this->config(), '--inspect=' . $this->mint()]);

        $this->assertStringContainsString('challenge.revocable is off', $off['stdout']);
        $this->assertStringNotContainsString('challenge.revocable is off', $on['stdout']);
    }

    public function testRevokingThenCheckingThenRestoring(): void
    {
        $config = $this->config();
        $token = $this->mint();

        $revoked = $this->runChallenge([$config, '--revoke=' . $token, '--reason=abusing it']);
        $this->assertSame(self::EXIT_OK, $revoked['code'], $revoked['stderr']);
        $this->assertStringContainsString('Revoked ', $revoked['stdout']);

        $nonce = $this->nonceOf($token);

        $status = $this->runChallenge([$config, '--status=' . $nonce, '--json']);
        $record = json_decode($status['stdout'], true);
        $this->assertSame('abusing it', $record['revoked']['reason'] ?? null);

        $restored = $this->runChallenge([$config, '--restore=' . $nonce]);
        $this->assertSame(self::EXIT_OK, $restored['code']);
        $this->assertStringContainsString('restored', $restored['stdout']);

        $after = $this->runChallenge([$config, '--status=' . $nonce, '--json']);
        $this->assertNull(json_decode($after['stdout'], true)['revoked']);
    }

    /**
     * The log line is what an operator has, not the token, so revoking by
     * nonce has to work on its own.
     */
    public function testRevokingByNonceNeedsNoToken(): void
    {
        $config = $this->config();

        $result = $this->runChallenge([$config, '--revoke-nonce=' . str_repeat('a', 32)]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertTrue(json_decode($this->runChallenge([$config, '--status=' . str_repeat('a', 32), '--json'])['stdout'], true)['revoked'] !== null);
    }

    public function testRestoringANonceThatWasNotRevokedIsNotAnError(): void
    {
        $result = $this->runChallenge([$this->config(), '--restore=' . str_repeat('b', 32)]);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('nothing to restore', $result['stdout']);
    }

    /**
     * Nothing left to withdraw is a different answer from "done", and the exit
     * code says which.
     */
    public function testRevokingAnExpiredPassReportsThatThereIsNothingLeft(): void
    {
        $result = $this->runChallenge([
            $this->config(),
            '--revoke-nonce=' . str_repeat('c', 32),
            '--expires=' . (time() - 60),
        ]);

        $this->assertSame(self::EXIT_UNANSWERABLE, $result['code']);
        $this->assertStringContainsString('nothing left to revoke', $result['stderr']);
    }

    public function testAStringThatIsNotAPassIsUnanswerable(): void
    {
        $result = $this->runChallenge([$this->config(), '--inspect=not-a-token']);

        $this->assertSame(self::EXIT_UNANSWERABLE, $result['code']);
        $this->assertStringContainsString('not a pass token signed by this configuration', $result['stderr']);
    }

    /**
     * `--revoke` and `--restore` in one invocation is somebody midway through
     * changing their mind. Picking an order is how the wrong one runs.
     */
    public function testTwoActionsAtOnceIsRefused(): void
    {
        $result = $this->runChallenge([$this->config(), '--revoke-nonce=aaa', '--restore=aaa']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('exactly one action', $result['stderr']);
    }

    public function testNoActionIsRefused(): void
    {
        $result = $this->runChallenge([$this->config()]);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('Nothing to do', $result['stderr']);
    }

    public function testUsageErrors(): void
    {
        $this->assertSame(self::EXIT_USAGE, $this->runChallenge(['--inspect=x'])['code'], 'no config file');
        $this->assertSame(self::EXIT_USAGE, $this->runChallenge([$this->dir . '/nope.yml', '--inspect=x'])['code']);
        $this->assertSame(self::EXIT_USAGE, $this->runChallenge([$this->config(), '--expires=soon', '--revoke-nonce=a'])['code']);
        $this->assertSame(self::EXIT_USAGE, $this->runChallenge([$this->config(), '--wat'])['code']);
    }

    public function testHelpExplainsItself(): void
    {
        $result = $this->runChallenge(['--help']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('--revoke-nonce', $result['stdout']);
    }

    /**
     * Without the secret nothing can tell a pass from a string, so the command
     * says that rather than reporting the token as forged.
     */
    public function testAConfigWithNoSecretIsAUsageError(): void
    {
        $path = $this->dir . '/nosecret.yml';
        file_put_contents($path, "challenge: { provider: math }\nstorage:\n  type: '" . \Kanopi\Firewall\Storage\FileStorage::class . "'\n  config: { storage_file: '" . $this->dir . "/blocked.data' }\n");

        $result = $this->runChallenge([$path, '--inspect=' . $this->mint()]);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('secret is empty', $result['stderr']);
    }

    /**
     * A config like config(), with these lines in place of its storage.
     *
     * @param array<int, string> $lines
     */
    private function configWith(array $lines): string
    {
        $path = $this->dir . '/config-' . uniqid('', true) . '.yml';
        file_put_contents($path, implode("\n", [
            'challenge:',
            '  provider: math',
            '  secret: ' . self::SECRET,
            '  ttl: 900',
            '  revocable: true',
            ...$lines,
            '',
        ]));

        return $path;
    }

    /**
     * A pass this configuration signed that carries no nonce.
     */
    private function mintWithoutNonce(): string
    {
        $encode = static fn(string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        $payload = $encode((string) json_encode(['ip' => '10.0.0.50', 'iat' => time(), 'exp' => time() + 900, 'aud' => 'math']));

        return $payload . '.' . $encode(hash_hmac('sha256', $payload, self::SECRET, true));
    }

    /**
     * A pass issued before challenge.passes_valid_from is already refused, and inspecting
     * it says so.
     */
    public function testInspectingAPassFromBeforeTheCutoffSaysItIsRefused(): void
    {
        $path = $this->configWith([
            '  passes_valid_from: ' . (time() + 3600),
            'storage:',
            "  type: '" . \Kanopi\Firewall\Storage\FileStorage::class . "'",
            "  config: { storage_file: '" . $this->dir . "/blocked.data' }",
        ]);

        $result = $this->runChallenge([$path, '--inspect=' . $this->mint()]);

        $this->assertStringContainsString('Already refused: challenge.passes_valid_from is', $result['stdout']);
    }

    /**
     * A signed pass with no nonce has nothing to revoke by.
     */
    public function testRevokingAPassWithNoNonceIsUnanswerable(): void
    {
        $result = $this->runChallenge([$this->config(), '--revoke=' . $this->mintWithoutNonce()]);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('carries no nonce', $result['stderr']);
    }

    /**
     * A store that dies with the process is named as one, because a revocation written
     * to it is forgotten.
     */
    public function testAStoreThatDoesNotLastIsWarnedAbout(): void
    {
        $path = $this->configWith(['storage:', "  type: '" . \Kanopi\Firewall\Storage\InMemoryStorage::class . "'"]);

        $result = $this->runChallenge([$path, '--inspect=' . $this->mint()]);

        $this->assertStringContainsString('does not outlive the process', $result['stdout']);
    }

    /**
     * Storage naming a connection that is not declared is the configuration's problem.
     */
    public function testAnUndeclaredConnectionIsAUsageError(): void
    {
        $path = $this->configWith([
            'storage:',
            "  type: '" . \Kanopi\Firewall\Storage\DatabaseStorage::class . "'",
            "  config: { connection: '%connection(nope)%' }",
        ]);

        $result = $this->runChallenge([$path, '--inspect=' . $this->mint()]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('nope', $result['stderr']);
    }

    public function testAnIncludeThatCannotBeLoadedIsAUsageError(): void
    {
        $path = $this->configWith(['configs:', '  - ' . $this->dir . '/missing.yml']);

        $result = $this->runChallenge([$path, '--inspect=' . $this->mint()]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('Could not load', $result['stderr']);
    }

    private function nonceOf(string $token): string
    {
        $claims = (new TokenManager(self::SECRET, 'math', 'math'))->inspect($token);

        return (string) ($claims['nonce'] ?? '');
    }

    private function mint(): string
    {
        return (new TokenManager(self::SECRET, 'math', 'math'))->mint(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']),
            900,
            'math'
        );
    }

    private function config(bool $revocable = true): string
    {
        $path = $this->dir . '/config' . ($revocable ? '' : '-off') . '.yml';

        file_put_contents($path, implode("\n", [
            'challenge:',
            '  provider: math',
            '  secret: ' . self::SECRET,
            '  ttl: 900',
            '  revocable: ' . ($revocable ? 'true' : 'false'),
            'storage:',
            "  type: '" . \Kanopi\Firewall\Storage\FileStorage::class . "'",
            "  config: { storage_file: '" . $this->dir . "/blocked.data' }",
            '',
        ]));

        return $path;
    }

    /**
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runChallenge(array $args): array
    {
        return $this->runFirewall('challenge', $args);
    }
}
