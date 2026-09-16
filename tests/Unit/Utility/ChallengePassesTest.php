<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\ChallengePasses;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reading and withdrawing passes from a configuration (#368).
 *
 * The part `bin/firewall-challenge` is a thin shell over, so the command test
 * can stay about exit codes and this can be about behaviour.
 */
class ChallengePassesTest extends AbstractTestCase
{
    private const SECRET = 'challenge-passes-test-secret-value';

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-passes-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->dir . '/*') as $file) {
            if (is_string($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    public function testItNamesTheBackendAndWhetherARevocationWouldBeRead(): void
    {
        $backend = $this->passes(['revocable' => true])->backend();

        $this->assertSame(FileStorage::class, $backend['class']);
        $this->assertTrue($backend['durable']);
        $this->assertTrue($backend['revocable']);
    }

    /**
     * Pointed at a throwaway store a revocation is written, reported, and
     * forgotten when the process ends — truthfully and uselessly. Saying so is
     * the difference between that and a working revocation.
     */
    public function testAStoreThatDiesWithTheProcessSaysSo(): void
    {
        $backend = $this->passes([], InMemoryStorage::class)->backend();

        $this->assertFalse($backend['durable']);
        $this->assertFalse($backend['revocable'], 'challenge.revocable is off by default');
    }

    public function testItReadsTheClaimsOfAPassItSigned(): void
    {
        $passes = $this->passes([]);
        $claims = $passes->inspect($this->mint());

        $this->assertIsArray($claims);
        $this->assertSame('10.0.0.50', $claims['ip']);
        $this->assertIsInt($claims['iat']);
    }

    public function testItRefusesAPassSignedBySomethingElse(): void
    {
        $other = new TokenManager('a-completely-different-secret', 'math', 'math');

        $this->assertNull($this->passes([])->inspect($other->mint($this->request(), 900, 'math')));
    }

    /**
     * Not a degraded mode: without the secret nothing can tell a pass from a
     * string, so there is no useful thing left to do.
     */
    public function testWithoutASecretThereIsNothingToDo(): void
    {
        $this->expectException(ConfigurationException::class);

        $this->passes([], FileStorage::class, false)->inspect('anything');
    }

    public function testRevokingAndRestoringRoundTrip(): void
    {
        $passes = $this->passes(['revocable' => true]);
        $claims = (array) $passes->inspect($this->mint());
        $nonce = (string) $claims['nonce'];

        $this->assertNull($passes->record($nonce));
        $this->assertTrue($passes->revoke($nonce, (int) $claims['exp'], 'abusing it'));
        $this->assertSame('abusing it', $passes->record($nonce)['reason'] ?? null);
        $this->assertTrue($passes->restore($nonce));
        $this->assertNull($passes->record($nonce));
    }

    #[DataProvider('cutoffProvider')]
    public function testTheConfiguredCutoffIsReported(mixed $declared, int $expected): void
    {
        $this->assertSame($expected, $this->passes(['passes_valid_from' => $declared])->validFrom());
    }

    /**
     * @return array<string, array{0: mixed, 1: int}>
     */
    public static function cutoffProvider(): array
    {
        return [
            'unset' => [null, 0],
            'empty' => ['', 0],
            'an epoch' => [1789000000, 1789000000],
            'an epoch as a string' => ['1789000000', 1789000000],
            'a date' => ['2099-01-01 00:00:00 UTC', 4070908800],
        ];
    }

    /**
     * No live token can outlast the ceiling counted from now, so a revocation
     * held that long always covers the pass being withdrawn. Holding it for
     * less would quietly un-revoke.
     */
    public function testTheDefaultRevocationWindowCoversAnyLivePass(): void
    {
        $this->assertEqualsWithDelta(time() + 900, $this->passes(['ttl' => 900])->defaultExpiry(), 1);
        $this->assertEqualsWithDelta(time() + 3600, $this->passes([])->defaultExpiry(), 1);
        $this->assertEqualsWithDelta(time() + 3600, $this->passes(['ttl' => 'one hour'])->defaultExpiry(), 1);
    }

    private function mint(): string
    {
        return (new TokenManager(self::SECRET, 'math', 'math'))->mint($this->request(), 900, 'math');
    }

    private function request(): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']);
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function passes(array $challenge, string $storage = FileStorage::class, bool $withSecret = true): ChallengePasses
    {
        $config = [
            'challenge' => $challenge + ['provider' => 'math'] + ($withSecret ? ['secret' => self::SECRET] : []),
            'storage' => ['type' => $storage],
        ];

        if ($storage === FileStorage::class) {
            $config['storage']['config'] = ['storage_file' => $this->dir . '/blocked.data'];
        }

        return new ChallengePasses([$config]);
    }
}
