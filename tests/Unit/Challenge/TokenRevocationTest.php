<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\PassRevocationList;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Withdrawing a pass before its own expiry (#368).
 *
 * Two levers, both off by default, because the stateless property is the point
 * of the design: a cutoff in time that costs nothing, and a per-nonce list that
 * costs one storage read on an otherwise-valid token.
 */
class TokenRevocationTest extends AbstractTestCase
{
    private const SECRET = 'a-long-random-token-test-secret';

    private const IP = '10.0.0.50';

    /**
     * The claim the cutoff compares against, which tokens did not carry before.
     */
    public function testAMintedPassRecordsWhenItWasIssued(): void
    {
        $before = time();
        $claims = $this->manager()->inspect($this->mint());

        $this->assertIsArray($claims);
        $this->assertGreaterThanOrEqual($before, $claims['iat']);
        $this->assertSame($claims['iat'] + 900, $claims['exp']);
    }

    public function testWithNoCutoffEveryValidPassIsAccepted(): void
    {
        $this->assertTrue($this->manager()->verify($this->mint(), $this->request()));
    }

    public function testACutoffAfterTheIssueTimeWithdrawsThePass(): void
    {
        $token = $this->mint();

        $this->assertTrue($this->manager()->verify($token, $this->request()));
        $this->assertFalse($this->manager(time() + 1)->verify($token, $this->request()));
    }

    public function testACutoffBeforeTheIssueTimeLeavesThePassAlone(): void
    {
        $this->assertTrue($this->manager(time() - 60)->verify($this->mint(), $this->request()));
    }

    /**
     * A token minted before `iat` existed cannot be dated, so any cutoff
     * withdraws it — which is the right way round. `passes_valid_from` is a
     * revocation lever, and the passes most worth withdrawing with it are the
     * ones minted before the firewall was fixed.
     */
    public function testAPassPredatingTheIssueClaimIsWithdrawnByAnyCutoff(): void
    {
        $legacy = $this->legacyToken(['ip' => self::IP, 'exp' => time() + 900, 'aud' => 'math', 'nonce' => 'n1']);

        $this->assertTrue($this->manager()->verify($legacy, $this->request()), 'It should still be accepted with no cutoff');
        $this->assertFalse($this->manager(1)->verify($legacy, $this->request()));
    }

    public function testARevokedNonceIsRefused(): void
    {
        $storage = new InMemoryStorage([]);
        $revocations = new PassRevocationList($storage);
        $manager = $this->manager(0, $revocations);
        $token = $this->mint();

        $this->assertTrue($manager->verify($token, $this->request()));

        $claims = $manager->inspect($token);
        $this->assertIsArray($claims);
        $revocations->revoke((string) $claims['nonce'], (int) $claims['exp']);

        $this->assertFalse($manager->verify($token, $this->request()));
    }

    public function testRestoringMakesThePassWorkAgain(): void
    {
        $revocations = new PassRevocationList(new InMemoryStorage([]));
        $manager = $this->manager(0, $revocations);
        $token = $this->mint();
        $claims = (array) $manager->inspect($token);

        $revocations->revoke((string) $claims['nonce'], (int) $claims['exp']);
        $this->assertFalse($manager->verify($token, $this->request()));

        $revocations->restore((string) $claims['nonce']);
        $this->assertTrue($manager->verify($token, $this->request()));
    }

    public function testRevokingOnePassLeavesAnotherAlone(): void
    {
        $revocations = new PassRevocationList(new InMemoryStorage([]));
        $manager = $this->manager(0, $revocations);
        $revoked = $this->mint();
        $kept = $this->mint();

        $revocations->revoke((string) ((array) $manager->inspect($revoked))['nonce'], time() + 900);

        $this->assertFalse($manager->verify($revoked, $this->request()));
        $this->assertTrue($manager->verify($kept, $this->request()));
    }

    /**
     * The storage read is the last thing verification does, and only on a
     * token that is otherwise entirely good. A token that was going to be
     * refused anyway must not cost a round trip to the store — nor may one
     * that reaches a manager holding no list at all.
     */
    public function testTheStoreIsNotConsultedForATokenThatFailsEarlier(): void
    {
        $storage = $this->createMock(\Kanopi\Firewall\Storage\StorageInterface::class);
        $storage->expects($this->never())->method('get');

        $manager = $this->manager(0, new PassRevocationList($storage));

        // Right token, wrong client: the IP binding refuses it before the
        // revocation list is reached.
        $this->assertFalse($manager->verify(
            $this->mint(),
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '198.51.100.9'])
        ));
    }

    /**
     * A pass carrying no nonce cannot be revoked by one, and is not refused
     * for it either.
     */
    public function testAPassWithNoNonceIsNotTreatedAsRevoked(): void
    {
        $manager = $this->manager(0, new PassRevocationList(new InMemoryStorage([])));
        $legacy = $this->legacyToken(['ip' => self::IP, 'exp' => time() + 900, 'aud' => 'math']);

        $this->assertTrue($manager->verify($legacy, $this->request()));
    }

    public function testInspectReadsTheClaimsOfASignedToken(): void
    {
        $claims = $this->manager()->inspect($this->mint());

        $this->assertIsArray($claims);
        $this->assertSame(self::IP, $claims['ip']);
        $this->assertSame('math', $claims['prv']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $claims['nonce']);
    }

    /**
     * An unsigned payload is somebody's guess about a token rather than a
     * token, so it reads as nothing at all.
     */
    public function testInspectRefusesAnythingThisManagerDidNotSign(): void
    {
        $manager = $this->manager();
        $token = $this->mint();

        $this->assertNull($manager->inspect(''));
        $this->assertNull($manager->inspect('no-dot-here'));
        $this->assertNull($manager->inspect('.signature'));
        $this->assertNull($manager->inspect('payload.'));
        $this->assertNull($manager->inspect($token . 'x'));
        $this->assertNull((new TokenManager('a-different-secret', 'math', 'math'))->inspect($token));
    }

    /**
     * Signed by this manager, and still not a token: the payload has to decode
     * to something before its claims can be read.
     */
    public function testInspectRefusesASignedPayloadThatIsNotAToken(): void
    {
        $manager = $this->manager();

        // Signed, and not base64url at all: `!` is outside the alphabet, and
        // the decode is strict rather than silently truncating.
        $this->assertNull($manager->inspect('!!!!.' . $manager->sign('!!!!')));

        // Signed, decodes, and is not a claim set.
        $this->assertNull($manager->inspect($this->signPayload($manager, 'not json at all')));
        $this->assertNull($manager->inspect($this->signPayload($manager, '"a string, validly encoded"')));
    }

    private function manager(int $validFrom = 0, ?PassRevocationList $revocations = null): TokenManager
    {
        return new TokenManager(self::SECRET, 'math', 'math', $validFrom, $revocations);
    }

    private function mint(): string
    {
        return $this->manager()->mint($this->request(), 900, 'math');
    }

    private function request(): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => self::IP]);
    }

    /**
     * A token in the shape minted before a claim existed.
     *
     * @param array<string, mixed> $payload
     */
    private function legacyToken(array $payload): string
    {
        return $this->signPayload($this->manager(), (string) json_encode($payload));
    }

    private function signPayload(TokenManager $tokenManager, string $payload): string
    {
        $encoded = rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');

        return $encoded . '.' . $tokenManager->sign($encoded);
    }
}
