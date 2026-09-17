<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\PassRevocationList;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The revoked-pass list itself (#368).
 */
class PassRevocationListTest extends AbstractTestCase
{
    private InMemoryStorage $storage;

    private PassRevocationList $list;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = new InMemoryStorage([]);
        $this->list = new PassRevocationList($this->storage);
    }

    public function testARevokedNonceIsReported(): void
    {
        $this->assertFalse($this->list->isRevoked('abc123'));

        $this->assertTrue($this->list->revoke('abc123', time() + 600, 'abusing the pass'));

        $this->assertTrue($this->list->isRevoked('abc123'));
        $this->assertSame('abusing the pass', $this->list->record('abc123')['reason'] ?? null);
    }

    public function testOnlyTheRevokedNonceIsAffected(): void
    {
        $this->list->revoke('abc123', time() + 600);

        $this->assertFalse($this->list->isRevoked('def456'));
        $this->assertNull($this->list->record('def456'));
    }

    /**
     * The token was never changed, so putting the holder's access back is only
     * a matter of forgetting the record.
     */
    public function testRestoringRemovesTheRecord(): void
    {
        $this->list->revoke('abc123', time() + 600);

        $this->assertTrue($this->list->restore('abc123'));
        $this->assertFalse($this->list->isRevoked('abc123'));
    }

    /**
     * Not a failure — there was nothing left to withdraw. The distinction
     * matters because the command reports one differently from the other.
     */
    public function testRevokingAnExpiredPassDoesNothing(): void
    {
        $this->assertFalse($this->list->revoke('abc123', time() - 1));
        $this->assertFalse($this->list->isRevoked('abc123'));
    }

    public function testAnEmptyNonceIsNeverRevokedOrRevocable(): void
    {
        $this->assertFalse($this->list->revoke('', time() + 600));
        $this->assertFalse($this->list->isRevoked(''));
        $this->assertFalse($this->list->restore(''));
        $this->assertNull($this->list->record(''));
    }

    /**
     * A store that can be read should not hand out a list of live pass
     * identifiers for free.
     */
    public function testTheNonceIsNotStoredInTheClear(): void
    {
        $this->list->revoke('abc123', time() + 600);

        $this->assertNull($this->storage->get(PassRevocationList::KEY_PREFIX . 'abc123'));
        $this->assertNotNull($this->storage->get(PassRevocationList::KEY_PREFIX . hash('sha256', 'abc123')));
    }

    /**
     * The record is written with the token's remaining lifetime, so the list
     * disappears exactly when the tokens it covers would have stopped being
     * accepted anyway. Nothing has to sweep it.
     */
    public function testTheRecordIsKeptOnlyAsLongAsTheTokenWouldHaveLived(): void
    {
        $expiresAt = time() + 5;
        $this->list->revoke('abc123', $expiresAt);

        $this->assertSame($expiresAt, $this->list->record('abc123')['expires_at'] ?? null);
    }

    /**
     * A custom backend can hand back whatever it likes. Anything that is not a
     * record reads as "not revoked" rather than being passed on for somebody
     * else to trip over.
     */
    public function testARecordThatIsNotAMapIsIgnored(): void
    {
        $storage = $this->createMock(\Kanopi\Firewall\Storage\StorageInterface::class);
        $storage->method('get')->willReturn('not a record');

        $this->assertNull((new PassRevocationList($storage))->record('abc123'));
    }
}
