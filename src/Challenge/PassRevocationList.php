<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Kanopi\Firewall\Storage\StorageInterface;

/**
 * Pass tokens withdrawn before their own expiry (#368).
 *
 * A pass token is stateless and HMAC-signed, so once issued it is accepted
 * until its `exp` passes. That is the property the design is built on — no
 * shared session store, horizontal scaling for free — and it is also why the
 * only lever before this was rotating `challenge.secret`, which re-challenges
 * every legitimate visitor holding a pass in order to withdraw one.
 *
 * This trades a little of that back, and only for deployments that ask:
 *
 * - **Nothing is consulted unless `challenge.revocable` is on.** `TokenManager`
 *   holds this as a nullable collaborator; NULL means not one storage read,
 *   ever, which is what a deployment that never revokes anything should pay.
 * - **The list is keyed by the token's `nonce`**, which the payload has always
 *   carried. Nothing new had to be minted into tokens for this to reach the
 *   ones already in the wild.
 * - **It trims itself.** Every record is written with the token's remaining
 *   lifetime, so it disappears exactly when the token it revokes would have
 *   stopped being accepted anyway. The list is bounded by the longest TTL in
 *   play rather than growing forever.
 *
 * Revoking a pass is the opposite direction from blocking an address, and the
 * two are not substitutes: blocking refuses a client, this withdraws an
 * *exemption* a client earned.
 */
final class PassRevocationList
{
    /**
     * Storage key prefix for a revoked pass.
     *
     * Shares the store with the block list and with single-use solution
     * receipts, and is namespaced the same way they are so a revocation can
     * never be mistaken for a block.
     */
    public const KEY_PREFIX = 'fw_challenge_revoked:';

    /**
     * @param StorageInterface $storage
     *   The configured store. Whatever the block list uses — the records are
     *   small, short-lived, and want the same fleet-wide visibility.
     */
    public function __construct(private readonly StorageInterface $storage)
    {
    }

    /**
     * Withdraw a pass.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     * @param int $expiresAt
     *   When the token would have expired on its own, as a unix timestamp.
     *   The record is kept until then and no longer.
     * @param string $reason
     *   Free text recorded alongside, so a later reader knows why.
     *
     * @return bool
     *   TRUE when the record was written. FALSE when the token had already
     *   expired, which is not a failure — there was nothing left to revoke.
     */
    public function revoke(string $nonce, int $expiresAt, string $reason = ''): bool
    {
        $ttl = $expiresAt - time();

        if ($nonce === '' || $ttl <= 0) {
            return false;
        }

        return $this->storage->set($this->key($nonce), [
            'revoked_at' => time(),
            'expires_at' => $expiresAt,
            'reason' => $reason,
        ], $ttl);
    }

    /**
     * Put a pass back.
     *
     * For the revocation made in a hurry against the wrong nonce. The token
     * itself was never changed, so restoring the holder's access is only a
     * matter of forgetting that this was ever written.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     *
     * @return bool
     *   TRUE when the record was removed.
     */
    public function restore(string $nonce): bool
    {
        return $nonce !== '' && $this->storage->delete($this->key($nonce));
    }

    /**
     * Has this pass been withdrawn?
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     *
     * @return bool
     *   TRUE when a revocation record is present.
     */
    public function isRevoked(string $nonce): bool
    {
        return $nonce !== '' && $this->storage->get($this->key($nonce)) !== null;
    }

    /**
     * What is recorded about a revoked pass.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     *
     * @return array<string, mixed>|null
     *   The record, or NULL when the pass is not revoked.
     */
    public function record(string $nonce): ?array
    {
        $record = $nonce === '' ? null : $this->storage->get($this->key($nonce));

        return is_array($record) ? $record : null;
    }

    /**
     * The storage key for a nonce.
     *
     * Hashed, like the single-use solution receipts are. A nonce is not a
     * secret — it is one of the claims in a token the client already holds —
     * but a store that can be read should not hand out a list of live pass
     * identifiers for free.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     *
     * @return string
     *   The namespaced key.
     */
    private function key(string $nonce): string
    {
        return self::KEY_PREFIX . hash('sha256', $nonce);
    }
}
