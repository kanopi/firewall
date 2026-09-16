<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Challenge\PassRevocationList;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;

/**
 * Read and withdraw challenge passes, from a configuration rather than a script (#368).
 *
 * `PassRevocationList` is the mechanism; this is the part an operator can reach. The shape
 * follows `BlockList`, and for the same reason: the interesting operation happens while
 * somebody is on the phone, and "write a PHP script" is a poor answer at that moment.
 *
 * ## The two questions it answers
 *
 * **What is this token?** A pass is opaque to everybody including the operator holding it.
 * `inspect()` verifies the signature and hands back the claims — which address it is bound
 * to, which provider earned it, when it was issued, when it expires, and the `nonce` that
 * identifies it.
 *
 * **Make it stop working.** `revoke()` writes the nonce to the store until the token's own
 * expiry. The token is not modified and cannot be; what changes is that the firewall now
 * refuses it.
 *
 * ## It is only useful against the real store
 *
 * Like `BlockList`, and unlike `bin/firewall-check`. Pointed at a throwaway store a
 * revocation is written, reported, and forgotten when the process ends — truthfully and
 * uselessly — so the backend is named in the output and a store that cannot outlive the
 * process says so.
 */
class ChallengePasses
{
    private ?StorageInterface $storage = null;

    /**
     * @var array<string, mixed>|null
     */
    private ?array $challenge = null;

    /**
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Configuration sources, as `Firewall::create()` takes them.
     */
    public function __construct(private readonly array $configs)
    {
    }

    /**
     * The configured storage backend, built once.
     *
     * @return StorageInterface
     *   The backend this configuration declares.
     */
    public function storage(): StorageInterface
    {
        if (!$this->storage instanceof StorageInterface) {
            $config = Config::load($this->configs);
            $this->storage = StorageFactory::create(is_array($config['storage'] ?? null) ? $config['storage'] : []);
        }

        return $this->storage;
    }

    /**
     * What the backend is, and whether a revocation written to it would last.
     *
     * @return array{class: string, durable: bool, revocable: bool}
     *   `durable` is false for a store that dies with the process. `revocable`
     *   reports `challenge.revocable`, because a revocation written while it is
     *   off is recorded and never read.
     */
    public function backend(): array
    {
        $storage = $this->storage();

        return [
            'class' => $storage::class,
            // The exact class, not `instanceof`: FileStorage extends
            // InMemoryStorage and is perfectly durable.
            'durable' => $storage::class !== InMemoryStorage::class,
            'revocable' => $this->isRevocable(),
        ];
    }

    /**
     * Whether the firewall will consult the revocation list at all.
     *
     * @return bool
     *   TRUE when `challenge.revocable` is on.
     */
    public function isRevocable(): bool
    {
        return ($this->challengeConfig()['revocable'] ?? false) === true;
    }

    /**
     * The cutoff drawn by `challenge.passes_valid_from`, if any.
     *
     * @return int
     *   A unix timestamp, or 0 when no cutoff is configured.
     */
    public function validFrom(): int
    {
        $declared = $this->challengeConfig()['passes_valid_from'] ?? null;

        if (is_int($declared)) {
            return $declared;
        }

        if (is_string($declared) && $declared !== '') {
            return ctype_digit($declared) ? (int) $declared : (int) strtotime($declared);
        }

        return 0;
    }

    /**
     * A token's claims, if it is one this configuration signed.
     *
     * @param string $token
     *   The pass token.
     *
     * @return array<string, mixed>|null
     *   The claims, or NULL when the signature does not match.
     *
     * @throws ConfigurationException
     *   When the configuration declares no `challenge.secret`.
     */
    public function inspect(string $token): ?array
    {
        return $this->tokens()->inspect($token);
    }

    /**
     * Withdraw a pass by its nonce.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     * @param int $expiresAt
     *   When the token expires on its own. The record is kept until then.
     * @param string $reason
     *   Free text recorded alongside.
     *
     * @return bool
     *   TRUE when the record was written; FALSE when the pass had already
     *   expired and there was nothing left to withdraw.
     */
    public function revoke(string $nonce, int $expiresAt, string $reason = ''): bool
    {
        return $this->revocations()->revoke($nonce, $expiresAt, $reason);
    }

    /**
     * Put a pass back.
     *
     * @param string $nonce
     *   The token's `nonce` claim.
     *
     * @return bool
     *   TRUE when a record was removed.
     */
    public function restore(string $nonce): bool
    {
        return $this->revocations()->restore($nonce);
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
        return $this->revocations()->record($nonce);
    }

    /**
     * How long to hold a revocation for a nonce with no known expiry.
     *
     * The ceiling from `challenge.ttl`, counted from now. No live token can
     * outlast it — one minted this second expires at most a ceiling from now,
     * and one minted earlier expires sooner — so this always covers the pass
     * being withdrawn. Holding the record slightly longer than the token lives
     * costs one storage key; holding it for less would quietly un-revoke.
     *
     * @return int
     *   A unix timestamp.
     */
    public function defaultExpiry(): int
    {
        $ttl = $this->challengeConfig()['ttl'] ?? null;
        $ttl = is_numeric($ttl) ? (int) $ttl : 0;

        return time() + ($ttl > 0 ? $ttl : 3600);
    }

    /**
     * The token manager this configuration describes.
     *
     * @return TokenManager
     *   A manager holding the configured secret.
     *
     * @throws ConfigurationException
     *   When the configuration declares no `challenge.secret` — which is not a
     *   degraded mode here: without the secret nothing can tell a pass from a
     *   string, so there is no useful thing left to do.
     */
    public function tokens(): TokenManager
    {
        $challenge = $this->challengeConfig();
        $provider = is_string($challenge['provider'] ?? null) ? $challenge['provider'] : 'math';
        $audience = trim(is_string($challenge['audience'] ?? null) ? $challenge['audience'] : '');

        return new TokenManager(
            is_string($challenge['secret'] ?? null) ? $challenge['secret'] : '',
            $audience === '' ? $provider : $audience,
            $provider
        );
    }

    /**
     * The revocation list backed by the configured store.
     *
     * @return PassRevocationList
     *   The list.
     */
    public function revocations(): PassRevocationList
    {
        return new PassRevocationList($this->storage());
    }

    /**
     * The `challenge:` section, loaded once.
     *
     * @return array<string, mixed>
     *   The configured challenge block.
     */
    private function challengeConfig(): array
    {
        if ($this->challenge === null) {
            $config = Config::load($this->configs);
            $declared = $config['challenge'] ?? null;

            // Rebuilt with string keys rather than handed straight across:
            // `challenge:` comes out of YAML, so a hand-edited file can produce
            // a list, and every reader below indexes it by name.
            $challenge = [];

            foreach (is_array($declared) ? $declared : [] as $key => $value) {
                $challenge[(string) $key] = $value;
            }

            $this->challenge = $challenge;
        }

        return $this->challenge;
    }
}
