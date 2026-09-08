<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Traits\FileTrait;

/**
 * File-based key-value store with in-memory caching.
 * Persists data to disk using PHP serialization.
 */
class FileStorage extends InMemoryStorage
{
    use FileTrait;

    /**
     * Path of the file to save/load.
     */
    protected string $filePath;

    /**
     * Path of the file to save/load the offenses from.
     */
    protected string $offensesFilePath;

    /**
     * Construct a FileStorage instance.
     *
     * @param array<string, mixed> $config
     *   Configuration array.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->filePath = $this->validateFilePath(
            strval($config['storage_file'] ?? $this->defaultStoragePath('storage_data.json'))
        );
        $this->loadStorageFile();
        $this->getLogger()->debug('FileStorage initialized', ['file' => $this->filePath]);

        $this->offensesFilePath = $this->validateFilePath(
            strval($config['offense_file'] ?? $this->defaultOffenseFile())
        );
        $this->adoptLegacyOffenseFile($config);
        $this->loadOffenseFile();
        $this->getLogger()->debug('FileStorage offenses initialized', ['file' => $this->offensesFilePath]);
    }

    /**
     * Where offenses go when the configuration does not say.
     *
     * Derived from the storage file, not from the directory holding it. The old default was
     * `{dir}/storage_data_offenses.json`, so two stores in one directory -- two sites, two
     * environments, or one site running two stores for different purposes -- shared a single
     * offense history and escalated each other's clients (#244).
     *
     * Offenses drive `blocking_escalation`, so an address that offended twice against one
     * store and once against another reached a three-offense stage on both.
     *
     * @return string
     *   Path to this store's offense sidecar.
     */
    protected function defaultOffenseFile(): string
    {
        return $this->filePath . '.offenses';
    }

    /**
     * Carry an old shared offense file over to this store's own, once.
     *
     * Only when the operator has not named a file, and only when this store has no history
     * of its own yet. Without it, upgrading resets every client to zero offenses and a
     * repeat offender gets a first-offender's ban until it earns its way back up -- a
     * security regression on upgrade that nothing announces.
     *
     * Copied rather than shared, so two stores that were contaminating each other start from
     * the same place and diverge correctly from here. The history they start with is the
     * history they already had; this does not make it worse.
     *
     * @param array<string, mixed> $config
     *   Storage configuration.
     */
    protected function adoptLegacyOffenseFile(array $config): void
    {
        if (isset($config['offense_file'])) {
            return;
        }

        $legacy = \dirname(\realpath($this->filePath) ?: $this->filePath) . '/storage_data_offenses.json';

        if ($legacy === $this->offensesFilePath || !is_file($legacy)) {
            return;
        }

        // A store with its own history has already been through this.
        if ((int) @filesize($this->offensesFilePath) > 0) {
            return;
        }

        if (!@copy($legacy, $this->offensesFilePath)) {
            $this->getLogger()->warning('Could not carry the previous offense history over', [
                'from' => $legacy,
                'to' => $this->offensesFilePath,
                'impact' => 'Escalation stages restart from zero for every client.',
            ]);

            return;
        }

        $this->getLogger()->info('Adopted the previous shared offense history', [
            'from' => $legacy,
            'to' => $this->offensesFilePath,
            'detail' => 'Offenses now live beside the storage file rather than being shared '
                . 'by every store in the directory. The old file is left in place; it can be '
                . 'removed once every store using it has started.',
        ]);
    }

    /**
     * Internal method used for loading the storage file.
     *
     * A file that cannot be decoded leaves the in-memory store alone. It used
     * to be replaced with `[]`, and an empty block list means "nobody is
     * blocked" -- so an unreadable file let every blocked client through
     * (#225). Keeping the last known state is the conservative reading, and
     * for a block list conservative means still blocking.
     */
    protected function loadStorageFile(): void
    {
        $entries = $this->readFromFile($this->filePath);

        if ($entries === null) {
            return;
        }

        /** @phpstan-ignore assign.propertyType */
        $this->store = $entries;
    }

    /**
     * Internal method used for saving to storage file.
     */
    protected function persistStorageFile(): void
    {
        $this->persistToFile($this->store, $this->filePath);
    }

    /**
     * Internal method used for loading the offense file.
     *
     * Same reasoning as loadStorageFile(): an undecodable file keeps the last
     * known offense counts rather than resetting every client to zero.
     */
    protected function loadOffenseFile(): void
    {
        $entries = $this->readFromFile($this->offensesFilePath);

        if ($entries === null) {
            return;
        }

        /** @phpstan-ignore assign.propertyType */
        $this->offenses = $entries;
    }

    /**
     * Internal method used for saving to the offense file.
     */
    protected function persistOffenseFile(): void
    {
        $this->persistToFile($this->offenses, $this->offensesFilePath);
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        return (bool) $this->withExclusiveLock($this->offensesFilePath, function () use ($key): bool {
            $this->loadOffenseFile();
            parent::recordOffense($key);
            $this->persistOffenseFile();
            return true;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        return (bool) $this->withExclusiveLock($this->filePath, function () use ($key, $value, $expire): bool {
            $this->loadStorageFile();
            $result = parent::set($key, $value, $expire);
            if ($result) {
                $this->getLogger()->debug('Value set in file storage', [
                    'key' => $key,
                    'expire' => $expire,
                    'file' => $this->filePath,
                ]);
                $this->persistStorageFile();
            }

            return $result;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->loadStorageFile();
        return parent::get($key, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        return (bool) $this->withExclusiveLock($this->filePath, function () use ($key): bool {
            $this->loadStorageFile();
            $result = parent::delete($key);
            if ($result) {
                $this->getLogger()->debug('Key deleted from file storage', [
                    'key' => $key,
                    'file' => $this->filePath,
                ]);
                $this->persistStorageFile();
            }

            return $result;
        });
    }

    /**
     * {@inheritdoc}
     *
     * One lock, one read, one write -- for the whole sweep rather than per key.
     *
     * The inherited implementation calls `delete()` once per expired key, and
     * this class overrides `delete()` with an exclusive lock plus a full file
     * load and a full rewrite. So a sweep cost that per expired entry: measured
     * at 2.1ms for 50 and 7.9ms for 200, against 0.0004ms when nothing had
     * expired (#250).
     *
     * That cost is not spread across requests. `Firewall::__construct()` calls
     * this on every request, and it is free until a batch of bans lapses
     * together -- then the whole bill lands on whichever request arrives next.
     * With the default 300-second ban that is the first real visitor after an
     * attack, paying for the attacker's expired blocks.
     *
     * Offenses are deliberately left alone. `deleteMatching()` drops them
     * alongside a block because an operator lifting a ban should not have it
     * escalated straight back; an expiry is the opposite case -- the ban ran
     * its course, and the offense history is exactly what
     * `blocking_escalation` needs to give a repeat offender a longer one next
     * time.
     */
    public function expire(): bool
    {
        return (bool) $this->withExclusiveLock($this->filePath, function (): bool {
            $this->loadStorageFile();

            $currentTime = time();
            $cleared = 0;

            foreach ($this->store as $key => $value) {
                if (!is_array($value)) {
                    continue;
                }

                if (($value['expire'] ?? 0) <= 0) {
                    continue;
                }

                if ($value['expire'] >= $currentTime) {
                    continue;
                }

                // Unset directly rather than calling $this->delete().
                //
                // delete() is overridden here to take the same exclusive lock
                // this closure already holds, and flock() locks attach to the
                // open file description -- so a nested acquisition blocks on a
                // lock this very process holds. A permanent self-deadlock, not
                // a slow path. `deleteMatching()` documents the same trap.
                unset($this->store[$key]);
                $cleared++;
            }

            if ($cleared > 0) {
                $this->persistStorageFile();

                $this->getLogger()->debug('Expired entries cleared from file storage', [
                    'file' => $this->filePath,
                    'entries_cleared' => $cleared,
                ]);
            }

            return true;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        return (bool) $this->withExclusiveLock($this->filePath, function (): bool {
            $previousCount = count($this->store);
            $result = parent::reset();
            if ($result) {
                $this->getLogger()->info('File storage reset', [
                    'file' => $this->filePath,
                    'entries_cleared' => $previousCount,
                ]);
                $this->persistStorageFile();
            }

            return $result;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        return (bool) $this->withExclusiveLock($this->filePath, function () use ($key, $amount): bool {
            $this->loadStorageFile();
            $return = parent::addToExpire($key, $amount);
            if ($return) {
                $this->persistStorageFile();
            }

            return $return;
        });
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        $this->loadOffenseFile();
        return parent::countOffenses($key, $start, $end);
    }

    /**
     * {@inheritdoc}
     */
    public function listOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX, int $limit = 50): array
    {
        $this->loadOffenseFile();
        return parent::listOffenses($key, $start, $end, $limit);
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $pattern): array
    {
        // Both files, because find() reports an offense count alongside each
        // block. Unlocked, matching get() and countOffenses(): a read that is
        // a snapshot is acceptable here, and taking an exclusive lock for it
        // would serialise every lookup against live traffic.
        $this->loadStorageFile();
        $this->loadOffenseFile();

        return parent::find($pattern);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteMatching(array $patterns): int
    {
        // Both files are written, so both locks are held. The nesting order —
        // storage first, offenses second — is the order set() already
        // establishes by taking the storage lock and then calling
        // recordOffense(). Acquiring them the other way round anywhere would
        // invite a deadlock between two concurrent processes; matching the
        // existing order is what avoids it.
        //
        // The two locks are distinct files, so this nesting is safe where a
        // second lock on the *same* file would not be: flock() is not
        // reentrant within a process.
        return (int) $this->withExclusiveLock($this->filePath, fn(): int
            => (int) $this->withExclusiveLock($this->offensesFilePath, function () use ($patterns): int {
                $this->loadStorageFile();
                $this->loadOffenseFile();

                // parent::deleteMatching() mutates $this->store and
                // $this->offenses directly rather than routing through
                // delete(), which would try to re-take the storage lock this
                // closure already holds.
                $deleted = parent::deleteMatching($patterns);

                if ($deleted > 0) {
                    $this->persistStorageFile();
                    // Offenses are pruned by parent::deleteMatching(); without
                    // persisting them they would survive the un-block and
                    // re-escalate the address on its next hit.
                    $this->persistOffenseFile();

                    $this->getLogger()->info('Records deleted by pattern from file storage', [
                        'deleted' => $deleted,
                        'file' => $this->filePath,
                    ]);
                }

                return $deleted;
            }));
    }
}
