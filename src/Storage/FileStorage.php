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
class FileStorage extends InMemoryStorage implements ConcurrencyGaugeInterface
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

    /**
     * {@inheritdoc}
     *
     * A separate file from the block list, and a stricter lock than the rest of
     * this class uses.
     *
     * `withExclusiveLock()` falls back to running the action *unlocked* when it
     * cannot take the lock, which is right for a block-list write -- recording
     * a block without the lock beats not recording it. It is wrong here. An
     * increment that is not atomic under-counts, the cap admits more tarpits
     * than it allows, and that is the self-DoS the cap exists to prevent. So
     * this refuses instead, and reports it as the zero the interface reserves
     * for "could not be counted".
     */
    public function enter(string $key, int $ttl): int
    {
        return $this->withGaugeLock($key, function ($handle) use ($ttl): int {
            $count = $this->readGauge($handle, $ttl) + 1;
            $this->writeGauge($handle, $count);

            return $count;
        }, 0);
    }

    /**
     * {@inheritdoc}
     */
    public function leave(string $key): void
    {
        $this->withGaugeLock($key, function ($handle): int {
            // Never below zero. A caller releasing in a `finally` cannot always
            // know whether its claim succeeded, and the alternative to
            // tolerating that is a leak on every error path.
            $count = max(0, $this->readGauge($handle, 0) - 1);
            $this->writeGauge($handle, $count);

            return $count;
        }, 0);
    }

    /**
     * {@inheritdoc}
     */
    public function inFlight(string $key): int
    {
        return $this->withGaugeLock($key, fn($handle): int => $this->readGauge($handle, 0), 0);
    }

    /**
     * Run an action holding an exclusive lock on the gauge file, or give up.
     *
     * @param string $key
     *   What is being counted.
     * @param callable(resource): int $action
     *   The action, given the open handle.
     * @param int $onFailure
     *   Returned when the lock could not be taken.
     *
     * @return int
     *   The action's result, or $onFailure.
     */
    private function withGaugeLock(string $key, callable $action, int $onFailure): int
    {
        $path = $this->gaugeFilePath($key);
        $handle = @fopen($path, 'c+');

        if ($handle === false) {
            return $onFailure;
        }

        @chmod($path, 0600);

        if (!$this->lockGauge($handle)) {
            @fclose($handle);

            return $onFailure;
        }

        try {
            return $action($handle);
        } finally {
            @flock($handle, LOCK_UN);
            @fclose($handle);
        }
    }

    /**
     * Take an exclusive lock on an open gauge file.
     *
     * Blocking, not `LOCK_NB`. The hold is a read, a small write and a close;
     * waiting microseconds for it is correct, and giving up would report a
     * failure that is really contention.
     *
     * A seam, for the same reason `LocalFetcher::readFile()` is one: `flock()`
     * failing on a handle that opened is real -- a filesystem without locking,
     * an NFS mount without a lock daemon -- and is not something a test can
     * provoke against a working one. What happens next matters enough to be
     * exercised: the caller must refuse rather than proceed unlocked, because
     * an increment that is not atomic under-counts and the cap stops holding.
     *
     * @param resource $handle
     *   The open handle.
     *
     * @return bool
     *   TRUE when the lock was taken.
     */
    protected function lockGauge($handle): bool
    {
        return @flock($handle, LOCK_EX);
    }

    /**
     * Read the count from an open, locked gauge file.
     *
     * @param resource $handle
     *   The open handle.
     * @param int $ttl
     *   When positive, a count older than this reads as zero. The backstop for
     *   a worker killed between `enter()` and `leave()`: the leak makes the cap
     *   stricter until it clears, which is the safe direction.
     *
     * @return int
     *   The count.
     */
    private function readGauge($handle, int $ttl): int
    {
        rewind($handle);
        $contents = (string) stream_get_contents($handle);

        if (preg_match('/^(\d+):(\d+)$/', trim($contents), $match) !== 1) {
            return 0;
        }

        if ($ttl > 0 && time() - (int) $match[2] > $ttl) {
            return 0;
        }

        return (int) $match[1];
    }

    /**
     * Write the count to an open, locked gauge file.
     *
     * @param resource $handle
     *   The open handle.
     * @param int $count
     *   The count.
     */
    private function writeGauge($handle, int $count): void
    {
        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, $count . ':' . time());
        fflush($handle);
    }

    /**
     * Where a gauge's counter lives.
     *
     * Beside the block list rather than inside it: the block list is read and
     * rewritten wholesale, and a counter touched on every tarpit has no
     * business in a file whose write amplification is the size of the block
     * list.
     *
     * @param string $key
     *   What is being counted.
     *
     * @return string
     *   The file path.
     */
    private function gaugeFilePath(string $key): string
    {
        return $this->filePath . '.gauge.' . hash('sha256', $key) . '.txt';
    }
}
