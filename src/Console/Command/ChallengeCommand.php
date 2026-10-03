<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\ChallengePasses;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall challenge`: read a challenge pass, and withdraw one (#368).
 *
 * A pass token is stateless and HMAC-signed, so before this the only way to stop one being
 * accepted was to rotate `challenge.secret` -- re-challenging every visitor holding a pass to
 * withdraw a single one. Reads and writes the real store, so the backend is named.
 */
final class ChallengeCommand extends FirewallCommand
{
    private const EXIT_OK = 0;

    private const EXIT_UNANSWERABLE = 1;

    protected const EXIT_USAGE = 2;

    protected function configure(): void
    {
        $this
            ->setName('challenge')
            ->setDescription('Read a challenge pass, and withdraw one')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('inspect', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Decode a pass: address, provider, issued, expires, nonce')
            ->addOption('revoke', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Withdraw that pass, until its own expiry')
            ->addOption('revoke-nonce', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Withdraw by nonce, for when the log is what you have')
            ->addOption('restore', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Put a revoked pass back')
            ->addOption('status', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Whether a nonce is currently revoked, and why')
            ->addOption('expires', null, InputOption::VALUE_REQUIRED, 'With --revoke-nonce: when the token expires, as a unix timestamp')
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Recorded alongside a revocation')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(<<<'TEXT'
            Give exactly one of --inspect, --revoke, --revoke-nonce, --restore or --status.

            Exit codes:
              0  the question was answered, whatever the answer
              1  the token is not one this configuration signed, or has already expired
              2  the configuration could not be read, or the arguments made no sense
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');

        $json = $input->getOption('json') === true;
        $reason = is_string($input->getOption('reason')) ? $input->getOption('reason') : '';
        $expires = null;
        $given = $input->getOption('expires');

        if ($given !== null) {
            $given = (string) $given;

            if (!ctype_digit($given) || (int) $given <= 0) {
                $this->err("--expires must be a unix timestamp.\n");

                return self::EXIT_USAGE;
            }

            $expires = (int) $given;
        }

        $actions = [];

        foreach (['inspect', 'revoke', 'revoke-nonce', 'restore', 'status'] as $action) {
            /** @var array<int, string> $values */
            $values = $input->getOption($action);

            foreach ($values as $value) {
                $actions[] = [$action, $value];
            }
        }

        if ($files === []) {
            $this->err("No configuration files given. Try --help.\n");
            return self::EXIT_USAGE;
        }

        foreach ($files as $file) {
            if (!is_file($file)) {
                $this->err(sprintf("Configuration file not found: %s\n", $file));
                return self::EXIT_USAGE;
            }
        }

        // Exactly one, and said so rather than guessed at. `--revoke` and `--restore`
        // in the same invocation is somebody midway through changing their mind, and
        // picking an order for them is how the wrong one ends up being the one that ran.
        if (count($actions) !== 1) {
            $this->err($actions === []
                ? "Nothing to do. Give one of --inspect, --revoke, --revoke-nonce, --restore or --status.\n"
                : "Give exactly one action. Try --help.\n");
            return self::EXIT_USAGE;
        }

        Config::clearLoadErrors();
        Config::load($files);

        foreach (Config::getLoadErrors() as $error) {
            $this->err(sprintf("Could not load %s: %s\n", $error['file'], $error['message']));
            return self::EXIT_USAGE;
        }

        [$action, $value] = $actions[0];
        $challengePasses = new ChallengePasses($files);

        try {
            $backend = $challengePasses->backend();
        } catch (ConfigurationException $configurationException) {
            $this->err($configurationException->getMessage() . "\n");
            return self::EXIT_USAGE;
        }

        $finish = function (array $payload, array $lines, int $code) use ($json, $backend): never {
            $this->finish($json, $backend, $payload, $lines, $code);
        };

        /**
         * Decode a token, or stop.
         *
         * @return array<string, mixed>
         */
        $claimsOf = static function (string $token) use ($challengePasses, $finish): array {
            try {
                $claims = $challengePasses->inspect($token);
            } catch (ConfigurationException $configurationException) {
                $finish(
                    ['error' => $configurationException->getMessage()],
                    [$configurationException->getMessage()],
                    self::EXIT_USAGE
                );
            }

            if ($claims === null) {
                $finish(
                    ['error' => 'not_signed_by_this_configuration'],
                    ['This is not a pass token signed by this configuration.'],
                    self::EXIT_UNANSWERABLE
                );
            }

            return $claims;
        };

        /**
         * A timestamp a person can read.
         */
        $when = static fn(mixed $stamp): string => is_int($stamp)
            ? gmdate('Y-m-d H:i:s', $stamp) . ' UTC'
            : 'not recorded';

        /**
         * Describe a token's claims.
         *
         * @param array<string, mixed> $claims
         *
         * @return array<int, string>
         */
        $describe = static function (array $claims) use ($when, $challengePasses): array {
            $expiresAt = is_int($claims['exp'] ?? null) ? $claims['exp'] : 0;
            $issuedAt = is_int($claims['iat'] ?? null) ? $claims['iat'] : 0;
            $cutoff = $challengePasses->validFrom();

            $lines = [
                sprintf('  address:  %s', is_string($claims['ip'] ?? null) ? $claims['ip'] : '—'),
                sprintf('  provider: %s', is_string($claims['prv'] ?? null) ? $claims['prv'] : 'the default (this pass predates per-rule providers)'),
                sprintf('  audience: %s', is_string($claims['aud'] ?? null) ? $claims['aud'] : '—'),
                sprintf('  issued:   %s', $when($claims['iat'] ?? null)),
                sprintf('  expires:  %s%s', $when($claims['exp'] ?? null), $expiresAt > 0 && $expiresAt <= time() ? '  (already expired)' : ''),
                sprintf('  nonce:    %s', is_string($claims['nonce'] ?? null) ? $claims['nonce'] : '—'),
            ];

            if ($cutoff > 0 && $issuedAt < $cutoff) {
                $lines[] = sprintf('  ! Already refused: challenge.passes_valid_from is %s.', $when($cutoff));
            }

            return $lines;
        };

        if ($action === 'inspect') {
            $claims = $claimsOf($value);
            $nonce = is_string($claims['nonce'] ?? null) ? $claims['nonce'] : '';

            $finish(
                ['claims' => $claims, 'revoked' => $challengePasses->record($nonce)],
                array_merge(
                    ['Pass token:'],
                    $describe($claims),
                    $challengePasses->record($nonce) === null ? [] : ['  status:   REVOKED']
                ),
                self::EXIT_OK
            );
        }

        if ($action === 'status') {
            $record = $challengePasses->record($value);

            $finish(
                ['nonce' => $value, 'revoked' => $record],
                $record === null
                    ? [sprintf('Nonce %s is not revoked.', $value)]
                    : [
                        sprintf('Nonce %s is revoked.', $value),
                        sprintf('  revoked:  %s', $when($record['revoked_at'] ?? null)),
                        sprintf('  until:    %s', $when($record['expires_at'] ?? null)),
                        sprintf('  reason:   %s', ($record['reason'] ?? '') === '' ? '—' : (string) $record['reason']),
                    ],
                self::EXIT_OK
            );
        }

        if ($action === 'restore') {
            $restored = $challengePasses->restore($value);

            $finish(
                ['nonce' => $value, 'restored' => $restored],
                [$restored
                    ? sprintf('Nonce %s restored — the pass is accepted again until it expires.', $value)
                    : sprintf('Nonce %s was not revoked; nothing to restore.', $value)],
                self::EXIT_OK
            );
        }

        // Both revoke paths converge here: one knows the expiry because the token
        // carried it, the other takes the ceiling because no live pass outlasts it.
        if ($action === 'revoke') {
            $claims = $claimsOf($value);
            $nonce = is_string($claims['nonce'] ?? null) ? $claims['nonce'] : '';
            $expiresAt = $expires ?? (is_int($claims['exp'] ?? null) ? $claims['exp'] : 0);
            $described = $describe($claims);
        } else {
            $nonce = $value;
            $expiresAt = $expires ?? $challengePasses->defaultExpiry();
            $described = [];
        }

        if ($nonce === '') {
            $finish(
                ['error' => 'no_nonce'],
                ['That token carries no nonce, so there is nothing to revoke by.'],
                self::EXIT_UNANSWERABLE
            );
        }

        if ($challengePasses->revoke($nonce, $expiresAt, $reason)) {
            $finish(
                ['nonce' => $nonce, 'revoked' => true, 'until' => $expiresAt, 'reason' => $reason],
                array_merge(
                    [sprintf('Revoked %s until %s.', $nonce, $when($expiresAt))],
                    $described
                ),
                self::EXIT_OK
            );
        }

        $finish(
            ['nonce' => $nonce, 'revoked' => false, 'reason' => 'already_expired'],
            [sprintf('That pass expired at %s, so there is nothing left to revoke.', $when($expiresAt))],
            self::EXIT_UNANSWERABLE
        );
    }

    /**
     * Report a result and stop.
     *
     * @param bool $json
     *   Whether --json was asked for.
     * @param array{class: string, durable: bool, revocable: bool} $backend
     *   The store the passes are kept in.
     * @param array<mixed> $payload
     *   The machine-readable result.
     * @param array<mixed> $lines
     *   What to print when --json was not asked for: to stdout on success, stderr otherwise.
     * @param int $code
     *   The exit code.
     */
    private function finish(bool $json, array $backend, array $payload, array $lines, int $code): never
    {
        if ($json) {
            $this->out(json_encode($payload + ['backend' => $backend], JSON_PRETTY_PRINT) . "\n");

            throw $this->stop($code);
        }

        $write = $code === self::EXIT_OK ? $this->out(...) : $this->err(...);

        foreach ($lines as $line) {
            $write((is_string($line) ? $line : '') . "\n");
        }

        $this->out(sprintf("\n  backend: %s\n", $backend['class']));

        if (!$backend['durable']) {
            $this->out("  ! This store does not outlive the process, so a revocation written here is forgotten.\n");
        }

        if (!$backend['revocable']) {
            $this->out("  ! challenge.revocable is off, so the firewall does not consult this list.\n");
        }

        throw $this->stop($code);
    }
}
