<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * When a rule is awake.
 *
 * "Block this country outside business hours." "Turn this rate limit on for the campaign."
 * "Allow the deploy pipeline during the maintenance window." All three are the same
 * question asked of a rule -- *is it my turn?* -- and all three were previously answered by
 * commenting the rule out and remembering to put it back (#205).
 *
 * ```yaml
 * metadata:
 *   name: after-hours-geo-block
 *   active:
 *     timezone: America/Los_Angeles
 *     days: [mon, tue, wed, thu, fri]
 *     hours: "18:00-06:00"
 * ```
 *
 * ## Everything is wall clock, in the rule's own timezone
 *
 * `isActiveAt()` converts the instant it is given into the configured zone **once**, and
 * every comparison after that is against the local calendar and the local clock face. So
 * `hours: "18:00-06:00"` means what a person standing in that timezone would say it means,
 * on both sides of a daylight-saving transition, with no arithmetic that has to know one
 * happened.
 *
 * That falls out rather than being handled:
 *
 * - **Spring forward.** `01:00-03:00` on the day 02:00 does not exist is simply a shorter
 *   window. No local time inside the gap occurs, so none is compared.
 * - **Fall back.** `01:00-03:00` on the day 01:30 happens twice is active both times,
 *   because both are 01:30 locally. A window written across that hour is longer that day.
 *
 * Neither is a bug to be fixed; a rule about business hours *should* follow the clock on the
 * wall of the business.
 *
 * ## The timezone is required, and that is the point
 *
 * Defaulting to the server's zone would make a rule mean one thing on a developer's laptop,
 * another in a container that ships with UTC, and a third the day somebody moves the region.
 * A rule that changes behaviour when the infrastructure moves is worse than no rule, so
 * `timezone` is mandatory the moment anything else in `active:` is set.
 *
 * ## A schedule that cannot be understood stops the rule
 *
 * Every parse failure here throws, which `LazyObjectRegistry` catches and turns into a
 * failed rule: not running, and named as not running by `Firewall::getFailedRules()`,
 * `firewall-doctor` and `firewall-check` (#247, #260). The two alternatives are both
 * inventions -- treating a broken schedule as *always on* silently over-blocks, treating it
 * as *always off* silently stops protecting -- and inventing an answer to a misconfiguration
 * is how `file:` came to be written under `FileStorage` in five places (#189). `--lint`
 * catches the same mistakes before a deploy, where they are cheap.
 */
final class Schedule
{
    /**
     * Day names accepted in `days`, mapped to ISO-8601 day numbers.
     */
    private const DAYS = [
        'mon' => 1, 'monday' => 1,
        'tue' => 2, 'tuesday' => 2,
        'wed' => 3, 'wednesday' => 3,
        'thu' => 4, 'thursday' => 4,
        'fri' => 5, 'friday' => 5,
        'sat' => 6, 'saturday' => 6,
        'sun' => 7, 'sunday' => 7,
    ];

    /**
     * Keys `active:` understands.
     */
    private const KEYS = ['timezone', 'days', 'hours', 'from', 'until'];

    /**
     * @param \DateTimeZone $dateTimeZone
     *   The zone every comparison is made in.
     * @param array<int, int> $days
     *   ISO-8601 day numbers, ascending. Empty means every day.
     * @param array<int, array{int, int}> $hours
     *   Minute-of-day ranges, half open. A range whose end is below its start
     *   wraps over midnight. Empty means all day.
     * @param string|null $from
     *   Local `Y-m-d H:i` the window opens on, inclusive.
     * @param string|null $until
     *   Local `Y-m-d H:i` the window closes on, exclusive.
     * @param string $description
     *   The schedule in the words it was configured with.
     */
    private function __construct(
        private readonly \DateTimeZone $dateTimeZone,
        private readonly array $days,
        private readonly array $hours,
        private readonly ?string $from,
        private readonly ?string $until,
        private readonly string $description
    ) {
    }

    /**
     * Read a rule's `metadata.active`.
     *
     * @param mixed $active
     *   The value as configured, of whatever shape it turned out to be.
     *
     * @return self|null
     *   NULL when nothing is configured, which is every rule that has always
     *   run and should keep running.
     *
     * @throws \InvalidArgumentException
     *   When something is configured and cannot be read as a schedule.
     */
    public static function fromMetadata(mixed $active): ?self
    {
        if ($active === null) {
            return null;
        }

        if (!is_array($active)) {
            throw new \InvalidArgumentException(sprintf(
                '`active` must be a map of %s; got %s.',
                implode(', ', self::KEYS),
                get_debug_type($active)
            ));
        }

        if ($active === []) {
            return null;
        }

        $unknown = array_diff(array_keys($active), self::KEYS);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf(
                '`active` does not understand %s. It reads %s.',
                implode(', ', array_map(static fn(mixed $key): string => '`' . $key . '`', $unknown)),
                implode(', ', self::KEYS)
            ));
        }

        $dateTimeZone = self::readTimezone($active['timezone'] ?? null);
        $days = self::readDays($active['days'] ?? null);
        $hours = self::readHours($active['hours'] ?? null);
        $from = self::readBoundary($active['from'] ?? null, 'from');
        $until = self::readBoundary($active['until'] ?? null, 'until');

        if ($from !== null && $until !== null && $until <= $from) {
            throw new \InvalidArgumentException(sprintf(
                '`active.until` (%s) is not after `active.from` (%s), so the rule could never run.',
                $until,
                $from
            ));
        }

        return new self($dateTimeZone, $days, $hours, $from, $until, self::describeConfigured($active, $dateTimeZone));
    }

    /**
     * Whether the rule is awake at a given instant.
     *
     * @param \DateTimeImmutable $now
     *   The instant to ask about, in any zone.
     *
     * @return bool
     *   TRUE when every configured constraint holds.
     */
    public function isActiveAt(\DateTimeImmutable $now): bool
    {
        $local = $now->setTimezone($this->dateTimeZone);
        $stamp = $local->format('Y-m-d H:i');

        if ($this->from !== null && $stamp < $this->from) {
            return false;
        }

        if ($this->until !== null && $stamp >= $this->until) {
            return false;
        }

        if ($this->days !== [] && !in_array((int) $local->format('N'), $this->days, true)) {
            return false;
        }

        if ($this->hours === []) {
            return true;
        }

        $minute = ((int) $local->format('G') * 60) + (int) $local->format('i');

        foreach ($this->hours as [$start, $end]) {
            // A range that ends below where it starts is one that crosses
            // midnight: 18:00-06:00 is the evening *and* the small hours, not
            // the twelve hours between them.
            $inside = $start < $end
                ? $minute >= $start && $minute < $end
                : $minute >= $start || $minute < $end;

            if ($inside) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the schedule constrains anything at all.
     *
     * An `active:` holding only a timezone parses cleanly and leaves the rule running at
     * all times, which is never what somebody who wrote a schedule meant. Nothing about it
     * is malformed, so it is not a parse failure -- it is something `--lint` warns about.
     *
     * @return bool
     *   TRUE when no day, hour or date bounds the rule.
     */
    public function isAlwaysActive(): bool
    {
        return $this->days === []
            && $this->hours === []
            && $this->from === null
            && $this->until === null;
    }

    /**
     * The schedule, in the words it was configured with.
     *
     * @return string
     *   A single line, for a diagnostic that has to say why a rule matched
     *   nothing all afternoon.
     */
    public function describe(): string
    {
        return $this->description;
    }

    /**
     * The zone the rule is scheduled in.
     *
     * @return \DateTimeZone
     *   The configured timezone.
     */
    public function getTimezone(): \DateTimeZone
    {
        return $this->dateTimeZone;
    }

    /**
     * Read `active.timezone`, which is never optional and never inferred.
     *
     * @param mixed $timezone
     *   The configured value.
     *
     * @return \DateTimeZone
     *   The zone to compare in.
     *
     * @throws \InvalidArgumentException
     *   When absent or not a zone this system knows.
     */
    private static function readTimezone(mixed $timezone): \DateTimeZone
    {
        if (!is_string($timezone) || trim($timezone) === '') {
            throw new \InvalidArgumentException(
                '`active.timezone` is required, as an identifier like `America/Los_Angeles` or `UTC`. '
                . "The server's zone is deliberately not a default: a rule that changes behaviour "
                . 'when a container moves is worse than no rule.'
            );
        }

        try {
            return new \DateTimeZone(trim($timezone));
        } catch (\Exception) {
            throw new \InvalidArgumentException(sprintf(
                '`active.timezone` is not a timezone this system knows: %s.',
                trim($timezone)
            ));
        }
    }

    /**
     * Read `active.days`.
     *
     * @param mixed $days
     *   The configured value: one day, a list of them, or nothing.
     *
     * @return array<int, int>
     *   ISO-8601 day numbers, ascending and deduplicated. Empty means every day.
     *
     * @throws \InvalidArgumentException
     *   When a name is not a day, or the list is empty.
     */
    private static function readDays(mixed $days): array
    {
        if ($days === null) {
            return [];
        }

        $names = is_array($days) ? $days : [$days];

        if ($names === []) {
            throw new \InvalidArgumentException('`active.days` is an empty list, so the rule could never run.');
        }

        $numbers = [];

        foreach ($names as $name) {
            $key = is_string($name) ? strtolower(trim($name)) : '';

            if (!isset(self::DAYS[$key])) {
                throw new \InvalidArgumentException(sprintf(
                    '`active.days` does not understand %s. Write days as %s.',
                    is_string($name) ? '`' . $name . '`' : get_debug_type($name),
                    'mon, tue, wed, thu, fri, sat, sun'
                ));
            }

            $numbers[] = self::DAYS[$key];
        }

        $numbers = array_values(array_unique($numbers));
        sort($numbers);

        return $numbers;
    }

    /**
     * Read `active.hours`.
     *
     * @param mixed $hours
     *   One range, a list of them, or nothing.
     *
     * @return array<int, array{int, int}>
     *   Minute-of-day pairs, half open. Empty means all day.
     *
     * @throws \InvalidArgumentException
     *   When a range is not `HH:MM-HH:MM`, names an impossible time, or is
     *   zero length.
     */
    private static function readHours(mixed $hours): array
    {
        if ($hours === null) {
            return [];
        }

        $ranges = is_array($hours) ? $hours : [$hours];

        if ($ranges === []) {
            throw new \InvalidArgumentException('`active.hours` is an empty list, so the rule could never run.');
        }

        $parsed = [];

        foreach ($ranges as $range) {
            $parsed[] = self::readRange($range);
        }

        return $parsed;
    }

    /**
     * Read one `HH:MM-HH:MM` range.
     *
     * @param mixed $range
     *   The configured range.
     *
     * @return array{int, int}
     *   Start and end as minutes of the day.
     *
     * @throws \InvalidArgumentException
     *   When it cannot be read, or reads as a window of no length.
     */
    private static function readRange(mixed $range): array
    {
        $written = is_string($range) ? trim($range) : '';

        if (!preg_match('/^(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$/', $written, $matches)) {
            throw new \InvalidArgumentException(sprintf(
                '`active.hours` must be written `HH:MM-HH:MM`, like `18:00-06:00`; got %s.',
                is_string($range) ? '`' . $range . '`' : get_debug_type($range)
            ));
        }

        $start = self::minuteOfDay((int) $matches[1], (int) $matches[2], $written);
        $end = self::minuteOfDay((int) $matches[3], (int) $matches[4], $written);

        if ($start === $end) {
            throw new \InvalidArgumentException(sprintf(
                '`active.hours` range `%s` starts and ends at the same time, which is no window at all. '
                . 'Leave `hours` out for all day.',
                $written
            ));
        }

        return [$start, $end];
    }

    /**
     * Turn an hour and minute into minutes past midnight.
     *
     * @param int $hour
     *   The hour, which has to be one a clock has.
     * @param int $minute
     *   The minute, likewise.
     * @param string $written
     *   The range as configured, for the message.
     *
     * @return int
     *   Minutes past local midnight.
     *
     * @throws \InvalidArgumentException
     *   When the time does not exist.
     */
    private static function minuteOfDay(int $hour, int $minute, string $written): int
    {
        if ($hour > 23 || $minute > 59) {
            throw new \InvalidArgumentException(sprintf(
                '`active.hours` range `%s` names a time that does not exist.',
                $written
            ));
        }

        return ($hour * 60) + $minute;
    }

    /**
     * Read `active.from` or `active.until`.
     *
     * A date on its own covers the whole of that day, which is how a person
     * reads "until the second of December". Both are normalised to the same
     * local `Y-m-d H:i` so the comparison is a string compare against a
     * fixed-width stamp -- no instant arithmetic, and therefore nothing for a
     * daylight-saving transition to be wrong about.
     *
     * @param mixed $value
     *   The configured boundary.
     * @param string $key
     *   Which one, for the message.
     *
     * @return string|null
     *   Local `Y-m-d H:i`, or NULL when unset.
     *
     * @throws \InvalidArgumentException
     *   When it is not a date this can read.
     */
    private static function readBoundary(mixed $value, string $key): ?string
    {
        if ($value === null) {
            return null;
        }

        $written = is_string($value) ? trim($value) : '';

        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $written, $date)) {
            $day = self::checkDate($date, $written, $key);

            // `until: 2026-12-02` closes at the end of that day rather than at
            // its first minute, because the alternative reading makes a
            // one-day campaign run for no time at all.
            return $key === 'until'
                ? $day->modify('+1 day')->format('Y-m-d H:i')
                : $day->format('Y-m-d H:i');
        }

        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})$/', $written, $stamp)) {
            $day = self::checkDate($stamp, $written, $key);

            if ((int) $stamp[4] > 23 || (int) $stamp[5] > 59) {
                throw new \InvalidArgumentException(sprintf(
                    '`active.%s` names a time that does not exist: %s.',
                    $key,
                    $written
                ));
            }

            return $day->format('Y-m-d') . ' ' . $stamp[4] . ':' . $stamp[5];
        }

        throw new \InvalidArgumentException(sprintf(
            "`active.%s` must be written `YYYY-MM-DD` or `YYYY-MM-DD HH:MM`, in the rule's own timezone; got %s.",
            $key,
            is_string($value) ? '`' . $value . '`' : get_debug_type($value)
        ));
    }

    /**
     * Check that a matched date is a day the calendar has.
     *
     * @param array<int, string> $parts
     *   The year, month and day from the pattern.
     * @param string $written
     *   The boundary as configured, for the message.
     * @param string $key
     *   Which boundary, for the message.
     *
     * @return \DateTimeImmutable
     *   Midnight on that day, in UTC, used only for its calendar arithmetic.
     *
     * @throws \InvalidArgumentException
     *   When the date does not exist.
     */
    private static function checkDate(array $parts, string $written, string $key): \DateTimeImmutable
    {
        if (!checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])) {
            throw new \InvalidArgumentException(sprintf(
                '`active.%s` is not a date on the calendar: %s.',
                $key,
                $written
            ));
        }

        return new \DateTimeImmutable(
            sprintf('%s-%s-%s 00:00', $parts[1], $parts[2], $parts[3]),
            new \DateTimeZone('UTC')
        );
    }

    /**
     * Say the schedule back in the terms it was written in.
     *
     * @param array<string, mixed> $active
     *   The configured block, already known to be readable.
     * @param \DateTimeZone $dateTimeZone
     *   The parsed zone, so the line names the same one the comparison uses.
     *
     * @return string
     *   One line, for a diagnostic.
     */
    private static function describeConfigured(array $active, \DateTimeZone $dateTimeZone): string
    {
        $parts = [];

        if (isset($active['days'])) {
            $days = is_array($active['days']) ? $active['days'] : [$active['days']];
            $parts[] = implode(', ', array_map(static fn(mixed $day): string => strtolower(trim((string) $day)), $days));
        }

        if (isset($active['hours'])) {
            $hours = is_array($active['hours']) ? $active['hours'] : [$active['hours']];
            $parts[] = implode(', ', array_map(static fn(mixed $hour): string => trim((string) $hour), $hours));
        }

        if (isset($active['from'])) {
            $parts[] = 'from ' . trim((string) $active['from']);
        }

        if (isset($active['until'])) {
            $parts[] = 'until ' . trim((string) $active['until']);
        }

        return ($parts === [] ? 'always' : implode(' ', $parts)) . ' (' . $dateTimeZone->getName() . ')';
    }
}
