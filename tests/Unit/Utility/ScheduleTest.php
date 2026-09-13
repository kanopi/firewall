<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Utility\Schedule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * When a rule is awake (#205).
 *
 * Every test here hands `isActiveAt()` an instant rather than asking about now, so a
 * schedule is a pure function of the two and the suite says the same thing on a Tuesday
 * afternoon as it does at 3am on the last Sunday in October.
 *
 * The daylight-saving cases are the ones worth reading. They are not testing PHP's timezone
 * database; they are pinning the *decision* that a window is wall-clock time in the rule's
 * own zone, because the other decision -- durations measured in elapsed hours -- is a
 * defensible design that would answer these differently, and nothing in the code would look
 * wrong afterwards.
 */
final class ScheduleTest extends TestCase
{
    /**
     * An instant, spelled in a way the reader can check against the assertion.
     */
    private function at(string $local, string $timezone = 'UTC'): \DateTimeImmutable
    {
        return new \DateTimeImmutable($local, new \DateTimeZone($timezone));
    }

    /**
     * A schedule, from the shape an operator writes.
     *
     * @param array<string, mixed> $active
     *   The `metadata.active` block.
     */
    private function schedule(array $active): Schedule
    {
        $schedule = Schedule::fromMetadata($active);

        $this->assertInstanceOf(Schedule::class, $schedule);

        return $schedule;
    }

    /**
     * No schedule is the answer for every rule that has ever run.
     */
    public function testNothingConfiguredIsNoSchedule(): void
    {
        $this->assertNull(Schedule::fromMetadata(null));
    }

    /**
     * `active: {}` constrains nothing, which is not a schedule either.
     *
     * The linter warns about it, because writing one and getting a rule that runs at all
     * times is a surprise. It is not an error: nothing about it is ambiguous.
     */
    public function testAnEmptyBlockIsNoSchedule(): void
    {
        $this->assertNull(Schedule::fromMetadata([]));
    }

    /**
     * Hours are read in the rule's zone, not the server's.
     *
     * The instant here is one moment. It is inside the window as Los Angeles tells the
     * time and outside it as UTC does, so a implementation that skipped the conversion
     * would return the opposite answer for both assertions.
     */
    public function testHoursAreReadInTheConfiguredZone(): void
    {
        $pacific = $this->schedule(['timezone' => 'America/Los_Angeles', 'hours' => '18:00-23:00']);
        $utc = $this->schedule(['timezone' => 'UTC', 'hours' => '18:00-23:00']);

        // 2026-09-15 02:00Z is 2026-09-14 19:00 in Los Angeles.
        $instant = $this->at('2026-09-15 02:00');

        $this->assertTrue($pacific->isActiveAt($instant));
        $this->assertFalse($utc->isActiveAt($instant));
    }

    /**
     * The start of a window is inside it and the end is not.
     *
     * Half open, like every other range in the library. `09:00-17:00` describes a working
     * day, and 17:00 is when it stopped.
     */
    public function testAWindowIncludesItsStartAndExcludesItsEnd(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'hours' => '09:00-17:00']);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 09:00')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 16:59')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 17:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 08:59')));
    }

    /**
     * A window whose end is before its start crosses midnight.
     *
     * `18:00-06:00` is the evening and the small hours. Reading it as "the twelve hours
     * between them" is the plausible bug, and it is exactly inverted, so the 12:00
     * assertion is the one that catches it.
     */
    public function testAWindowCrossingMidnightIsTheEveningAndTheSmallHours(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'hours' => '18:00-06:00']);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 18:00')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 23:59')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-15 05:59')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-15 06:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 12:00')));
    }

    /**
     * Several windows in a day.
     */
    public function testHoursMayBeAListOfWindows(): void
    {
        $schedule = $this->schedule([
            'timezone' => 'UTC',
            'hours' => ['09:00-12:00', '13:00-17:00'],
        ]);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 11:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 12:30')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 13:00')));
    }

    /**
     * Days are read at the instant being asked about, not at the window's start.
     *
     * This is the documented consequence of `days: [mon..fri] hours: 18:00-06:00`: Friday
     * at 22:00 is awake, and Saturday at 02:00 -- the same night -- is not, because it is
     * Saturday. Somebody who wants that night adds `sat`.
     *
     * Pinned because the other reading (a window belongs to the day it opened on) is
     * defensible, would pass every other test in this file, and would make this one fail.
     */
    public function testDaysAreReadAtTheMomentAsked(): void
    {
        $schedule = $this->schedule([
            'timezone' => 'UTC',
            'days' => ['mon', 'tue', 'wed', 'thu', 'fri'],
            'hours' => '18:00-06:00',
        ]);

        // 2026-09-18 is a Friday; 2026-09-19 is a Saturday.
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-18 22:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-19 02:00')));

        $withSaturday = $this->schedule([
            'timezone' => 'UTC',
            'days' => ['mon', 'tue', 'wed', 'thu', 'fri', 'sat'],
            'hours' => '18:00-06:00',
        ]);

        $this->assertTrue($withSaturday->isActiveAt($this->at('2026-09-19 02:00')));
    }

    /**
     * Day names are read the way people write them.
     */
    public function testDayNamesAreForgiving(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'days' => [' Monday ', 'MON', 'wed']]);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 12:00')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-16 12:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-15 12:00')));
    }

    /**
     * One day, written as one day.
     */
    public function testASingleDayNeedNotBeAList(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'days' => 'sun']);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-20 12:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-21 12:00')));
    }

    /**
     * A window that only exists for part of the year.
     *
     * `until` as a bare date covers the whole of that day, because "until the second of
     * December" does. The 2026-12-02 23:59 assertion is what says so; reading the date as
     * midnight would make a single-day campaign last no time at all.
     */
    public function testFromAndUntilBoundTheSchedule(): void
    {
        $schedule = $this->schedule([
            'timezone' => 'UTC',
            'from' => '2026-11-27',
            'until' => '2026-12-02',
        ]);

        $this->assertFalse($schedule->isActiveAt($this->at('2026-11-26 23:59')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-11-27 00:00')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-12-02 23:59')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-12-03 00:00')));
    }

    /**
     * A boundary with a time on it means that minute, exactly.
     */
    public function testABoundaryMayCarryATime(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'until' => '2026-12-02 09:00']);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-12-02 08:59')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-12-02 09:00')));
    }

    /**
     * `T` between the date and the time, as anybody who has typed an ISO stamp will.
     */
    public function testABoundaryAcceptsAnIsoSeparator(): void
    {
        $schedule = $this->schedule(['timezone' => 'UTC', 'from' => '2026-12-02T09:00']);

        $this->assertFalse($schedule->isActiveAt($this->at('2026-12-02 08:59')));
        $this->assertTrue($schedule->isActiveAt($this->at('2026-12-02 09:00')));
    }

    /**
     * Boundaries are local to the rule, like everything else.
     */
    public function testBoundariesAreReadInTheConfiguredZone(): void
    {
        $schedule = $this->schedule(['timezone' => 'America/Los_Angeles', 'until' => '2026-12-02']);

        // 2026-12-03 07:00Z is still 2026-12-02 23:00 in Los Angeles.
        $this->assertTrue($schedule->isActiveAt($this->at('2026-12-03 07:00')));
        $this->assertFalse($schedule->isActiveAt($this->at('2026-12-03 08:01')));
    }

    /**
     * Constraints are ANDed: every one has to hold.
     */
    public function testEveryConstraintHasToHold(): void
    {
        $schedule = $this->schedule([
            'timezone' => 'UTC',
            'days' => ['mon'],
            'hours' => '09:00-17:00',
            'from' => '2026-09-14',
            'until' => '2026-09-14',
        ]);

        $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 12:00')));
        // Right day of the week, right hour, outside the date range.
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-21 12:00')));
        // Inside the date range, wrong hour.
        $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 18:00')));
    }

    /**
     * Spring forward: the window is shorter that day, and nothing special happens.
     *
     * 2026-03-08 is when Los Angeles skips 02:00. A window of `01:00-03:00` has no 02:00
     * to be active at, because no such local time occurs -- the instant that would have
     * been 02:30 is 03:30, which is past the end.
     */
    public function testSpringForwardShortensAWindowRatherThanShiftingIt(): void
    {
        $schedule = $this->schedule(['timezone' => 'America/Los_Angeles', 'hours' => '01:00-03:00']);

        // 09:30Z = 01:30 PST, still before the jump.
        $this->assertTrue($schedule->isActiveAt($this->at('2026-03-08 09:30')));
        // 10:30Z = 03:30 PDT. Locally it is past 03:00, so the window has closed --
        // one hour of elapsed time after it opened, not two.
        $this->assertFalse($schedule->isActiveAt($this->at('2026-03-08 10:30')));
    }

    /**
     * Fall back: the window covers both passes of the repeated hour.
     *
     * 2026-11-01 is when Los Angeles repeats 01:00. Both instants below are 01:30 on the
     * wall, an hour apart, and a rule about local time is active for both.
     */
    public function testFallBackCoversARepeatedHourTwice(): void
    {
        $schedule = $this->schedule(['timezone' => 'America/Los_Angeles', 'hours' => '01:00-03:00']);

        // 08:30Z = 01:30 PDT, the first pass.
        $this->assertTrue($schedule->isActiveAt($this->at('2026-11-01 08:30')));
        // 09:30Z = 01:30 PST, the second.
        $this->assertTrue($schedule->isActiveAt($this->at('2026-11-01 09:30')));
    }

    /**
     * The description is the schedule in the operator's own words.
     *
     * It is what `firewall-doctor` prints next to a sleeping rule, so it has to be
     * recognisable as the thing they wrote, and it names the timezone even when they
     * wrote only a timezone.
     */
    public function testTheDescriptionReadsBackWhatWasConfigured(): void
    {
        $schedule = $this->schedule([
            'timezone' => 'America/Los_Angeles',
            'days' => ['mon', 'fri'],
            'hours' => '18:00-06:00',
            'from' => '2026-11-27',
            'until' => '2026-12-02',
        ]);

        $this->assertSame(
            'mon, fri 18:00-06:00 from 2026-11-27 until 2026-12-02 (America/Los_Angeles)',
            $schedule->describe()
        );

        $this->assertSame(
            'always (UTC)',
            $this->schedule(['timezone' => 'UTC'])->describe()
        );

        $this->assertSame(
            '09:00-12:00, 13:00-17:00 (UTC)',
            $this->schedule(['timezone' => 'UTC', 'hours' => ['09:00-12:00', '13:00-17:00']])->describe()
        );
    }

    /**
     * A schedule holding only a timezone parses, and constrains nothing.
     *
     * It is not a parse failure -- nothing about it is malformed -- so it has to be
     * askable, which is how `--lint` warns about the rule that wrote a schedule and got
     * one that never keeps it out.
     */
    public function testAScheduleWithNoWindowSaysSo(): void
    {
        $this->assertTrue($this->schedule(['timezone' => 'UTC'])->isAlwaysActive());
        $this->assertTrue($this->schedule(['timezone' => 'UTC'])->isActiveAt($this->at('2026-09-14 12:00')));

        $this->assertFalse($this->schedule(['timezone' => 'UTC', 'days' => ['mon']])->isAlwaysActive());
        $this->assertFalse($this->schedule(['timezone' => 'UTC', 'hours' => '09:00-17:00'])->isAlwaysActive());
        $this->assertFalse($this->schedule(['timezone' => 'UTC', 'from' => '2026-01-01'])->isAlwaysActive());
        $this->assertFalse($this->schedule(['timezone' => 'UTC', 'until' => '2026-01-01'])->isAlwaysActive());
    }

    /**
     * An unnamed timezone is UTC, and is never the host's.
     *
     * The two halves are separate claims and the second is the one worth a test: the
     * server's zone is set to Los Angeles here, and the window is still read in UTC. A
     * rule that took its meaning from the host would mean one thing on a laptop, another
     * in a container that ships with UTC, and a third the day somebody moves the region,
     * with nothing in the configuration changing.
     */
    public function testAnUnnamedTimezoneIsUtcAndNotTheServers(): void
    {
        $was = date_default_timezone_get();
        date_default_timezone_set('America/Los_Angeles');

        try {
            $schedule = $this->schedule(['hours' => '09:00-17:00']);

            $this->assertSame('UTC', $schedule->getTimezone()->getName());

            // 2026-09-14 16:00Z is 09:00 in Los Angeles. Read as UTC -- which is what
            // happens -- it is inside the window; read in the server's zone it would be
            // at the very edge of it, and the assertion below would be the one to move.
            $this->assertTrue($schedule->isActiveAt($this->at('2026-09-14 16:00')));
            // 2026-09-14 08:00Z is 01:00 in Los Angeles: outside either way, and the
            // control for the assertion above.
            $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 08:00')));
            // 2026-09-14 23:00Z is 16:00 in Los Angeles -- inside a window read in the
            // server's zone, outside one read in UTC. This is the assertion that fails
            // if the default ever becomes the host's zone.
            $this->assertFalse($schedule->isActiveAt($this->at('2026-09-14 23:00')));
        } finally {
            date_default_timezone_set($was);
        }
    }

    /**
     * An empty timezone is the same as an absent one.
     *
     * `timezone: "%env(TZ)%"` resolving to nothing is the realistic way to get here, and
     * it should land on the documented default rather than on a parse failure that stops
     * the rule.
     */
    public function testAnEmptyTimezoneIsTheDefault(): void
    {
        $this->assertSame('UTC', $this->schedule(['timezone' => '   ', 'days' => ['mon']])->getTimezone()->getName());
    }

    /**
     * A schedule with no timezone still says which zone it was read in.
     *
     * `firewall-doctor` prints this next to a sleeping rule, so the operator who never
     * wrote a zone finds out which one they got from the report rather than from a
     * support ticket.
     */
    public function testTheDescriptionNamesTheDefaultedZone(): void
    {
        $this->assertSame('09:00-17:00 (UTC)', $this->schedule(['hours' => '09:00-17:00'])->describe());
    }

    /**
     * The zone is readable, for a caller that wants to say when "now" is there.
     */
    public function testTheTimezoneIsAvailable(): void
    {
        $this->assertSame(
            'America/Los_Angeles',
            $this->schedule(['timezone' => 'America/Los_Angeles'])->getTimezone()->getName()
        );
    }

    /**
     * Everything that is not a schedule, and the message it earns.
     *
     * A parse failure stops the rule, so each of these is an afternoon somebody does not
     * spend wondering why nothing matched -- but only if the message says which key and
     * what it wanted. The assertions are on the substring that carries that.
     *
     * @param mixed $active
     *   The `active:` block as configured.
     * @param string $expected
     *   Text the message has to contain.
     */
    #[DataProvider('unreadableSchedules')]
    public function testAnUnreadableScheduleThrows(mixed $active, string $expected): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');

        Schedule::fromMetadata($active);
    }

    /**
     * @return array<string, array{mixed, string}>
     *   Keyed by what is wrong with it.
     */
    public static function unreadableSchedules(): array
    {
        return [
            'not a map' => ['weeknights', '`active` must be a map'],
            'unknown key' => [
                ['timezone' => 'UTC', 'hour' => '18:00-06:00'],
                '`active` does not understand `hour`',
            ],
            'timezone that is not one' => [
                ['timezone' => 'America/Atlantis'],
                'not a timezone this system knows: America/Atlantis',
            ],
            'timezone that is not a string' => [
                ['timezone' => 7, 'days' => ['mon']],
                '`active.timezone` must be an identifier like `America/Los_Angeles`; got int',
            ],
            'empty days' => [['timezone' => 'UTC', 'days' => []], '`active.days` is an empty list'],
            'a day that is not one' => [
                ['timezone' => 'UTC', 'days' => ['funday']],
                '`active.days` does not understand `funday`',
            ],
            'a day that is not a string' => [
                ['timezone' => 'UTC', 'days' => [1]],
                '`active.days` does not understand int',
            ],
            'empty hours' => [['timezone' => 'UTC', 'hours' => []], '`active.hours` is an empty list'],
            'hours in words' => [
                ['timezone' => 'UTC', 'hours' => '6pm-6am'],
                '`active.hours` must be written `HH:MM-HH:MM`',
            ],
            'hours that are not a string' => [
                ['timezone' => 'UTC', 'hours' => [1800]],
                '`active.hours` must be written `HH:MM-HH:MM`, like `18:00-06:00`; got int',
            ],
            'an hour a clock does not have' => [
                ['timezone' => 'UTC', 'hours' => '25:00-26:00'],
                'names a time that does not exist',
            ],
            'a minute a clock does not have' => [
                ['timezone' => 'UTC', 'hours' => '10:00-10:75'],
                'names a time that does not exist',
            ],
            'a window of no length' => [
                ['timezone' => 'UTC', 'hours' => '09:00-09:00'],
                'starts and ends at the same time',
            ],
            'a boundary in another format' => [
                ['timezone' => 'UTC', 'from' => '27/11/2026'],
                '`active.from` must be written `YYYY-MM-DD`',
            ],
            'a boundary that is not a string' => [
                ['timezone' => 'UTC', 'until' => 20261202],
                '`active.until` must be written `YYYY-MM-DD` or `YYYY-MM-DD HH:MM`, in the rule\'s own timezone; got int',
            ],
            'a date the calendar does not have' => [
                ['timezone' => 'UTC', 'from' => '2026-02-30'],
                '`active.from` is not a date on the calendar',
            ],
            'a date the calendar does not have, with a time' => [
                ['timezone' => 'UTC', 'until' => '2026-02-30 09:00'],
                '`active.until` is not a date on the calendar',
            ],
            'a boundary time that does not exist' => [
                ['timezone' => 'UTC', 'until' => '2026-12-02 25:00'],
                '`active.until` names a time that does not exist',
            ],
            'until before from' => [
                ['timezone' => 'UTC', 'from' => '2026-12-02', 'until' => '2026-11-27'],
                'is not after `active.from`',
            ],
            'until equal to from' => [
                ['timezone' => 'UTC', 'from' => '2026-12-02 09:00', 'until' => '2026-12-02 09:00'],
                'is not after `active.from`',
            ],
        ];
    }
}
