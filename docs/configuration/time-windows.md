# Time Windows

Some rules only make sense some of the time. Blocking a country outside business hours,
turning a rate limit up for a campaign, allowing the deploy pipeline through during a
maintenance window — before 2.27.0 each of those was a rule somebody commented out and
remembered to put back.

`metadata.active` gives any rule a window:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    metadata:
      name: after-hours-geo-block
      active:
        timezone: America/Los_Angeles
        days: [mon, tue, wed, thu, fri]
        hours: "18:00-06:00"
    config:
      - "country:XX"
```

Outside its window the rule is not consulted at all. That is stronger than it sounds: the
rule is skipped **before** it evaluates, so a sleeping GeoLocation rule costs no database
lookup, and — the part that matters — a sleeping rate limit does not spend a request out of
anybody's budget for a window it was never going to enforce.

Every key is optional.

| Key | Type | Meaning |
|---|---|---|
| `timezone` | string | An identifier like `America/Los_Angeles`. Defaults to **UTC** — never the server's zone |
| `days` | list | Days the rule is awake: `mon` … `sun`, or full names. Absent means every day |
| `hours` | string or list | `HH:MM-HH:MM`, or several. Absent means all day |
| `from` | string | `YYYY-MM-DD` or `YYYY-MM-DD HH:MM`. The rule does not run before it |
| `until` | string | The same, and the rule does not run after it |

## The timezone defaults to UTC, and never to the server's

Leave `timezone` out and the window is read in UTC. The host's zone is deliberately not
consulted: a rule that takes its meaning from the machine means one thing on a laptop,
another in a container that ships with UTC, and a third the morning somebody moves the
region — with nothing in the configuration changing to say so. A fixed default is a rule
that means the same thing everywhere it is deployed.

UTC also has no daylight saving, so a window that does not name a zone is one that never
changes length.

!!! warning "UTC is a safe default, not a correct one for business hours"

    `hours: "18:00-06:00"` with no timezone is 18:00 **UTC** — 11:00 in Los Angeles, 02:00
    in Singapore. Nothing in the configuration or the logs looks wrong when that is not
    what you meant, so name the zone whenever the window is about people:

    ```yaml
    active:
      timezone: America/Los_Angeles
      hours: "18:00-06:00"
    ```

    `firewall-check --lint` warns on a scheduled rule that does not name one, and naming
    `UTC` explicitly silences it.

A `timezone` that *is* written and is not a zone this system knows — a typo, or an
identifier that does not exist — stops the rule rather than falling back to the default.
The point of the key is that the zone is never guessed.

## Everything is the clock on the wall

Whatever instant the request arrives at, it is converted into the rule's timezone once, and
every comparison after that is against the local calendar and the local clock face. `18:00`
means what a person standing in Los Angeles would mean by it.

### Days and hours are both read at the current moment

A rule is awake when **today** is one of its days and **now** is inside one of its hours.
That is worth stating plainly because of one case:

```yaml
days: [mon, tue, wed, thu, fri]
hours: "18:00-06:00"
```

Friday at 22:00 is inside the window. Saturday at 02:00 is not — it is Saturday, and
Saturday is not in the list, even though the window that covers it opened on Friday evening.
If you want the small hours of Saturday morning, say so:

```yaml
days: [mon, tue, wed, thu, fri, sat]
```

The alternative — deciding which day a window "belongs" to — is ambiguous in the other
direction (Monday 02:00 belongs to Sunday night) and impossible to read off the
configuration. This way the rule is a statement about the present moment, and you can always
answer "is it awake?" by looking at a clock and a calendar.

### Windows may cross midnight

`hours: "18:00-06:00"` is the evening *and* the small hours, not the twelve hours between
them. A range whose end is earlier than its start wraps; one whose end is later does not.

The start is included and the end is not, so `09:00-17:00` is awake at 09:00 and asleep at
17:00 exactly. For a rule that is awake all day, leave `hours` out — a range that starts and
ends at the same time is rejected rather than guessed at.

Several windows are a list:

```yaml
hours: ["09:00-12:00", "13:00-17:00"]
```

### Daylight saving does what the wall clock does

Because the comparison is local wall-clock time, transitions need no special handling and
get none:

- **Spring forward.** On the day 02:00 does not exist, `01:00-03:00` is simply a shorter
  window. No local time inside the gap ever occurs, so none is ever compared.
- **Fall back.** On the day 01:30 happens twice, a window covering it is awake both times.
  That day the window is an hour longer.

Neither is a bug. A rule about business hours should follow the clock on the wall of the
business — but if you need a window that is exactly *n* hours long every day of the year,
schedule it in `UTC`, where nothing shifts.

## Campaigns and maintenance windows

`from` and `until` bound the schedule with dates rather than repeating it weekly:

```yaml
metadata:
  name: campaign-rate-limit
  active:
    timezone: UTC
    from: 2026-11-27
    until: 2026-12-02
```

Both are read in the rule's own timezone. A bare date as `until` covers the whole of that
day — the rule above stops at the end of the second of December, because that is what "until
the second" means to a person. Add a time and it means that minute exactly:

```yaml
    until: 2026-12-02 09:00     # awake up to 08:59, asleep from 09:00
```

They combine with `days` and `hours`, so "weeknights, but only during the campaign" is all
four keys at once. A `until` that is not after its `from` is rejected: it describes a rule
that could never run.

## Finding out that a rule is asleep

A scheduled rule matching nothing looks exactly like a broken one, and the afternoon spent
telling them apart is the real cost of this feature. So it is reported in three places.

**`firewall-doctor`** lists it, as information rather than a warning — a rule outside its
window is doing what it was configured to do:

```
  ✓ Rule after-hours-geo-block is asleep right now
      Configured as a block rule, awake mon, tue, wed, thu, fri 18:00-06:00
      (America/Los_Angeles). Until then it matches nothing, which is not the same as
      being broken.
```

**`firewall-check --explain`** says `ASLEEP` rather than `pass`, because the rule did not
run — which is usually the answer to "why wasn't this caught?":

```
Plugins evaluated, in order:
  ASLEEP  after-hours                  awake mon, tue, wed, thu, fri 18:00-06:00 (America/Los_Angeles)
  pass    admin-paths                    0.04 ms
```

**The log** carries `Rule is outside its active window` at debug level on each request that
skipped it, with the window in the context.

**A status page** can ask directly:

```php
foreach ($firewall->getSleepingRules() as $rule) {
    echo "{$rule['plugin']} ({$rule['bucket']}) is awake {$rule['window']}\n";
}
```

Like `getFailedRules()`, that builds every rule that has not been built yet — it belongs on
a status page, not on a request path.

## A schedule that cannot be read stops the rule

A misspelled key, a timezone this system does not have, `hours: "6pm-6am"` — any of them and
the rule **does not start**. It is reported by `getFailedRules()`, by `firewall-doctor` and
by `firewall-check`, in the same place as a rule whose storage backend is unreachable.

That is deliberate, and it is the least bad of three options. Treating an unreadable
schedule as *always on* silently over-blocks; treating it as *always off* silently stops
protecting. Both invent an answer to a question the operator got wrong, which is how `file:`
came to be documented under `FileStorage` in five places when the key is `storage_file`.

`firewall-check --lint` catches all of it before a deploy, where it is cheap:

```
  ✗ Rule "after-hours-geo-block" has a schedule that cannot be read
      `active.days` does not understand `funday`. Write days as mon, tue, wed, thu, fri,
      sat, sun. The rule will not start.
```

It also warns about an `active:` block that constrains nothing — a timezone and no window,
or an empty map — because that rule runs at all times, which is never what somebody who
wrote a schedule meant, and about a window that never named a zone:

```
  ! Rule "after-hours" is scheduled without naming a timezone
      Its window is read in UTC. That is deliberate -- the server's zone is never used, so
      the rule means the same thing on every host -- but if the window means business hours
      somewhere, name that zone: `timezone: America/Los_Angeles`.
```

## What this is not

It does not schedule the firewall's **mode**. `global.mode` and `global.lockdown` apply to
every request regardless of what any rule is doing; a maintenance window that puts the whole
site behind [lockdown](global.md#lockdown) is still a config change or a
[panic switch](global.md#panic-switch).

It is also not an allow-list holiday. A `response: allow` rule with a window is asleep
outside it, which means the traffic it used to let through is evaluated by every rule below
it again — that is the point of scheduling one, and worth saying out loud before you
schedule the rule that lets your own monitoring in.
