# Troubleshooting

Organised by the sentence you would actually type, not by subsystem. Each entry is the
symptom, **the one command that confirms it**, and the fix.

Almost all of these are answered by `firewall-check --explain`, which evaluates a request
against a throwaway store — so asking about an address can never ban it.

---

## "My allow rule isn't working"

**Confirm it:**

```console
$ firewall-check --config=firewall.yml --ip=198.51.100.7 --url=/ --explain
```

Read the `Plugins evaluated, in order` list. If the allow rule is not in it, it did not
match. If it *is* in it and the request was still blocked, that is a different problem —
see below.

**The usual cause is the opposite of what people expect:** weights do not decide this.

Buckets are consulted in a fixed order — **allow, then challenge, then block** — and
`weight` only sorts rules *within* one bucket. An allow rule with the worst weight in the
file still beats a block rule with the best:

```
ALLOWED  GET /
  client            198.51.100.7
  allowed by        allow-last

Configured but not reached:
  block     block-first    Kanopi\Firewall\Plugins\IpAddress    weight -9999
```

So "my allow rule is losing to a block rule" is almost never true. What is usually true is
that the allow rule **did not match the request** — a CIDR that does not contain the
address, or a client IP that is not what you think it is (see
[Everything is blocked](#everything-is-blocked-or-nothing-is)).

---

## "Legitimate traffic is being blocked"

**Confirm it:**

```console
$ firewall-check --config=firewall.yml --ip=203.0.113.9 --url=/checkout --explain
```

The verdict names the rule: `blocked by  crs-paranoia-2`. If your rules have no
`metadata.name`, give them one — every log line about a rule is otherwise identified only
by its class, and two rules of the same class are indistinguishable.

**The fix, in order of how much you should reach for it:**

1. **Put that one rule in observe mode** rather than turning the firewall down. The rule
   evaluates, logs at `warning` with `enforced: false`, and is then treated as no match:

    ```yaml
    metadata:
      name: crs-paranoia-2
      mode: log        # match, report it, carry on
    ```

    Everything else keeps enforcing. Leave it a week, count what it *would* have blocked,
    then tune or remove it.

2. **Add a narrow allow rule** with a negative weight, if a specific client needs to get
   through regardless.

3. **`global.mode: log`** turns off enforcement for the whole site. That is the blunt
   instrument, and it is the right one during an incident — but if you are reaching for it
   because of one rule, use the first option.

---

## "I locked myself out"

**Confirm it:**

```console
$ firewall-block firewall.yml --show=203.0.113.9
```

That reads the **real** block list, which is the point — unlike `firewall-check`, which
deliberately uses a throwaway.

**Fix it:**

```console
$ firewall-block firewall.yml --lift=203.0.113.9
$ firewall-block firewall.yml --lift=203.0.113.0/24 --dry-run   # check first if it is a range
```

Being blocked repeatedly after lifting means a rule is still matching you. Find it with
`firewall-check --explain`; lifting a block does not stop the rule that caused it.

!!! note "Bans get longer, not just repeated"

    `blocking_escalation` lengthens each subsequent ban for the same client. A block you
    lifted an hour ago coming back for six hours is that working as configured — see
    [Global Settings](../configuration/global.md).

---

## "The challenge loops forever"

A visitor solves the challenge and is immediately challenged again.

**Confirm it:** check that the submission path reaches the firewall at all.

```console
$ firewall-check --config=firewall.yml --ip=203.0.113.9 --url=/_firewall/challenge --explain
```

**Four causes, in the order they actually happen:**

| | |
|---|---|
| **Your application routes the submission path** | `challenge.path` (default `/_firewall/challenge`) must reach the firewall, and the firewall must run before your router. If the app claims that URL, no solution is ever received. |
| **The token was earned against a different provider** | A token carries a `prv` claim and only satisfies rules using *that* provider. A visitor who solved a `math` challenge is still challenged by a `turnstile` rule. This is deliberate. |
| **The client IP changes between solving and returning** | Tokens are IP-bound. Behind a proxy whose trusted-proxy configuration is wrong, every request can look like a different client. |
| **Two instances, same secret, same provider** | Both default their `aud` claim to the provider name, so a token from one satisfies the other — or, if the secrets differ, neither. Set `challenge.audience` explicitly. |

---

## "Everything is blocked, or nothing is"

**Confirm it:**

```console
$ firewall-doctor firewall.yml
```

**If nothing is blocked at all:**

- **`mode`** — `disabled` evaluates nothing; `log` evaluates everything and enforces
  nothing. Check for a [panic file](../configuration/global.md#panic-switch) too: it
  overrides `mode` and leaves no trace in the config. `firewall-doctor` reports an active
  one as a warning.
- **You are running under CLI.** `evaluate()` returns immediately under `PHP_SAPI === 'cli'`
  for every mode except `exception`. That is deliberate — Artisan, Drush, WP-CLI and cron
  have no visitor to protect — but it means a CLI reproduction of a web problem proves
  nothing.
- **Nothing in your config loaded.** See the next entry.

**If everything is blocked, or IP rules behave randomly**, the client IP is probably not
what you think. Every rule reads `$request->getClientIp()`, which only honours
`X-Forwarded-For` after your application has called `Request::setTrustedProxies()`. Without
it, behind a CDN, every visitor appears to come from the proxy — so one bad actor can get
the whole site blocked, and an IP allowlist can be walked past with a forged header. Assert
what is in front of you:

```yaml
global:
  behind_proxy: true
  require_trusted_proxies: true   # refuse to start without them
```

---

## "None of my rules are configured"

`firewall-doctor` reports no rules, or `firewall-rule list` says `No rules are configured`,
on a config that plainly has them.

**Confirm it:**

```console
$ firewall-rule list firewall.yml
```

It prints the load errors. **A `configs:` entry naming a file that does not exist empties
the entire document** — a missing include is a load failure, not a skipped line, so *every*
rule stops being configured:

```
That configuration did not load cleanly:
  Config not found: /srv/app/config/firewall-managed.yml
```

**Fix it:** create the file before referencing it (`firewall-rule init` does exactly that,
in that order), or remove the include. Set `global.require_config: true` to make this throw
at startup instead of degrading quietly.

---

## "Rate limits trip on normal browsing"

**Confirm it:** check whether the path you are testing has a rule of its own.

**Every path is rate limited by default**, not only the ones under `config:`. A request
matching no rule falls through to a catch-all built from `default_rate` and
`default_sample` — so adding one rule to protect `/user/login` also imposes a site-wide cap
on everything else, at whatever `default_rate` says.

```yaml
metadata:
  default_rate: 60
  default_sample: 60
  limit_unlisted_paths: false   # count only what you listed
config:
  - path: /user/login
    rate: 5
    sample: 300
```

!!! warning "`default_rate: 0` is not unlimited"

    The check is `count >= rate`, and a count is never negative, so `0` is satisfied by no
    request at all — including the first. It blocks everything.

---

## "Rules stopped matching after an update"

**Confirm it:**

```console
$ firewall-sources firewall.yml --dry-run     # what each source resolved to, no network
$ firewall-doctor firewall.yml                # how stale each cache is
```

**Two different causes:**

- **A rule source stopped refreshing.** `firewall-sources` fails when a fetch *fails*; it
  says nothing about a fetch that stopped being attempted — a cron removed in a migration, a
  credential that expired. The rule keeps matching, on a list frozen at whatever it said when
  the sync last worked. Set
  [`global.stale_source_error_after`](../configuration/global.md#stale-rule-sources) to make
  that fail a deploy.
- **`composer update` changed a preset.** Presets ship inside the package, so what they
  block can change with a library upgrade. The release notes call out preset behaviour
  changes under *What changes on upgrade*.

---

## Still stuck

| | |
|---|---|
| Something is misconfigured and I want it found | `firewall-doctor firewall.yml` |
| A rule can never match, and I want to know before deploying | `firewall-check --config=firewall.yml --lint` |
| I need to see what my application receives | [React to Decisions](decision-events.md) |
| An exception reached my code and I do not recognise it | [Exceptions](../reference/error-handling.md) |
