# Glossary

Terms this documentation uses in a specific way. Two sentences each, and a link to where the
idea is explained properly.

### Anomaly score

The running total a [CRS](../plugins/crs.md) rule set accumulates over one request, weighted
by each matching rule's severity — critical adds 5, error 4, warning 3, notice 2. Nothing is
rejected until the total crosses `anomaly_thresholds.inbound`, which is why a single match is
not a block.

### Audience

The `aud` claim on a [pass token](#pass-token), which stops a token minted by one firewall
instance satisfying another. It defaults to the provider name, so two deployments using the
same provider *and* the same secret will accept each other's tokens unless you set
`challenge.audience` explicitly. → [Scoping tokens](../plugins/challenges.md#scoping-tokens-across-instances)

### Bucket

One of the three groups a [rule](#rule) is filed into by its [response](#response) — **allow**,
**challenge**, **block** — consulted in that fixed order. Buckets always beat
[weights](#weight): an allow rule with the worst weight in the file still runs before a block
rule with the best. → [Evaluation Order](evaluation-order.md)

### Decision event

A read-only PSR-14 event the firewall dispatches after it decides what to do with a request,
for metrics, notifications or an audit trail. A listener cannot change the verdict, and one
that throws is logged and ignored rather than allowed to break the request. →
[React to Decisions](../how-to/decision-events.md)

### Durable block list

Storage-backed state recording clients blocked by earlier requests, consulted on every
request after the allow bucket. It is what makes a ban outlast the request that caused it —
and, because the allow bucket runs first, an allow rule lets a listed client back in. →
[Evaluation Order](evaluation-order.md)

### Escalation stage

One entry in `blocking_escalation`, saying that a client with at least `offense` offenses in
the last `window` seconds gets banned for `duration`. Stages let a repeat offender be banned
for longer than a first-time one without any rule changing. →
[Multiple Offenses](../configuration/global.md#multiple-offenses-defense)

### Managed file

The separate YAML file `firewall-rule` owns and rewrites in full. It exists so the command
never has to edit the configuration you wrote, which parsing and re-dumping would strip every
comment out of. → [Manage Rules](../how-to/managing-rules.md)

### Observe mode

Evaluating a rule and *reporting* the match instead of acting on it. Available per rule with
`metadata.mode: log` — which leaves every other rule enforcing — or site-wide with
`global.mode: log`. → [Observing one rule](../configuration/global.md#observing-one-rule-while-the-rest-enforce)

### Offense

One recorded instance of a client being blocked, counted by the storage backend. Offenses are
what [escalation stages](#escalation-stage) count to decide how long the next ban lasts, so
they outlive the block that produced them. → [Storage](../configuration/storage.md)

### Panic switch

A file named by `global.panic_file` that overrides `global.mode` while it exists, so the mode
can change during an incident without a deploy. It fails safe: a file that names nothing
recognisable changes nothing and is reported. →
[Panic Switch](../configuration/global.md#panic-switch)

### Paranoia level

Which tiers of CRS rules are active, from 1 (conservative) to 4 (aggressive). Raising it
catches more and produces more false positives; it is the blunt lever, and `disabled_rules`
is the precise one. → [OWASP CRS](../plugins/crs.md)

### Pass token

The HMAC-signed token a visitor receives for solving a challenge, which satisfies later
challenge rules until it expires. It is bound to the client IP, the [audience](#audience) and
the provider that issued it — so it skips the challenge bucket and never suppresses a block. →
[Challenges](../plugins/challenges.md)

### Plugin

The PHP class that implements a kind of check — `IpAddress`, `RateLimit`, `Crs`. A plugin is
code; a [rule](#rule) is one configured use of it, and one plugin can back many rules. →
[Plugins](../plugins/index.md)

### Preset

A rule set shipped inside the package and pulled in with `configs:`, such as
`malicious-requests.yml`. Because presets ship with the library, `composer update` can change
what they block. → [Presets](../presets/index.md)

### Response

What a rule does when it matches — `allow`, `block` or `challenge`. It also decides which
[bucket](#bucket) the rule goes in, which is why it matters more than [weight](#weight). →
[Plugins](../plugins/index.md)

### Rule

One entry under `plugins:` — a [plugin](#plugin) class plus the configuration that makes it do
something specific. Give every rule a `metadata.name`, or the log cannot tell two rules of the
same class apart. → [Configuration Keys](configuration-keys.md)

### Sample

The rate-limit time window, in seconds: `rate: 5` with `sample: 300` is five requests per five
minutes. The same idea is called a [window](#window) in escalation, which is an inconsistency
in the configuration rather than a difference in meaning. → [Rate Limit](../plugins/rate-limit.md)

### Source

A list of rule entries that lives outside your configuration — a file, a URL, a feed somebody
else publishes — declared under `metadata.sources`. Sources append to a rule's `config:`
rather than replacing it. → [Rule Sources](../configuration/sources.md)

### Upstream

Where a [source](#source) fetches from: a path, a URL, or a `{config_dir}` token. It is one
key of a source declaration, not a synonym for it. →
[Rule Sources](../configuration/sources.md#every-option)

### Weight

Ordering *within* one [bucket](#bucket); lower runs first. It has no effect between buckets,
which is the single most common misunderstanding about how rules are evaluated. →
[Evaluation Order](evaluation-order.md)

### Window

The lookback period of an [escalation stage](#escalation-stage), in seconds — how far back the
firewall counts [offenses](#offense) when deciding the next ban length. Rate limiting calls
the same concept a [sample](#sample). →
[Multiple Offenses](../configuration/global.md#multiple-offenses-defense)
