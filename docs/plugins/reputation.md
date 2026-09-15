# Reputation Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Reputation`

Ask a service how bad an address is, and match when its answer crosses a threshold.

[AbuseIPDB](abuseipdb.md) is one such service, and until 2.27.0 it was the only one this
library could talk to — its caching, its fail-open posture and its quota budgeting were all
good, and all welded to one plugin. Spamhaus, Project Honeypot, an internal reputation
service and a client's own scoring endpoint all want the same shape, so this rule is that
shape and a **provider** is the part that differs.

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Reputation"
    response: block
    weight: 40
    metadata:
      name: internal-reputation
    config:
      provider: http
      upstream: "https://reputation.example.com/v1/score?ip={ip}"
      score_path: data.score
      threshold: 75
      when:
        - "path@starts_with:/login"
```

`provider` is `abuseipdb`, `http`, or the class name of [one you
wrote](#writing-a-provider). `AbuseIpdb` is this rule with `provider: abuseipdb` fixed, which
is why nothing about that plugin's configuration changed when this was extracted out from
under it.

## Only ask where it is worth asking

A reputation lookup is the most expensive thing in an evaluation: a network round trip, a
slice of somebody's quota, and latency in front of a visitor. On most sites only a handful of
paths justify it.

`when:` is a list of the [same conditions](../configuration/conditional-logic.md) every other
rule uses, so path gating and method gating are the same feature:

```yaml
when:
  - "path@starts_with:/login"
  - "path:/checkout"
```

```yaml
when:
  - type: AND
    rules:
      - "method:POST"
      - "path:/login"
```

Entries are first-match-wins, like a plugin's `config:` list — any one matching is enough. No
`when:` means every request, which is what rules written before 2.27.0 did.

!!! warning "A misspelled condition gates the rule off entirely"

    `pathh:/login` matches nothing, so the lookup never happens — while the configuration
    still reads as though reputation is being checked on `/login`. The rule reports it at
    `warning` on startup, with a suggestion, the same way an unusable rule is reported.

## The `http` provider

For any endpoint that takes an address and answers with something parseable.

| Key | Type | Default | |
|---|---|---|---|
| `upstream` | string or map | *required* | The endpoint, exactly as a [rule source declares one](../configuration/sources.md#upstreams) |
| `format` | enum | `json` | `json`, `txt`, `csv`, `tsv`, `ndjson`, `yaml`, `xml` |
| `score_path` | string | | Where the score is in the decoded body, in the dot syntax a source `select:` uses |
| `score_pattern` | string | | *Or* a regular expression with one capturing group, read from the raw body |
| `trusted_path` / `trusted_pattern` | string | *unset* | The same two ways of finding an "allow this one" flag |
| `provider_name` | string | `Reputation service` | What the log lines call it |
| `public_only` | bool | `true` | `false` to look up private and reserved addresses too |
| `content_type` | string | `application/json` | Sent with an `upstream.body` |

`upstream:` is the whole [source upstream](../configuration/sources.md#upstreams) block, so
`method`, `headers`, `body`, `auth`, `timeout`, `max_redirects` and `allow_insecure` all work
here because they already worked there — including the refusal to send a credential over
plain `http`.

### A GET with a token

```yaml
config:
  provider: http
  upstream:
    url: "https://reputation.example.com/v1/score?ip={ip}"
    auth:
      type: bearer
      token: "%env(REPUTATION_TOKEN)%"
  score_path: data.score
```

### A POST with the address in the body

```yaml
config:
  provider: http
  upstream:
    url: "https://reputation.example.com/v1/score"
    method: POST
    body: '{"ip": "{ip}", "tenant": "acme"}'
    headers:
      X-Request-Source: firewall
  score_path: data.risk
```

`{ip}` is substituted in the URL **and** the body, JSON-escaped on the way in so an address
carrying a quote cannot break the document or overwrite a field beside it.

### A plain-text service

Some services answer with a line rather than a document. Two ways to read one:

```yaml
format: txt
score_path: 0            # the body is "82\n" — a list of lines, so 0 is the first
```

```yaml
score_pattern: '/risk=(\d+)/'    # the body is "risk=82 reason=open-proxy"
```

A pattern reads the **raw body**, so `format:` means nothing alongside it; a path reads the
**decoded structure**. Use one or the other. A pattern must compile and must capture
something — both are checked at startup, not per request.

### XML

```yaml
format: xml
score_path: data.@attributes.score      # <response><data score="77"/></response>
```

Attributes land under `@attributes`, which is SimpleXML's convention and the shape the API's
own documentation will match.

!!! danger "An XML body with a `DOCTYPE` is refused"

    A response body is bytes somebody else's server produced, and every familiar way of
    weaponising one starts with a document type declaration: an entity pointing at
    `file:///etc/passwd` or an internal URL (XXE — a file read and an SSRF out of a response
    body), or nested entities that expand to gigabytes. Nothing that publishes a score sends
    one, so the decoder rejects the body before the parser sees it. It reaches the rule as a
    failed lookup, so the request is allowed through rather than erroring.

!!! danger "A missing score is a failure, not a zero"

    If `score_path` resolves to nothing, or `score_pattern` does not match — the endpoint
    changed shape, or answers `{"error": "..."}` with a 200 — the lookup is treated as
    **failed** and the rule fails open loudly. Reading it as zero would score every visitor
    clean: protection switched off, with a healthy-looking service behind it.

!!! danger "The request has to name the address"

    `{ip}` must appear in the URL or the body. Without it the same question is asked for
    every visitor — a reputation check that can neither fail nor help — so the rule refuses
    to start.

## Scoring something other than the address

A reputation service answers two quite different questions, and until 2.28.0 this rule could
only ask one of them. `subject:` asks the other — score the thing being **submitted**:

```yaml
config:
  provider: http
  subject: post.email               # default: client_ip
  when:
    - "path:/register"
  upstream:
    url: "https://verify.example.com/check"
    method: POST
    body: '{"email": "{subject}"}'
  score_path: data.risk
  threshold: 75
```

The field vocabulary is the one rate-limit keys and `when:` conditions already use:
`client_ip`, `post.*`, `header.*`, `query.*`, `cookie.*`.

`{subject}` is the token; `{ip}` still works and means the same thing, so a 2.27.0
configuration needs no edit.

**A request that does not carry the subject is skipped**, not asked with an empty value — on
most sites `post.email` exists on one path out of thousands. Sending an empty subject would
be worse than skipping: a scoring service asked about `""` answers *something*, and the
answer is about nothing.

Pair it with [`when:`](#only-ask-where-it-is-worth-asking). A signup form is one path;
without a gate the rule wakes on every request to find out there is no email on it.

### The subject leaves your server

!!! danger "This sends user data to a third party — decide that on purpose"

    An email address is personal data. A username is credential-adjacent. `subject:` is the
    one setting in this library that takes something a visitor typed and sends it somewhere
    else, so it is worth being deliberate about which service, under what agreement, and
    whether your privacy notice says so.

    Nothing about this is a reason not to use it — checking a signup against a
    breach corpus is a real control. It is a reason to know you turned it on.

**Send a digest instead**, if the service takes one:

```yaml
subject: post.email
subject_hash: sha256        # the value never leaves the server
```

The value is lower-cased before hashing, because every service that accepts a digest
normalises first — otherwise `Alice@example.com` and `alice@example.com` are two different
mailboxes to it. An algorithm this system does not have stops the rule at startup rather
than quietly falling back to plaintext.

**The logs never carry the value.** A non-address subject is written as its kind and a short
digest — `post.email 3f2a91c0b7d4` — which is enough to correlate two entries and not enough
to be a disclosure. A firewall writes log lines on every request, and those outlive the
request by however long the logs are kept.

### Not every provider can answer

`handles()` is per kind, so a provider says which subjects it scores. **AbuseIPDB scores
addresses**, so pointing an AbuseIPDB rule at `subject: post.email` refuses to start:

```
The reputation rule is configured with `subject: post.email`, but AbuseIPDB only scores
client addresses. Point it at a provider that scores that, or remove `subject:`.
```

That is a configuration error rather than a runtime surprise, because sending a username to
a service that scores IP addresses gets an answer, and the answer is about something else.

A provider opts in by implementing `SubjectAwareReputationProviderInterface` alongside
`ReputationProviderInterface` — see [writing a provider](#writing-a-provider).

### Caching

Each subject kind gets its own cache entry, so a score for `post.email` and one for an
address are never confused. An address keeps the file name it had in 2.27.0, so upgrading
orphans nothing.

## Settings every provider shares

| Key | Type | Default | |
|---|---|---|---|
| `threshold` | float | `75` | Score at or above which the rule matches, on the provider's scale |
| `cache_ttl` | int | provider's | How long a verdict is reused |
| `error_cache_ttl` | int | provider's | How long a *failed* lookup is remembered |
| `cache_dir` | string | temp dir | Where verdicts are cached |
| `on_error` | enum | `fail_open` | What to do when the service cannot answer |
| `subject` | string | `client_ip` | What to look up — `post.email`, `header.x-api-key`, … |
| `subject_hash` | string | *unset* | Send a digest rather than the value: `sha256` |
| `block_status` | int | `403` | Status returned when this rule blocks |
| `block_duration` | int | `3600` | How long the address is remembered |

The threshold is compared as a number, not an integer, so a service scoring 0–1 works
without scaling anything: `threshold: 0.8`.

## It fails open

A lookup that times out, is refused, runs into a spent quota, or returns something that is
not a verdict reports **no match**, logs at `warning`, and lets evaluation continue.
Reputation is corroborating evidence, not the last line of defence — a third party's outage
must not become an outage here.

That is the opposite of the identity verification on the [User Agent
plugin](user-agent.md#verifying-the-crawler-is-who-it-says), which fails *closed*: verification guards an **allow**,
where "cannot confirm" has to mean "not allowed". Reputation corroborates a **block**, where
"cannot confirm" has to mean "carry on".

### `on_error`

| | Behaviour |
|---|---|
| `fail_open` *(default)* | No match. The request proceeds to the next rule |
| `last_known_good` | Reuse the verdict this firewall last fetched **for that address**, however old |

Two of the three values a [rule source's `on_error`](../configuration/sources.md#failure-policy)
takes, with the same meanings. `abort` is deliberately not among them: a source aborts during
bootstrap, where a loud failure is a deploy that stops. This runs in the request path, where
it would be a 500 for a visitor because somebody else's API is slow.

`last_known_good` does not weaken failing open. It reuses an answer the provider already gave
about that exact address and which would otherwise have been thrown away for being old — no
request is ever refused on an answer that was never given. It costs one more cache file per
address, and a `warning` each time it is used, because acting on a stale verdict is something
worth seeing in a log.

## Caching

Verdicts are cached per address **and per provider**, so cost is one call per unique visitor
per period and two services never read each other's answers — 4 out of 100 is clean and 4 out
of 5 is not.

Failures are cached too, for the much shorter `error_cache_ttl`. Without that, an outage
would make every request wait out the full `timeout` before failing open: availability
preserved on paper while the site crawls.

Verdicts and failures live in **separate files**. A failure written over the verdict it
replaced would destroy the only thing `last_known_good` has to fall back on, at exactly the
moment it is needed.

Cache entries are named by SHA-1 of the address rather than the address itself, so client IPs
are not readable from a directory listing.

## Writing a provider

Seven methods, and nothing about caching, thresholds or failure policy among them — the rule
owns all of that.

```php
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationVerdict;

class SpamhausProvider implements ReputationProviderInterface
{
    public function __construct(private readonly array $config = []) {}

    public function getName(): string { return 'Spamhaus'; }

    // Namespaces the verdict cache. Filesystem-safe.
    public function getSlug(): string { return 'spamhaus'; }

    // Non-null makes the rule inert and says why, once per request at debug —
    // so a rule can be deployed before its credential is provisioned.
    public function getConfigurationProblem(): ?string
    {
        return isset($this->config['api_key']) ? null : 'no api_key configured';
    }

    // FALSE skips the lookup entirely: no call, no latency, no quota.
    public function knowsAbout(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) !== false;
    }

    public function check(string $ip): ReputationVerdict
    {
        // ... your lookup ...
        if ($somethingWentWrong) {
            // The only failure signal. The rule catches it, logs it, caches it
            // briefly and carries on.
            throw new ReputationUnavailableException('Spamhaus is not answering');
        }

        return new ReputationVerdict(
            score: 82.0,
            trusted: false,
            attributes: ['listed_on' => 'SBL'],   // log context only
        );
    }

    public function getDefaultCacheTtl(): int { return 3600; }
    public function getDefaultErrorCacheTtl(): int { return 300; }
}
```

To score more than addresses, implement `SubjectAwareReputationProviderInterface` too — two
more methods, and the address-only contract keeps working unchanged:

```php
class BreachCorpusProvider implements SubjectAwareReputationProviderInterface
{
    // ... the seven above, then:

    // Asked once, when the rule is built. A rule whose `subject:` this refuses
    // does not start.
    public function handles(ReputationSubject $subject): bool
    {
        return $subject->kind === 'post.email';
    }

    public function checkSubject(ReputationSubject $subject): ReputationVerdict
    {
        // $subject->value is the thing to look up, already hashed when the rule
        // configured `subject_hash`. $subject->describe() is what may be logged.
        return new ReputationVerdict(score: 82.0);
    }
}
```

The two interfaces are separate rather than one widened interface, because
`ReputationProviderInterface` shipped in 2.27.0 with this page telling people how to write
one. Widening it a release later would have made every provider written from it fatally
incomplete on a `composer update` — the same reason `ObserveModeInterface` and
`ScheduledRuleInterface` are separate from `PluginInterface`.

Then name the class:

```yaml
config:
  provider: "App\\Firewall\\SpamhausProvider"
  api_key: "%env(SPAMHAUS_KEY)%"
  threshold: 50
```

The whole `config:` block reaches the provider's constructor, so provider settings sit
alongside the rule's rather than under a nested key.

Failure is an exception rather than a null return on purpose: it means failing open is what a
provider gets for free, and failing closed would be something somebody had to write
deliberately.

## What gets logged

A match logs at `info` with `ip`, `score`, `threshold` and whatever the provider put in
`attributes`.

A failed lookup logs at `warning` with `error`, `http_status` and a note that the request was
allowed through. A stale verdict used under `last_known_good` logs at `warning` with
`age_seconds`.

Skips — an unconfigured provider, an address the provider knows nothing about, a score under
the threshold, a trusted address, a still-cached recent failure — log at `debug`.
