# Rule Sources

A plugin's rules do not have to be written into your configuration. `metadata.sources`
points a plugin at lists that live somewhere else — a file on disk, a URL, a list your
team publishes, a list someone else publishes — and turns whatever shape they arrive in
into the rules that plugin expects.

The problem this solves is that almost nothing in the world publishes rules in our
format. Cloud providers publish JSON. Monitoring vendors publish newline-delimited text.
Threat feeds publish NDJSON. Sources declare what a list *is* and which part of it you
want, so those lists can be consumed as they are rather than reshaped by hand first.

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    enable: true
    metadata:
      sources:
        - name: tor-exits
          upstream: "{config_dir}/lists/tor-exits.txt"
          validate: cidr
    config:
      - 203.0.113.7      # local additions still land last
```

---

## The pipeline

Every source runs through the same seven stages. Only the first two know anything about
wire formats; after `decode` everything is a plain PHP array, which is what lets one
pipeline serve text, JSON, NDJSON, YAML, CSV, and TSV alike.

```
fetch → decompress → decode → select → where → template → validate
```

| Stage | Key | What it does |
|---|---|---|
| fetch | `upstream`, `ttl` | Reads the file or URL, revalidating rather than re-downloading when it can |
| decompress | `compression` | Unwraps a gzipped body |
| decode | `format`, `headers`, `comment`, `delimiter` | Turns bytes into records |
| select | `select` | Narrows a document to the records you want |
| where | `where` | Keeps only the records matching your conditions |
| template | `template` | Shapes each record into the rule the plugin takes |
| validate | `validate`, `max_delta` | Rejects entries, and refreshes, that do not look right |

Every stage is optional except the fetch. A source that is already a plain list of the
values a plugin wants needs nothing but an `upstream`.

---

## Every option

### On the source

| Key | Type | Default | Purpose |
|---|---|---|---|
| `upstream` | string or map | *required* | Where the list lives and how to ask for it — see [Upstreams](#upstreams) |
| `name` | string | derived from `upstream` | Used in logs, errors, and match attribution |
| `format` | enum | inferred from extension, else `txt` | `txt`, `json`, `ndjson`, `yaml`, `csv`, `tsv` |
| `compression` | enum | inferred from extension, else `none` | `none`, `gzip` |
| `select` | string | none | Dot-path selecting records from the decoded document |
| `where` | list | `[]` | Conditional-logic rules every kept record must satisfy |
| `template` | string or map | none | Output shape; records pass through untouched when absent |
| `validate` | enum | none | `cidr`, `ip`, `regex`, `string` |
| `max_delta` | float | none | Reject a refresh moving the entry count by more than this fraction |
| `ttl` | int | `KANOPI_FIREWALL_CACHE_TTL`, else 3600 | Seconds before the cached copy is revalidated |
| `on_error` | enum | `last_known_good` | `last_known_good`, `fail_open`, `abort` |
| `required` | bool | `false` | Abort rather than degrade when this source fails |
| `header_row` | bool | `true` | CSV/TSV: treat the first row as column names |
| `comment` | string | `#` | Text formats: strip from this marker to end of line |
| `delimiter` | string | `,` for csv, tab for tsv | CSV/TSV field delimiter |

### On the upstream

| Key | Type | Default | Purpose |
|---|---|---|---|
| `url` | string | *required* | File path or URL the list is read from |
| `method` | enum | `GET` | `GET`, `POST`, or `HEAD` |
| `headers` | map | `{}` | Extra request headers |
| `auth` | map | none | Credentials — see [Authentication](#authentication) |
| `body` | string | none | Request body, for methods that take one |
| `timeout` | float | `KANOPI_FIREWALL_CACHE_TIMEOUT`, else 5.0 | Seconds to wait |
| `max_redirects` | int | `5` | Redirect hops to follow |
| `allow_insecure` | bool | `false` | Permit credentials over plain `http://` |

A bare string is shorthand for a source with nothing but an upstream, and an upstream with
nothing but a URL. These three are the same source:

```yaml
sources:
  - "{config_dir}/lists/tor-exits.txt"

  - upstream: "{config_dir}/lists/tor-exits.txt"

  - upstream:
      url: "{config_dir}/lists/tor-exits.txt"
```

---

## Upstreams

Most upstreams are a bare location, so `upstream` takes a string. When the request needs
more than a URL, the same key takes a map instead:

```yaml
- name: private-feed
  upstream:
    url: https://feeds.example.com/v1/blocklist.json
    method: POST
    body: '{"scope":"active"}'
    headers:
      Content-Type: application/json
      X-Account: "12345"
    auth:
      type: bearer
      token: "%env(FEED_TOKEN)%"
    timeout: 10
  format: json
  select: "results.*"
  template: "{value[address]}"
  validate: cidr
```

Everything about *reaching* the list lives under `upstream`; everything else on the source
is about the list itself. That split is also why the CSV first-row option is
`header_row` — `headers` under `upstream` is unambiguously request headers.

Header values are stripped of newlines, since one would otherwise let an injected value
start a header of its own.

---

## Authentication

`upstream.auth` covers the four shapes feeds actually use.

=== "Bearer token"

    ```yaml
    upstream:
      url: https://feeds.example.com/v1/list.json
      auth:
        type: bearer
        token: "%env(FEED_TOKEN)%"
    ```

    Sends `Authorization: Bearer <token>`.

=== "Basic"

    ```yaml
    upstream:
      url: https://feeds.example.com/v1/list.json
      auth:
        type: basic
        username: "%env(FEED_USER)%"
        password: "%env(FEED_PASSWORD)%"
    ```

    Sends `Authorization: Basic <base64>`.

=== "API key header"

    ```yaml
    upstream:
      url: https://feeds.example.com/v1/list.json
      auth:
        type: header
        name: X-API-Key
        value: "%env(FEED_KEY)%"
    ```

=== "Query parameter"

    ```yaml
    upstream:
      url: https://feeds.example.com/v1/list.json
      auth:
        type: query
        name: api_key
        value: "%env(FEED_KEY)%"
    ```

    Appended to the request URL, and scrubbed from anything the firewall prints.

!!! tip "Keep the secret out of the config file"
    `%env(...)%` is resolved at load time, so credentials can live in the environment
    rather than in a file that ends up in version control. See
    [Environment Variables](environment-variables.md).

### Credentials never reach a log

Every place the firewall shows an upstream — log context, exception messages, CLI output,
the plugin's own debug dump of its metadata — shows a redacted form:

```
https://reader:hunter2@example.org/list.txt   →  https://***@example.org/list.txt
https://example.org/list?api_key=s3cr3t       →  https://example.org/list?api_key=***
```

Redaction runs whether or not `auth` is declared, because a URL pasted straight in can
carry a token on its own. Parameters named `token`, `key`, `api_key`, `access_token`,
`auth`, `password`, `secret`, `signature` and similar are all scrubbed.

### Plain `http://` is refused

A credential sent over plain http travels in clear text, so declaring one on an `http://`
upstream is an error. An operator on a trusted internal network can say so explicitly:

```yaml
upstream:
  url: http://internal.example/list.txt
  auth:
    type: bearer
    token: "%env(FEED_TOKEN)%"
  allow_insecure: true
```

### Redirects do not carry credentials off-origin

Redirects are followed by hand rather than by PHP's `follow_location`, which reuses the
whole request context on every hop — so a redirect to another host would resend your
`Authorization` header to whoever answered it. When a hop changes scheme, host, or port,
both `auth` and any `headers` you set are dropped before the next request. An API key
header is a credential whatever it is called.

`max_redirects: 0` disables following altogether.

### Rotating a credential does not invalidate the cache

The cache key covers everything that can change *what comes back* — URL, method, headers,
body — but deliberately not the credential. Rotating a token does not change the list it
fetches, and re-decoding every source on a key rotation would be pure waste.

---

## Formats

### `txt` — newline-delimited

The default, and what most published lists actually are. Real lists are rarely tidy, so
the decoder handles the mess: `#` banners, blank separators, trailing whitespace, and
trailing labels are all stripped.

```
# UptimeRobot IPv4
# updated 2026-09-04

216.144.250.150
69.162.124.224/28    # datacenter block
```

```yaml
- name: uptimerobot
  upstream: "{config_dir}/lists/uptimerobot.txt"
  validate: cidr
```

A marker only opens a comment at the start of a line or after whitespace, so a value that
legitimately contains one — `/path#fragment` — survives. Set `comment: ";"` for a
different marker, or `comment: ""` to disable stripping entirely.

### `json` — a single document

```yaml
- name: cloud-ec2-us
  upstream: https://example.org/v1/ranges.json
  format: json
  select: "prefixes.*"
  where:
    - "service:EC2"
    - "region@starts_with:us-"
  template: "{value[ip_prefix]}"
  validate: cidr
```

### `ndjson` — one document per line

A separate format because the body as a whole is not valid JSON. Several threat feeds
publish this.

```yaml
- name: reputation-feed
  upstream: https://example.org/v1/feed.ndjson
  where:
    - "score@greater_than:80"
  template: "{value[ip]}"
```

### `yaml` — a single document

```yaml
- name: shared-rules
  upstream: "{config_dir}/lists/rules.yml"
```

!!! warning "A `.txt` list declared as `yaml` produces nothing"
    YAML folds a newline-delimited IP list into one long scalar, so the parse *succeeds*
    and yields no records. The decoder rejects this explicitly rather than leaving you
    with a silently empty rule list — but the fix is always the same: declare it
    `format: txt`.

### `csv` and `tsv` — delimited rows

With `header_row: true` (the default) each row becomes a map keyed by column name. With
`header_row: false` rows stay numerically indexed and you address columns by position.

```csv
asn,org,country
13335,CLOUDFLARENET,US
16509,AMAZON-02,US
```

```yaml
- name: hosting-asns
  upstream: "{config_dir}/lists/hosting-asns.csv"
  format: csv
  template: "asn:{value[asn]}"
```

→ `["asn:13335", "asn:16509"]`

With `header_row: false` the same file is `template: "asn:{value[0]}"`, addressing columns
by index.

### Compression

Compression is a separate axis from format, so there is no `json-gz` to declare:

```yaml
- name: big-list
  upstream: https://example.org/v1/ranges.json.gz    # format and compression both inferred
```

Both are inferred from the extension: `ranges.json.gz` is JSON, gzipped. Declare
`compression: gzip` explicitly when the URL does not say so.

---

## `select` — narrowing a document

`select` is a dot-path with wildcards and alternation — the same syntax the loader uses
for `relativePathKeys`.

| Token | Matches |
|---|---|
| `*` | any single key at that depth |
| `{a,b}` | either named key |
| `(a\|b)` or `a\|b` | the same, spelled differently |
| anything else | that key, literally |

```yaml
select: "prefixes.*"                    # every record in one collection
select: "{prefixes,ipv6_prefixes}.*"    # every record across two collections
select: "data.regions.*.ranges.*"       # nested collections
```

Alternation earns its keep on documents that split what is really one list across two
keys — AWS publishes IPv4 under `prefixes` and IPv6 under `ipv6_prefixes`, and
`{prefixes,ipv6_prefixes}.*` takes both in one source.

With no `select`, a decoded list is already the record set, and anything else is treated
as a single record. So a document that *is* the list needs no selector at all.

---

## `where` — filtering records

`where` reuses the plugin conditional-logic engine, so every operator, negation, and
group described in [Conditional Logic](conditional-logic.md) works here unchanged.

```yaml
where:
  - "service:EC2"
  - "region@starts_with:us-"
  - "!deprecated:true"
```

!!! important "`where` is AND, not OR"
    A plugin's `config:` list is first-match-wins, so adding a rule there *widens* what
    matches. A `where` list *narrows*: a record is kept only when it satisfies every rule.
    Use an explicit group when you want the other behaviour:

    ```yaml
    where:
      - type: OR
        rules:
          - "service:EC2"
          - "service:LAMBDA"
    ```

Filtering is what makes large published documents usable. A cloud provider's range list
runs to thousands of prefixes across every service and region; almost nobody wants all of
them, and `select` alone cannot express which — by the time you have descended to
`ip_prefix` you have lost the `service` and `region` fields you needed to decide.

Scalar records — text lines — expose themselves as `value`, so text lists are filterable
too:

```yaml
where:
  - "value@starts_with:10."
```

---

## `template` — shaping entries

Worth being precise about how much of the plugin surface needs this. `IpAddress` is the
outlier: its config is bare values (`10.0.0.0/8`), so a list of addresses feeds it
directly. Every other plugin takes **rule strings** — `Asn` takes `asn:13335`, `Url`
takes `path@starts_with:/admin`, `UserAgent` takes `client.name:Chrome` — and no upstream
feed publishes those. So a template is the normal case, not the exception.

`{value}` always means the record. Index into it when it is structured:

| The record is | Reference it with |
|---|---|
| a text line, or any scalar | `{value}` |
| a JSON/YAML object | `{value[ip_prefix]}` |
| a CSV row with headers | `{value[asn]}` |
| a CSV row with `header_row: false` | `{value[0]}` |
| nested | `{value[geo][country]}` |
| whichever key exists | `{value[ip_prefix\|ipv6_prefix]}` |

Write a literal brace as `{{` or `}}`.

### Plucking one field

```yaml
select: "prefixes.*"
where:
  - "service:EC2"
template: "{value[ip_prefix]}"
```

A template that is *exactly* one placeholder keeps the field's own type, so a numeric
column stays numeric rather than becoming the string `"443"`.

### Building a rule string

```yaml
- name: bad-agents
  upstream: "{config_dir}/lists/user-agents.txt"
  format: txt
  template: "client.name@contains:{value}"
```

### Building a structured rule

`Url` and `UserAgent` both accept grouped condition objects, which a string template
cannot produce. Interpolate into the leaves instead:

```yaml
- name: scanner-signatures
  upstream: https://example.org/v1/scanners.json
  format: json
  select: "signatures.*"
  template:
    type: AND
    rules:
      - "client.name@contains:{value[name]}"
      - "bot:{value[is_bot]}"
```

### Passing records through

With no `template`, records reach the plugin untouched — the right default for a source
that already publishes rules in our own shape.

### When a placeholder cannot resolve

The record is **dropped**, and the count is logged. A rule with a hole in it would match
the wrong things, which is worse than one rule fewer.

!!! warning "Interpolation is string injection into a rule DSL"
    Rule strings are delimited by `:` and `@`. An upstream value containing either changes
    what the resulting rule *means* — a user agent of `foo@regex:.*` interpolated into
    `client.name@contains:{value}` is not the rule you wrote. This is harmless for a list
    you publish and worth thinking about for a third-party feed. Two mitigations: prefer
    the map form of `template`, which is built structurally rather than split on
    delimiters, and set `validate` so anything malformed is rejected before it reaches the
    plugin.

---

## Guardrails

These matter most when `upstream` is a URL you do not control. A feed that breaks, or is
tampered with, otherwise reaches a plugin's rule list intact.

### `validate`

| Value | Accepts |
|---|---|
| `cidr` | An address, a CIDR block, or a `start-end` range — exactly what `IpAddress` can use |
| `ip` | A single address, nothing with a prefix or range |
| `regex` | A pattern that compiles |
| `string` | Any non-empty string |

Individual bad entries are dropped and logged rather than failing the whole source: one
malformed line in a 9,000-entry list should not take the other 8,999 with it. Structured
entries are rule maps rather than values, so the scalar validators pass them through.

A `/0` prefix is accepted but logged as a warning — it covers the entire address space,
is essentially never intended, and is catastrophic in either an allow or a block list.

### `max_delta`

Rejects a refresh whose entry count moved further than a healthy update ever would:

```yaml
max_delta: 0.25    # refuse a change of more than 25% either way
```

The first load has nothing to compare against, so the check is inert until a source has
succeeded once. This is what stops an upstream that starts returning an error page — or
an empty document — from quietly emptying your block list.

---

## Failure policy

Failure handling is deliberately asymmetric, and choosing the wrong side is the most
consequential mistake available here.

| `on_error` | Behaviour |
|---|---|
| `last_known_good` *(default)* | Reuse the last successful copy; contribute nothing if there is none |
| `fail_open` | Contribute nothing and carry on |
| `abort` | Throw, taking the firewall bootstrap with it |

`required: true` forces aborting regardless of `on_error`.

**For a block list, degrading is right.** Losing coverage beats losing the site, so the
default lets a broken source fall back or drop out while the others keep working.

**For an allow list, degrading is wrong.** Quietly dropping your CI provider's ranges
means deploys start getting challenged or blocked, and the only signal is a log line
nobody is watching. Mark those sources required:

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
  response: allow
  weight: -200
  metadata:
    sources:
      - name: ci-ranges
        upstream: https://example.org/v1/ci-ranges.json
        required: true      # fail loudly rather than silently locking out CI
        max_delta: 0.25
```

!!! danger "An allow entry short-circuits everything after it"
    `response: allow` stops evaluation the moment it matches. A wrong entry in an allow
    list does not merely admit one vendor — it exempts whoever currently holds that
    address from the entire firewall. Cloud addresses get recycled. Keep allow sources
    narrow, pin them with `validate` and `max_delta`, and prefer lists you or a party you
    trust actually publishes.

---

## Caching, and keeping fetches off the request path

### What is cached

The **result**, not the bytes. Caching a raw body only saves the download; the expensive
part of a large list is decoding it, and a 9,000-entry document parsed, selected,
filtered, and rendered on every request costs far more than the transfer ever did.

Entries are stored post-pipeline as a plain PHP array, which opcache holds in memory — so
a warm request is one `include`, not a parse.

The cache key covers `upstream` plus every option that changes the decoded result, so
editing a `select` or `template` invalidates it on its own. Renaming a source, or
changing its `ttl`, does not.

### How a refresh is avoided

1. Inside `ttl`, the cached entries are used with no fetch at all.
2. Past it, the stored `ETag` and `Last-Modified` go back as `If-None-Match` and
   `If-Modified-Since`. A `304` means no body crosses the wire.
3. For upstreams that do not support conditional requests, the body is hashed. An
   unchanged hash skips the decode even though the download happened.

### Where it is written

`KANOPI_FIREWALL_CACHE_DIR/sources` when that constant is defined, otherwise
`sys_get_temp_dir()/kanopi-firewall-sources`.

### Syncing out of band

Even with all of the above, a cold cache on a live request makes a visitor wait on
somebody else's HTTP server, and a TTL expiry under load sends every concurrent request
after the same URL at once. Refresh out of band instead:

```bash
# At deploy time, or on a cron
vendor/bin/firewall-sources config/firewall.yml
```

```
Cache directory: /var/cache/firewall/sources

  ✓ aws-ec2-us                  1284 entries in 412ms
  ✓ uptimerobot                 62 entries in 38ms
  ✓ tor-exits                   1533 entries in 190ms

3 sources refreshed.
```

| Option | Effect |
|---|---|
| `--force` | Revalidate even when the cached copy is fresh |
| `--dry-run` | Report what is cached and whether it is stale, without fetching |
| `--cache-dir=DIR` | Write somewhere other than the configured location |
| `--quiet` | Only report failures |

It exits `0` when everything loaded, `1` when any source failed, and `2` when the
configuration itself could not be read — so a deploy step can fail on a bad list. See
[Syncing Rule Sources](../guides/syncing-sources.md) for cron and deploy recipes.

The same upstream declared on several plugin entries is fetched once per run, not once
per plugin.

Then stop the runtime reaching the network at all:

```php
define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);
```

In offline mode a remote source is served from cache, and one with nothing cached is an
error rather than a silently empty rule list. Local files are still read normally, which
is the intended arrangement: sync to disk out of band, serve from disk.

---

## Worked examples

### The same data, three different responses

Because a source carries data and not policy, one list can drive whichever response suits
the deployment:

```yaml
plugins:
  # Trusted automation — straight through, nothing else runs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    metadata:
      sources:
        - name: uptimerobot
          upstream: "{config_dir}/lists/uptimerobot.txt"
          validate: cidr
          required: true

  # Bulk cloud egress — plausible, but prove it
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: challenge
    weight: 0
    enable: true
    metadata:
      sources:
        - name: cloud-egress
          upstream: "{config_dir}/lists/cloud-egress.txt"
          validate: cidr

  # Known bad — gone
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: 10
    enable: true
    metadata:
      sources:
        - name: tor-exits
          upstream: "{config_dir}/lists/tor-exits.txt"
          validate: cidr
```

### A cloud provider's range document

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
  response: challenge
  enable: true
  metadata:
    sources:
      - name: cloud-ec2-us
        upstream: https://example.org/v1/ranges.json
        format: json
        select: "{prefixes,ipv6_prefixes}.*"
        where:
          - "service:EC2"
          - "region@starts_with:us-"
        template: "{value[ip_prefix|ipv6_prefix]}"
        validate: cidr
        max_delta: 0.25
        ttl: 21600
```

### A CSV of ASNs

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\Asn"
  response: challenge
  enable: true
  metadata:
    reader:
      type: reader
      db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
    sources:
      - name: hosting-asns
        upstream: "{config_dir}/lists/hosting-asns.csv"
        format: csv
        where:
          - "category:hosting"
        template: "asn:{value[asn]}"
```

### Several sources into one plugin

Sources contribute in declaration order and inline `config:` is appended after all of
them, so a deployment can always add an entry without editing a shared list.

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
  response: allow
  weight: -200
  enable: true
  metadata:
    sources:
      - "{config_dir}/lists/circleci.txt"
      - "{config_dir}/lists/uptimerobot.txt"
      - "{config_dir}/lists/github-actions.txt"
  config:
    - 127.0.0.1
    - 10.0.0.0/8
```

---

## Attributing a match

Every entry remembers which source supplied it, so a match can name the list that caused
it rather than reporting only that something matched:

```php
$plugin->entrySource(0);   // "circleci"
$plugin->entrySource(42);  // null — a local entry from inline config
```

---

## Migrating from `metadata.config`

`metadata.config` still works, and is deprecated only for the job sources now do better.

**For rule lists**, move to `sources`. You gain declared formats, filtering, per-source
TTL and failure policy, and validation:

```yaml
# Before
metadata:
  config:
    - "{config_dir}/lists/blocklist.yml"

# After
metadata:
  sources:
    - upstream: "{config_dir}/lists/blocklist.yml"
```

Using `metadata.config` for a list logs a deprecation notice naming the files involved.

**For nested configuration documents**, keep using it. Sources produce *lists of
entries* — that is the whole shape of the pipeline — so a map-shaped document arrives as
one record rather than merging key by key. The nested `scoring` and `risk_levels` trees
that `VulnerabilityScore` loads still belong in `metadata.config`, and no deprecation
notice is emitted for them.

The two can be declared together. Sources contribute first, then files loaded through
`metadata.config`, then inline `config:`.

---

## Gotchas

**Sources are not config includes.** The top-level `configs:` key merges whole
configuration documents; `metadata.sources` produces a plugin's rule entries. A bare list
file added to `configs:` does nothing useful. See
[Loading & Includes](loading-and-includes.md).

**`where` narrows, `config:` widens.** Covered above, but it is the difference most likely
to surprise you.

**A large list is scanned linearly.** `IpAddress` walks its rule list per request. That is
fine for hundreds of entries; measure before pointing a plugin at many thousands, and
prefer `where` to cut a document down to the part you actually need.

**`headers` and `header_row` are different things.** `upstream.headers` are request
headers. `header_row` is the CSV/TSV option for whether the first row names the columns.
They sit at different levels for exactly that reason.

**A sync job needs the credentials too.** `bin/firewall-sources` is a separate process
from your application, so a token in your web server's environment is not automatically
present in cron. See [Syncing Rule Sources](../guides/syncing-sources.md#credentials).

**Declare `format` when the extension lies.** Inference reads the extension and falls back
to `txt`. An endpoint like `https://example.org/v1/ranges` serving JSON needs
`format: json` spelled out.
