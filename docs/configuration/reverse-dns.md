# Reverse DNS

How the firewall makes the DNS lookups behind
[`verify: reverse-dns`](../plugins/user-agent.md#verifying-the-crawler-is-who-it-says), and
who it asks.

**By default nothing changes and nothing is sent to a third party.** A rule that verifies
crawlers uses PHP's own lookups, as it always has. A site can choose instead to send its
lookups to a **provider**, a public DNS-over-HTTPS service such as Cloudflare's or
Google's, whose lookups have a time limit. That choice is the site's to make, and this page
is here so it can be made knowingly.

## How verification works

A rule with `verify: reverse-dns` matches only when the client proves it is the crawler it
claims to be. That takes two lookups:

1. **Reverse lookup.** The client's address, written backwards under `in-addr.arpa` (or
   `ip6.arpa`), is looked up for its PTR records: the hostnames the address claims.
2. **Forward lookup.** Each hostname inside the rule's `verify_suffixes` is looked up for
   its addresses. The client is verified when one of them is the client's own address.

The forward lookup is what makes it proof. Whoever owns a block of addresses writes its PTR
records, so anyone can make their address claim `crawl-1-2-3-4.googlebot.com`. Only Google
can make that name resolve back.

Whatever makes the lookups, the firewall itself always:

- caches verdicts, so an address is looked up once per `verify_ttl`, not once per request.
  Verdicts belong to the resolver or provider that reached them, so switching starts afresh:
  a refusal from a lookup PHP couldn't finish isn't carried over to a provider
- collapses concurrent lookups for one address into one
- opens a circuit breaker after a slow lookup, so a struggling resolver cannot hold every
  worker. Each resolver or provider has its own breaker, so a slow one doesn't switch off
  rules that use another
- makes at most two forward lookups per address. The owner of an address writes its PTR
  records, so it could list any number of invented `googlebot.com` names. Without a cap,
  each would cost a lookup, and together they could trip the breaker for everyone
- checks each hostname is a hostname (letters, digits, hyphens and dots) before using it
- matches domains on a label boundary, so `evilgooglebot.com` never passes for
  `googlebot.com`
- makes the forward confirmation itself

So no resolver or provider can make an allow rule match more than DNS confirms.

## Choosing who makes the lookups

| | When to use it |
|---|---|
| **PHP's own lookups** (`SystemResolver`, the default) | The host has a local caching resolver, or sends nothing to third parties as a policy |
| **A built-in provider** (`cloudflare`, `google`) | Verification times out, or holds workers, because the host's resolver is slow and you can't run a local one |
| **Your own provider** | You run a DNS-over-HTTPS resolver, or your platform offers one |
| **Your own resolver class** | You need something DNS over HTTPS can't express, such as a platform API with its own authentication |

### PHP's own lookups

`gethostbyaddr()` and `dns_get_record()`, through the operating system's resolver. Nothing
to configure.

Neither function takes a timeout. Each is bounded only by the operating system's resolver,
commonly 5 seconds per nameserver with two attempts, so on a host without a local caching
resolver one slow nameserver can hold a worker for ten seconds or more. The circuit breaker
limits how many workers that happens to. It can't shorten the first ones. If that's what
you're seeing, use a provider.

Neither function can tell "no such record" from "the lookup failed", so both are treated as
no record and remembered for `verify_negative_ttl`.

### A provider

A provider is a named package: a resolver class and its options. Every built-in provider
is `DnsOverHttpResolver` with one operator's settings. Name one, and every verifying rule
uses it:

```yaml
global:
  reverse_dns:
    provider: cloudflare
```

**Naming a provider is the opt-in.** The library ships provider definitions, but uses none
of them until a site's own configuration names one. From that moment, the reverse-DNS
names of visitors' addresses are sent to that provider. See
[What a provider receives](#what-a-provider-receives).

Each lookup is limited to `timeout_ms`, connecting included, and fails with "could not tell"
when it runs out. A verification makes up to two lookups.

```yaml
global:
  reverse_dns:
    provider: cloudflare
    timeout_ms: 300        # the default; per lookup
```

A rule can use a different provider, or a different limit:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: allow
    metadata:
      verify: reverse-dns
      verify_suffixes: [.googlebot.com, .google.com]
      verify_provider: google     # otherwise the global provider
      verify_timeout_ms: 500      # otherwise the global timeout_ms
    config:
      - "bot.name:Googlebot"
```

### How each rule's resolver is chosen

1. the rule's `verify_provider`
2. otherwise, `global.reverse_dns.provider`
3. otherwise, `global.reverse_dns.resolver`, with `resolver_options`
4. otherwise, PHP's own lookups

| Setting | In a rule | Default |
|---|---|---|
| `global.reverse_dns.provider` | `verify_provider` | none |
| `global.reverse_dns.resolver` | — | `Kanopi\Firewall\Utility\ReverseDns\SystemResolver` |
| `global.reverse_dns.resolver_options` | — | none |
| `global.reverse_dns.timeout_ms` | `verify_timeout_ms` | `300`, for `DnsOverHttpResolver` |
| `global.reverse_dns.providers` | — | the built-ins |

With a provider selected, `verify_slow_threshold_ms` defaults to twice the timeout plus
50 ms, so the breaker doesn't trip on two lookups that worked. With PHP's own lookups it
stays at 250 ms.

### Rules the configuration has to follow

Each of these stops the firewall starting, and `bin/firewall-check --lint` reports it:

- **`provider` and `resolver` can't both be set.** It's ambiguous which you meant. Use
  `provider` for a provider, or `resolver` (with `resolver_options`) for a class.
- **A provider is used whole.** Its options can't be changed one at a time. To change any
  of them, [define your own provider](#defining-your-own-provider) under a new name.
- **A rule picks only a provider,** with `verify_provider`, and a limit, with
  `verify_timeout_ms`. A rule can't name a resolver class.
- **Built-in names are reserved.** Defining `providers.cloudflare` is an error, so
  `cloudflare` always means the definition the library ships.
- **A provider name has to exist.** `provider: cloudfare` names the providers that do.
- **`resolver` is a fully-qualified class name.** There are no short names.

`bin/firewall-doctor` reports which provider or resolver each verifying rule uses, and the
host its lookups go to.

## What a provider receives

With a provider selected, it receives:

- **The reverse-DNS name of the client's address**, such as `1.66.249.66.in-addr.arpa`.
  This is the visitor's IP address, written backwards.
- **The hostname being confirmed**, such as `crawl-66-249-66-1.googlebot.com`.

It receives these only for requests that a `verify: reverse-dns` rule asks about: requests
that match the rule and claim to be a crawler. Other traffic is never looked up. A verdict
is cached, so an address is sent at most once per `verify_ttl` (an hour) or
`verify_negative_ttl` (a day).

The request comes from your web server. The provider sees your server's address, not the
visitor's, except as written into the query name.

**Under the GDPR, an IP address is personal data.** Choosing a provider is the site
operator's decision: read the provider's terms and privacy policy below, and check whether
your privacy notice covers sending this to them. To send nothing to a third party, keep PHP's
own lookups (with a local caching resolver on the host), or
[define a provider](#defining-your-own-provider) that points at a resolver you run.

## What a provider costs

Measured on 2026-10-07 with `tests/Performance/bin/doh-bench.sh` (#480). Each case is the
same 25-process probe #245 used for PHP's own lookups: 25 workers verifying one uncached
address at the same instant, through a real `DnsOverHttpResolver`. Each figure is the range
over three runs. The degraded cases run against a local server whose delay can be set, so
they don't depend on how a public provider behaves that day.

### One verification

A verification is two requests: the reverse lookup, then the forward one.

| | Cloudflare | Google |
|---|---|---|
| First verification in a process (TLS handshake included) | 86–93 ms | 66–71 ms |
| Every verification after that (connection reused) | 24–29 ms | 19–40 ms |
| **Cached verdict** | **0.02 ms** | **0.02 ms** |

For comparison, #245 measured ~112 ms for a cold round trip with PHP's own lookups, and
~2 ms once the host's resolver has the answer. A PHP-FPM worker keeps its connection to the
provider between requests, so it pays for the TLS handshake once, not once per lookup.

### The time limit holds

With `timeout_ms: 300`:

| Provider | Slowest request | Verified |
|---|---|---|
| Never answers | 306–308 ms | 0 of 25 |
| Answers in 400 ms | 306–307 ms | 0 of 25 |
| Answers SERVFAIL | 17–22 ms | 0 of 25 |
| Answers in 140 ms | 302–308 ms | 2–4 of 25 |
| Answers in 50 ms | 121–124 ms | 9–11 of 25 |

A provider that stops answering costs the first worker `timeout_ms`, not the
operating system's resolver's 5–10 seconds. Everyone else gets a refusal in under a
millisecond (p50 under 0.9 ms in every case).

**The limit covers the whole request, connecting and the TLS handshake included.** A
provider that answers in 290 ms usually fails against a 300 ms limit (0–1 of 25 verified),
because the handshake pushes the first request over it. Set `timeout_ms` well above the
provider's usual latency, not just above it.

**The worst case is one limit per request**, and a verification makes at most three: the
reverse lookup and two forward ones. With the default limit that's 900 ms, over the 650 ms
breaker threshold, so a provider slow enough to cause it trips the breaker. One run saw
602 ms, with two requests each just under the limit.

### Concurrency, and waiting for the verdict

As #245 found with PHP's lookups, one worker makes the lookups and the others are refused
straight away. 25 workers on one address cost 2–8 requests (one to four verifications),
not 50. That refusal is what leaves 9–18 of 25 unverified even with a fast provider.

`verify_claim_wait_ms` fixes that, as it does for PHP's lookups, **but the wait has to
cover both requests**, not one:

| Provider answers in | `verify_claim_wait_ms` | Verified | Median request |
|---|---|---|---|
| 50 ms | `0` | 9–11 of 25 | 0.7 ms |
| 50 ms | `100` | 16–18 of 25 | 94–101 ms |
| 50 ms | `200` | **25 of 25** | 93–113 ms |
| 140 ms | `400` | **25 of 25** | 267–281 ms |

A rule of thumb: set the wait to a little over twice the provider's latency, plus the
handshake.

### Invented PTR records

An address whose PTR records list 15 invented `crawl-*.googlebot.com` names costs three
requests per verification: the reverse lookup and the two forward lookups the cap allows,
not 16. The slowest request was 16–34 ms, and nothing verified.

## Built-in providers

| Provider | Operator | Jurisdiction | Logs kept, per the operator | Terms | Privacy |
|---|---|---|---|---|---|
| [`cloudflare`](#cloudflare) | Cloudflare, Inc. | United States | Deleted within 25 hours | [Terms](https://www.cloudflare.com/policies/terms/) | [Privacy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/) |
| [`google`](#google) | Google LLC (Google Ireland Limited in Europe) | United States / Ireland | Temporary logs deleted within 24–48 hours | [Terms](https://developers.google.com/speed/public-dns/terms) | [Privacy](https://developers.google.com/speed/public-dns/privacy) |

What each operator says about logging is quoted from its own policy, on the date given. It is
the operator's statement, not something the library verifies.

**Every built-in provider is checked weekly.** A scheduled CI job runs
`tests/Live/check-reverse-dns-providers.php`, which uses each provider exactly as a site
would, pinned address included. It runs a reverse lookup of a Googlebot address, the forward
lookup, a name with no record, and a full verification. If one fails, it opens an issue, so a
provider that changes or retires its API (as Quad9 retired its JSON service) is noticed by
the project before sites are affected. You can run the same check yourself, to test a
provider from your own network.

### `cloudflare`

#### Operator and jurisdiction

Cloudflare, Inc., in the United States, through its public 1.1.1.1 resolver.

#### Endpoint and connect address

`https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}`, connecting
to `1.1.1.1`. The certificate is checked against `cloudflare-dns.com`.

#### JSON API

Documented:
[Using DNS over HTTPS with JSON](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/).

#### What is sent

The reverse-DNS name of the client's address, and the hostname being confirmed. See
[What a provider receives](#what-a-provider-receives).

#### What the operator says it logs

From the [1.1.1.1 resolver privacy policy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/),
read on 2026-10-05:

- Logs include the query name and type, and the answer. Cloudflare says "All Public
  Resolver Logs are deleted within 25 hours", except aggregated statistics.
- The source address is truncated (the last octet of IPv4, the last 80 bits of IPv6) and
  the truncated address deleted within 25 hours. The full address "will not be stored in
  non-volatile storage". In this case the source address is your web server's.
- Cloudflare says it "will not sell or share Public Resolver users' personal data with
  third parties", nor use it to target advertising.
- Cloudflare says an accounting firm audits these practices.

#### Terms

The [1.1.1.1 terms of use](https://developers.cloudflare.com/1.1.1.1/terms-of-use/) apply
Cloudflare's [Website and Online Services Terms of Use](https://www.cloudflare.com/policies/terms/),
which name the 1.1.1.1 resolver as a free Online Service. Read on 2026-10-05:

- No restriction on commercial use.
- Section 7: no use that could "overburden" the service, and no exceeding or circumventing
  its limits.
- Section 4: Cloudflare may suspend access "at any time, with or without notice".
- Section 10: provided "as is", without warranty.
- Attribution is required of ISPs and network-equipment makers that integrate the resolver.

#### Rate limits

Not published.

#### Quirks

- Answers with `Content-Type: application/dns-json`.
- Echoes the query name without a trailing dot, and returns hostnames with one.
- No record: `Status: 3`, with no `Answer`.

#### Last verified

2026-10-05: the PTR lookup, the forward lookup and a name with no record all answered
correctly.

### `google`

#### Operator and jurisdiction

Google LLC in the United States, and Google Ireland Limited for users in Europe, through
Google Public DNS.

#### Endpoint and connect address

`https://dns.google/resolve?name={{ dns.name }}&type={{ dns.type }}`, connecting to
`8.8.8.8`. The certificate is checked against `dns.google`.

#### JSON API

Documented:
[JSON API for DNS over HTTPS](https://developers.google.com/speed/public-dns/docs/doh/json).

#### What is sent

The reverse-DNS name of the client's address, and the hostname being confirmed. See
[What a provider receives](#what-a-provider-receives).

#### What the operator says it logs

From [Google Public DNS: Your privacy](https://developers.google.com/speed/public-dns/privacy),
read on 2026-10-05:

- Temporary logs hold the requesting address and the query. For DNS over HTTPS they also
  hold the `Content-Type` and `Accept` headers. Google says these are deleted within 24 to
  48 hours, though it may keep them longer solely to address security and abuse. Here the
  requesting address is your web server's.
- Permanent logs hold anonymised, aggregated data, such as the domain name, the request
  type and city- or region-level location, with no full address.
- Google says it does not use this personal data to target advertising.

#### Terms

[Google Public DNS terms](https://developers.google.com/speed/public-dns/terms) apply the
Google APIs Terms of Service. Read on 2026-10-05, no restriction on commercial use.

#### Rate limits

Published: Google
[rate-limits each client](https://developers.google.com/speed/public-dns/docs/isp) by IPv4
address or IPv6 /64, and may throttle one that exceeds the limits. Cached verdicts keep a
verifying site far below them.

#### Quirks

- Answers with `Content-Type: application/json`.
- Adds a `Comment` field to some answers. It's ignored.
- No record: `Status: 3`, with an `Authority` SOA record in place of `Answer`.

#### Last verified

2026-10-05: the PTR lookup, the forward lookup and a name with no record all answered
correctly.

## Other public resolvers

Tested on 2026-10-05 and 2026-10-06, and not built in. A provider is built in only when the
operator documents its JSON API and its terms clearly allow automated lookups from a web
server without an account.

| Resolver | Result |
|---|---|
| DNS.SB | Answers JSON correctly, but doesn't document its JSON API. Its [terms](https://dns.sb/tos/) make the service free for "personal and non-commercial use", and say "commercial use requires prior authorization", including integrating it into products |
| AdGuard (its unfiltered host) | Answers JSON correctly, but doesn't document its JSON API. Its [EULA](https://adguard-dns.io/eula.html) allows the public servers without an account, but forbids using "automated agents… to generate automated searches, requests", which arguably covers a web server's lookups |
| NextDNS | Answers JSON correctly, but doesn't document its JSON API. Its [terms](https://nextdns.io/terms) are written for subscribers, and don't say whether use without an account is allowed |
| Quad9 | Answers only the standard binary format. Its JSON service [was retired on 5 May 2025](https://quad9.net/news/blog/quad9-json-based-dns-service-retires-5-may-2025/) |
| OpenDNS, Control D | Answer only the standard binary format |

Any of the JSON ones can still be [defined as your own provider](#defining-your-own-provider).
Check the operator's terms for your own use first: that's your agreement with them, and the
library doesn't make it for you.

`DnsOverHttpResolver` reads JSON. Resolvers that only speak the standard binary format
(RFC 8484) need support that isn't written yet.

## Defining your own provider

In the same shape the built-ins have: a resolver class and its options.

```yaml
global:
  reverse_dns:
    provider: internal
    providers:
      internal:
        resolver: "Kanopi\\Firewall\\Utility\\ReverseDns\\DnsOverHttpResolver"
        options:
          endpoint: "https://resolver.internal/dns-query?name={{ dns.name }}&type={{ dns.type }}"
          address: 10.0.0.53
          response: dns-json
```

A provider name is lower-case letters, digits, `-` and `_`.

### `DnsOverHttpResolver` options

| Option | Required | Default | |
|---|---|---|---|
| `endpoint` | yes | | The URL template. See [The endpoint template](#the-endpoint-template) |
| `address` | no | none | The IP to connect to, so the endpoint's own host is never looked up through the operating system's resolver. The certificate is still checked against the host |
| `headers` | no | `Accept: application/dns-json` | Request headers |
| `response` | no | `dns-json` | How to read the answer. See [Reading the response](#reading-the-response) |
| `timeout_ms` | no | `300` | Usually set with `global.reverse_dns.timeout_ms` |

**Set `address` whenever the endpoint names a host.** Without it, curl looks the host up
through the operating system's resolver before every new connection. That lookup has no
time limit, which is the stall a provider is meant to remove. `firewall-doctor` warns about
it.

Requires PHP's curl extension.

### The endpoint template

One template makes both lookups, so the parts that change between them are placeholders:

| Placeholder | Reverse lookup | Forward lookup |
|---|---|---|
| `{{ dns.name }}` | `1.66.249.66.in-addr.arpa` | the hostname being confirmed |
| `{{ dns.type }}` | `PTR` | `A`, or `AAAA` for an IPv6 client |
| `{{ client.ip }}` | `66.249.66.1` | empty |
| `{{ client.ip_arpa }}` | `1.66.249.66.in-addr.arpa` | empty |

A single template must contain `{{ dns.name }}` and `{{ dns.type }}`. A template with
`type=PTR` written into it couldn't make the forward lookup, and without the forward lookup
verification proves nothing. Values are URL-encoded as they are substituted.

A resolver that needs different URLs for the two lookups takes a map, on one host:

```yaml
endpoint:
  ptr: "https://resolver.internal/ptr/{{ client.ip }}"
  forward: "https://resolver.internal/lookup?name={{ dns.name }}&type={{ dns.type }}"
```

`ptr` must contain `{{ dns.name }}`, `{{ client.ip }}` or `{{ client.ip_arpa }}`, and
`forward` must contain `{{ dns.name }}`.

Refused at startup:

- anything but `https://`
- an unknown placeholder, such as `{{ dns.nme }}`
- a placeholder in the host
- a map whose two URLs use different hosts or ports

### Reading the response

`dns-json` reads the layout Cloudflare and Google share:

```json
{"Status": 0, "Answer": [{"name": "1.66.249.66.in-addr.arpa", "type": 12, "data": "crawl-66-249-66-1.googlebot.com."}]}
```

It's shorthand for this layout:

```yaml
response:
  format: json
  status: Status          # the DNS result code: 0 is an answer, 3 is no such name
  select: "Answer.*"      # every record, not only the first
  type: type              # keep the records of the type the lookup asked for
  template: "{value[data]}"
```

A resolver with its own format gives a layout of its own. `select` and `where` use the
path syntax and filter operators of [Rule Sources](sources.md), and `template` uses their
`{value[...]}` placeholders:

```yaml
response:
  format: json
  template: "{value[hostname]}"
  none_http: [404]        # this API means "no record" by answering 404
```

| Key | Required | |
|---|---|---|
| `format` | yes | `json` |
| `template` | yes | Which field of each record holds the hostname or address |
| `select` | no | Path to the records. Without it, the body is the record, or the list of records |
| `where` | no | Filters, as a Source's `where` |
| `type` | no | Field holding each record's type, as a name (`PTR`) or a number (`12`). Records of other types are dropped, so an alias (CNAME) record never stands in for an address |
| `status` | no | Field holding the DNS result code |
| `none_http` | no | HTTP status codes that mean "no record" |

How an answer is read:

| Outcome | With `status` | Without `status` |
|---|---|---|
| **Records found** | code 0, and records of the expected type | HTTP 200, and records |
| **No record**, remembered for `verify_negative_ttl` | code 3, or code 0 with no record of the expected type | HTTP 200 with no records, or a code in `none_http` |
| **Could not tell**, remembered for 60 seconds | any other code | any other HTTP status, a body that isn't JSON, a timeout |

"Could not tell" refuses the request, because this guards an allow rule. It is remembered
only briefly: long enough that a client whose own DNS keeps failing can't make every
request pay for a lookup, and short enough that one network blip doesn't refuse the real
crawler for a day.

At most 64 KB of a response, and 50 records, are read.

## Writing your own resolver

For lookups DNS over HTTPS can't express. Implement
`Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface`:

```php
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

final class PlatformDnsResolver implements ReverseDnsResolverInterface
{
    public function __construct(private readonly array $options = [])
    {
    }

    public function reverse(string $ip): LookupResult
    {
        // ... ask the platform, with a time limit ...
        return LookupResult::answer(['crawl-66-249-66-1.googlebot.com']);
    }

    public function forward(string $hostname, string $type): LookupResult
    {
        // $type is 'A' or 'AAAA', matching the client's address
        return LookupResult::none();
    }
}
```

Name it directly:

```yaml
global:
  reverse_dns:
    resolver: "App\\Firewall\\PlatformDnsResolver"
    resolver_options:
      base_url: "https://dns.platform.internal"
```

Or package it as a provider, so rules can pick it with `verify_provider`:

```yaml
global:
  reverse_dns:
    providers:
      platform:
        resolver: "App\\Firewall\\PlatformDnsResolver"
        options:
          base_url: "https://dns.platform.internal"
```

**What a resolver returns:**

- `LookupResult::answer($values)`: the hostnames, or the addresses.
- `LookupResult::none()`: there is no such record.
- `LookupResult::unknown($reason)`: the lookup couldn't say either way.

**A resolver returns data, never a verdict.** The firewall still validates every value,
checks the domain and makes the forward confirmation, so a resolver can't verify a client
DNS wouldn't.

**Every lookup must have a time limit.** The library can't put one on your code. It times
each call and opens the circuit breaker when one is slow, but that's a backstop, not a
limit.

**A resolver that throws** is treated as "could not tell". The error is logged, and listed
by `Firewall::getDegradedBackends()`.

**A constructor parameter typed `array`** receives the options, from `resolver_options` or
the provider's `options`. `global.reverse_dns.timeout_ms` is passed only to
`DnsOverHttpResolver`; your own resolver takes its limit in its own options.

## Troubleshooting

**"Reverse DNS lookup was slow - skipping verification for a while".** A verification took
longer than `verify_slow_threshold_ms`, so the breaker skips verification for five
minutes, and verified rules match nobody new until it closes. With PHP's own lookups, the
host's resolver is slow: run a local caching resolver, or select a provider. With a
provider, raise `timeout_ms`, or check that the server can reach the provider.

**A verified rule never matches.** Run `bin/firewall-doctor`, which shows each verifying
rule's resolver and where its lookups go. Then check debug logs for "could not say either
way", which means timeouts or errors reaching the provider, or a certificate that doesn't
match the endpoint's host, usually an `address` that belongs to a different provider.

**The firewall won't start, naming `global.reverse_dns`.** The message lists every problem.
`bin/firewall-check --lint` reports the same ones without starting anything.
