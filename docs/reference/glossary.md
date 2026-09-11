# Glossary

Every term used across these docs, in one place. Each entry is a working definition
with a link to the page that explains it properly.

## A

### Anomaly score

The running total a request accumulates as CRS rules match it, weighted by each
rule's severity — critical contributes 5, error 4, warning 3, notice 2. When the
total reaches `anomaly_thresholds.inbound`, CRS rule 949110 rejects the request.
See [OWASP CRS](../plugins/crs.md).

## B

### Bucket

A rate-limit counter, keyed by a client identifier and scoped to one rule. The
counter lives in storage for the length of its `sample`, then expires. See
[Rate Limit](../plugins/rate-limit.md).

## E

### Escalation stage

One entry in `blocking_escalation`, keyed to an offense count. A client at three
offenses gets whatever the third stage specifies, so a penalty can tighten from a
temporary ban to a permanent block. See
[Global Settings](../configuration/global.md).

## O

### Offense

A recorded block against a client, counted by the storage backend and used to
drive [escalation stages](#escalation-stage). See
[Storage](../configuration/storage.md).

## P

### Paranoia level

A CRS setting from 1 to 4 trading detection coverage against false-positive rate.
Level 1 is the recommended starting point; each step up adds more aggressive rule
tiers. See [OWASP CRS](../plugins/crs.md).

### Pass token

An HMAC-signed, IP-bound credential issued when a visitor solves a challenge. It
short-circuits later `response: challenge` rules from the same provider until it
expires. See [Challenge Responses](../plugins/challenges.md).

### Plugin

A request evaluator. Each one inspects one property of the request — IP, country,
user agent, URL, ASN, rate — and declares whether it matched. See
[Plugins](../plugins/index.md).

### Preset

A ready-made rule set shipped inside the package, included in one line through
`configs:`. Presets are versioned, so `composer update` can change what gets
blocked. See [Presets](../presets/index.md).

## R

### Response

The action a matching rule takes: `block`, `challenge`, `log`, or `allow`. Plugins
declare it per rule, and a global setting can cap it separately. See
[Global Settings](../configuration/global.md).

### Rule

One entry in a plugin's `config:` list — a pattern or condition to test, plus the
[response](#response) to take when it matches. See
[Managing Rules](../guides/managing-rules.md).

## S

### Sample

The length of the sliding window a rate-limit rule counts over, in seconds. A rule
of 5 requests per `sample: 300` allows five in any five-minute span. See
[Rate Limit](../plugins/rate-limit.md).

### Source

A remote list of rules fetched on a schedule — an IP blocklist, for example —
rather than written into your config by hand. See
[Rule Sources](../configuration/sources.md).

## U

### Upstream

The service a plugin asks for an answer: AbuseIPDB for reputation, MaxMind for
geolocation, the CDN edge for a bot score. Plugins are written to fail open when
an upstream is unreachable, so an outage does not take the site down with it.

### Weight

A rule's sort order within a [response](#response) group. Lower weights evaluate
first, which is what makes a deliberately narrow exception outrank a broad block.
See [Managing Rules](../guides/managing-rules.md).

### Window

See [Sample](#sample).
