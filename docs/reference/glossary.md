# Glossary

Terms used throughout the firewall documentation, in alphabetical order.
Follow the links for configuration details and examples.

## Anomaly score

The total points added by matching OWASP Core Rule Set (CRS) rules, with each
contribution weighted by its CRS severity. The request-side score is compared
with `anomaly_thresholds.inbound` (default `5`) to decide whether to reject the
request; see [Anomaly scores and thresholds](../plugins/crs.md#anomaly-scores-and-thresholds).

## Bucket

In plugin execution, a bucket is a group of entries sharing a `response` value:
`allow`, `challenge`, or `block`, evaluated in that order as described in
[Plugin execution order](../plugins/index.md#plugin-execution-order).
In rate limiting, it means the shared request budget for a client address and
rule pattern, so paths matching the same wildcard spend the same budget; see
[Rate limit rules](rate-limiting.md#rate-limit-rules-by-category).

## Escalation stage

An entry in `global.blocking_escalation` that uses an offense count within a
look-back window to select a ban duration. Stages let repeated offenses lead
to longer bans, including a permanent ban with `duration: 0`; see
[Multiple offenses defense](../configuration/global.md#multiple-offenses-defense).

## Offense

A recorded event in a client's blocking history, used to decide whether a
later ban should escalate. The `offense` key sets the count required within an
escalation stage's window, rather than a rate limit's allowed request count;
see [Multiple offenses defense](../configuration/global.md#multiple-offenses-defense).

## Paranoia level

The CRS rule tier selected by `paranoia`, from `1` (the default) to `4`, with
higher levels enabling more aggressive checks. It controls which rules run,
while the anomaly threshold controls how much accumulated evidence triggers a
rejection; see [OWASP CRS configuration](../plugins/crs.md#configuration-example).

## Pass token

An expiring, HMAC-signed token issued after a successful challenge, bound to
the client IP, audience, and challenge provider. A valid token satisfies
challenges for that provider but does not bypass block plugins; see
[Challenge responses](../plugins/challenges.md).

## Plugin

A request evaluator, such as `IpAddress` or `RateLimit`, configured as an entry
under `plugins:` with its own rules and response. The same class can appear
in several entries with different settings; see
[Plugin architecture](../plugins/index.md).

## Preset

A reusable, preconfigured firewall rule set shipped in the package's
`presets/` directory. Include presets through `configs:` to compose their
plugin entries with your own configuration; see [Presets](../presets/index.md).

## Response

The action selected by a plugin entry's `response` value when it matches:
`allow` permits the request, `challenge` requires a solved challenge, and
`block` rejects it. These values also determine the execution group, before
`weight` orders entries within that group; see
[Plugin execution order](../plugins/index.md#plugin-execution-order).

## Rule

A configured matching condition, such as an IP range or URL condition, whose
syntax depends on the plugin evaluating it. The docs also use "rule" for a
whole configured plugin entry, which can be named with `metadata.name`; see
[Naming a rule](../plugins/index.md#metadataname-naming-a-rule).

## Sample

The time interval, in seconds, over which a rate-limit rule counts requests,
configured with `sample`. Together, `rate: 5` and `sample: 300` allow five
requests in five minutes, as shown in the
[Rate Limit configuration](../plugins/rate-limit.md#configuration-example).

## Source

A declaration under `metadata.sources` that reads a list from a file or URL
and converts it into entries a plugin can match. A source supplies rule data,
while the plugin entry supplies the response policy; see
[Rule sources](../configuration/sources.md).

## Upstream

The location a source reads from, configured with `upstream` as a file path,
URL, or a map containing a `url` and request options. It describes how to
fetch the data, while the surrounding source describes how to interpret it;
see [Upstreams](../configuration/sources.md#upstreams).

## Weight

The integer that orders plugin entries within a response group, with lower
values running first and `0` as the default. A lower weight cannot move a
block entry ahead of the allow group; see
[Plugin execution order](../plugins/index.md#plugin-execution-order).

## Window

The look-back period in seconds used by an escalation stage to count a
client's offenses, configured with `window`. Rate-limit documentation also
uses "window" for the request-counting interval configured with `sample`;
compare [Multiple offenses defense](../configuration/global.md#multiple-offenses-defense)
and [Rate Limit](../plugins/rate-limit.md).
