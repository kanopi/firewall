# Export Metrics

`response: block` fired 4,000 times yesterday. Was that one bot, or four thousand customers?

The firewall dispatches [decision events](decision-events.md) for everything it decides, and
this turns those into counters a monitoring system already knows how to graph. Two exporters
ship, and the metric names are fixed so two installations produce the same series.

!!! info "The dashboard is not here, deliberately"

    A Grafana JSON file or a CMS admin screen changes on its own cadence and nothing on the
    request path should carry it — the same reasoning that put the framework middleware and
    the CMS packages in their own repositories. This is the library-side half: the series, and
    two ways to get them out.

## 1. Pick an exporter

| Deployment | Use |
|---|---|
| PHP-FPM, mod_php, classic share-nothing | `StatsdRecorder`. **Push, do not scrape** |
| A long-lived worker — RoadRunner, Swoole, FrankenPHP | `PrometheusRecorder`, held across requests |
| Anything else that wants a scrape endpoint | `PrometheusRecorder` plus your own shared store |

Prometheus scrapes; PHP, classically, forgets. Under PHP-FPM every request is a fresh process,
so a counter incremented during a request is gone before anything can scrape it, and a scrape
lands in a process that has seen almost nothing. That is the execution model rather than a
limitation of this library — every PHP Prometheus client works around it with shared memory or
a shared store. If you are on FPM, StatsD is the honest answer.

## 2. Wire the listener

PSR-14 dispatchers match on the **concrete** event class, so registering for `DecisionEvent`
catches nothing. `eventClasses()` is the list to loop over — and it is tested against the
shipped events, so a new event type cannot quietly go uncounted:

```php
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Metrics\DecisionMetricsListener;
use Kanopi\Firewall\Metrics\StatsdRecorder;

$listener = new DecisionMetricsListener(new StatsdRecorder('127.0.0.1', 8125));

foreach (DecisionMetricsListener::eventClasses() as $event) {
    $dispatcher->addListener($event, $listener);
}

$firewall = Firewall::create(['firewall.yml'], [], $dispatcher);
```

## 3. What you get

| Metric | Labels | Answers |
|---|---|---|
| `firewall_requests_total` | `decision`, `rule`, `enforced` | Block rate by rule, over time |
| `firewall_challenges_total` | `provider`, `outcome` | Challenge solve rate |
| `firewall_challenge_failures_total` | `provider`, `reason` | Whether failures are wrong answers or a broken provider |

`decision` is one of `allowed`, `blocked`, `challenged`, `recorded`, `redirected`, `marked`.
`outcome` is `issued`, `solved` or `failed` — **issued and solved are counted separately and
on purpose**, because `ChallengeSolved` only ever fires for the visitors who came back. One
number cannot tell "this rule is working perfectly" from "this rule is only catching bots that
never retry", and the ratio can.

```promql
# Solve rate, by provider
  sum(rate(firewall_challenges_total{outcome="solved"}[1h])) by (provider)
/ sum(rate(firewall_challenges_total{outcome="issued"}[1h])) by (provider)
```

### `enforced`, and the two decisions where it always reads `false`

`enforced="false"` means the firewall decided and did not act — a [`mode: log`](../configuration/global.md) dry run.

`recorded` and `marked` always read `false`, and that is not a bug. Both let the request
through: one writes to the block list, the other annotates. Filtering `enforced="true"` gives
you **what the firewall did to traffic**, and neither of those is one of those things. The
cost is that on those two buckets the label cannot also tell a dry run from a real one.

## Label cardinality, which is the thing to get right

Every label here is bounded. `rule` comes from your configuration, `provider` from a fixed
set, and `decision`, `outcome`, `reason` and `enforced` are enumerations.

**Nothing derived from a request is a label** — not the client address, not the path, not the
user agent. The obvious first draft of a firewall exporter labels by client IP, and that is
the draft that takes a Prometheus server down: one series per address, forever, on the
component that exists to be hit by addresses you did not expect.

The questions those labels would answer live in the [decision log](send-logs-somewhere.md),
where a row per decision is a query rather than a time series. That is also where the
**false-positive signal** lives — rules that fire once for an address that then behaves
normally for a week — because it cannot be computed from a counter at all.

Both exporters cap anyway, and count the excess into an `other` bucket rather than dropping
it: a series that stops incrementing looks like traffic that stopped, and "nothing is
happening" and "I stopped telling you" must not look the same.

| Cap | Default | Why it exists |
|---|---|---|
| `DecisionMetricsListener`, `rule` values | 200 | The mistake this library could make |
| `PrometheusRecorder`, series per metric | 2000 | The mistake a host could make reusing these recorders |

Set either to `0` if you have measured your own and would rather see all of them.

## A metrics backend must never slow a request

`StatsdRecorder` sends over **UDP only**, and the missing TCP mode is a refusal rather than an
omission. A TCP connect to a host that is up but not answering *waits* — so a metrics box
having a bad afternoon becomes a slow site, for every visitor. UDP has no handshake, no
acknowledgement and no retry: the datagram goes to the local network stack and the call
returns. The socket is opened once and set non-blocking, so even a full send buffer drops the
datagram rather than waiting for room.

Losing a packet costs one increment. Waiting for one costs a request.

[`Firewall::announce()`](decision-events.md#a-listener-that-throws-does-not-take-the-site-down)
already catches a listener that *throws*, so an exception cannot become an outage — but
nothing catches a listener that *hangs*, and a slow site is harder to diagnose than a failed
one.

An agent that cannot be reached is recorded **once per process** to
[`getDegradedBackends()`](../reference/error-handling.md#checking-that-a-backend-can-reach-its-server),
where a status page sees it, rather than a log line per request. It then stops trying, because
retrying would put the connect back on the request path. Metrics silently not arriving is
exactly the kind of thing nobody notices for a month.

## Serving a scrape endpoint

`PrometheusRecorder::render()` produces the exposition text. Serving it is your routing, your
authentication and your access control — a library that opened a port would be a library that
opened a port on somebody's firewall host.

```php
$recorder = new PrometheusRecorder();
// ... requests happen, in a long-lived worker ...

header('Content-Type: text/plain; version=0.0.4');
echo $recorder->render();
```

For a share-nothing deployment that still wants a scrape target, `snapshot()` and `load()` are
plain arrays to put in APCu, a file, or whatever the deployment already has:

```php
$recorder = new PrometheusRecorder();
$recorder->load(apcu_fetch('firewall_metrics') ?: []);
// ... handle the request ...
apcu_store('firewall_metrics', $recorder->snapshot());
```

They are arrays rather than an interface on purpose: the right store is entirely your
business, and anything chosen here would be wrong somewhere.

**Counters add and gauges replace** when a snapshot is loaded. Two workers that each saw 40
requests saw 80, so taking the larger would lose half of them; the sum of two readings of "how
many are in flight" is not a number about anything.

## Writing your own

`MetricsRecorderInterface` is two methods — `increment()` and `gauge()` — and that is all it
will be. An exporter interface grows histograms, summaries, timers and quantiles if you let
it, and each one is something every implementation then has to support or fake.

```php
final class MyRecorder implements MetricsRecorderInterface
{
    public function increment(string $metric, array $labels = [], int $by = 1): void { /* … */ }
    public function gauge(string $metric, array $labels = [], float $value = 0.0): void { /* … */ }
}
```

It must not throw, must not block, and must not wait for a remote service to answer. It is
called on the request path.
