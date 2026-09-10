# Reacting to Decisions

The firewall can tell your application what it decided about each request. Register any
[PSR-14](https://www.php-fig.org/psr/psr-14/) dispatcher and listen:

```php
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Firewall;

$dispatcher = /* any PSR-14 EventDispatcherInterface */;

$firewall = Firewall::create([__DIR__ . '/firewall.yml'], [], $dispatcher);
```

```php
// Registration is your dispatcher's business; this is Symfony's.
$dispatcher->addListener(RequestBlocked::class, function (RequestBlocked $event): void {
    if (!$event->isEnforced()) {
        return;                              // a dry run — nothing happened
    }

    $statsd->increment('firewall.blocked', [
        'rule' => $event->getPlugin()?->getName() ?? 'blocklist',
        'status' => (string) $event->getStatusCode(),
    ]);
});
```

Without a dispatcher nothing changes and nothing is dispatched. The parameter is optional and
trailing, so existing `Firewall::create()` calls are untouched.

## The events

| Event | Dispatched when |
|---|---|
| `RequestAllowed` | The request is going through — an allow rule matched, or nothing matched |
| `RequestBlocked` | A rule matched, or the client was already on the durable block list |
| `RequestChallenged` | A challenge rule matched and an interstitial is being served |
| `ChallengeSolved` | A submission verified and a pass token was minted |
| `ChallengeFailed` | A submission was refused |

All five extend `Kanopi\Firewall\Event\DecisionEvent`, so a dispatcher that matches on a
parent class can take every decision with one listener. Every event carries `getRequest()`.

### Telling similar things apart

Two events answer a question that looks like one question and is really two:

```php
$event->wasBypassed();       // RequestAllowed: a rule let it through, vs nothing objected
$event->wasAlreadyBlocked(); // RequestBlocked: the durable list, vs a rule matching now
```

`getPlugin()` returns `null` in both of those second cases, and that is the honest answer —
the block list records a key, not what put it there.

`RequestChallenged` and `ChallengeSolved`/`ChallengeFailed` both carry `getProvider()`, which
is a separate fact from the rule now that a rule can name its own provider. Comparing the two
counts is how you find a challenge that is too hard: served against solved.

## Listeners cannot change a verdict

By the time an event is dispatched the decision is made — and in `block` mode the response is
about to be written. The events carry no setters, implement no `StoppableEventInterface`, and
whatever a listener returns is discarded.

That is a deliberate limit, not an oversight. Two different things get asked of an extension
point:

| | "Let me contribute a rule" | "Tell me what you decided" |
|---|---|---|
| Mechanism | [Plugins](custom-plugins.md) | These events |

The first already had a good answer. The second had none — you parsed logs, or you subclassed
`Firewall` and overrode `protected` methods. This is the second, and nothing about
`PluginInterface` or `PluginManager` moved to add it.

## A listener that throws does not take the site down

Dispatch is wrapped. A metrics listener whose socket is unreachable, or a notifier whose queue
is full, gets its exception logged at `error`:

```
firewall.ERROR: A decision listener threw, and was ignored
  {"event":"Kanopi\\Firewall\\Event\\RequestBlocked","listener_error":"Connection refused", …}
```

…and the request carries on being blocked or allowed exactly as it would have been. A firewall
that fails because somebody's StatsD box is down has become the outage.

The corollary is that a listener is not a place to put anything the request depends on. If it
must happen, it does not belong here.

## One event per request, except in `log` mode

`block` and `exception` terminate at the first decision, so exactly one terminal event comes
out.

[`mode: log`](../configuration/global.md#mode) terminates nothing — that is what makes it a
dry run — so a single request can report a block list hit *and* end up allowed:

```
RequestBlocked   isEnforced() === false   wasAlreadyBlocked() === true
RequestAllowed
```

Check `isEnforced()` in any listener that notifies a human, opens a ticket or invalidates a
cache. A listener that only counts probably wants both, kept apart.

!!! note "Observe-mode rules never reach these events"

    A rule carrying [`metadata.mode: log`](../configuration/global.md#observing-one-rule-while-the-rest-enforce)
    is treated as *no match* by `PluginManager`, so the firewall never sees a decision to
    announce. Those matches are in the log, at `warning`, with `enforced: false`.

## Choosing a dispatcher

`kanopi/firewall` requires `psr/event-dispatcher` — three interfaces, no implementation — so
any PSR-14 dispatcher works and none is imposed on you.

`symfony/event-dispatcher` implements PSR-14 and is listed under `suggest` if you want one and
have no opinion:

```console
$ composer require symfony/event-dispatcher
```

Frameworks generally have one already: Laravel's, Symfony's, and Drupal's container-registered
dispatcher are all PSR-14.

## What this is groundwork for

There is an open question about whether the event dispatcher should *replace* `PluginManager`
rather than sit beside it. That would change `PluginInterface` — the contract every custom
plugin implements — and it is not a change to make on a hunch.

So: this is the additive half, and the answer is meant to come from evidence. After a couple
of releases, if every listener anyone wrote is reactive, the dispatcher never needed to be the
engine. If people are contorting listeners to try to influence verdicts, that is real evidence
the core should be event-driven — and it will be designed properly rather than arrived at by
accident.
