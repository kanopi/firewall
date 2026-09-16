# Add a Challenge

`response: challenge` serves an interstitial when a rule matches, instead of refusing the
request. A visitor who solves it is issued a pass token and continues; a bot generally does
not.

This page gets one running. For how the token works, what each provider depends on, and the
interface for writing your own, see [Challenge Responses](../plugins/challenges.md).

## 1. Configure the challenge block

```yaml
challenge:
  provider: math                # start here; see below for the alternatives
  secret: '%env(FIREWALL_CHALLENGE_SECRET)%'   # REQUIRED — long, random, from the environment
  cookie_name: fw_challenge_pass
  header_name: X-Firewall-Challenge
  path: /_firewall/challenge    # where a submission is recognised
```

`challenge.secret` is **required** as soon as any rule uses `response: challenge`. Startup
fails with `ConfigurationException` if it is empty — the firewall will not fall back to
unsigned tokens.

!!! warning "The submission path must reach the firewall"

    `path` is where the interstitial POSTs its answer. If your application routes that URL
    itself, or the firewall runs after your router, a challenged visitor can never solve and
    is locked out for as long as the rule matches.

### A host served from a subdirectory

`path` is matched against `Request::getPathInfo()`, which has the base path **stripped**. The
form action needs it. On a site at `example.com/` those are the same string; on one at
`example.com/app/` they are not:

| | |
|---|---|
| Matched against `getPathInfo()` | `/_firewall/challenge` |
| Rendered as the form action | `/app/_firewall/challenge` |

The base path is taken from the request, so **this needs no configuration** — `path` keeps its
one job and the form action is built from it.

Set `submit_url` only when the browser's view of the URL and the application's differ by
something the request cannot work out, which in practice means a proxy that rewrites paths:

```yaml
challenge:
  path: /_firewall/challenge
  submit_url: https://edge.example.com/challenge
```

!!! note "Fixed in 2.29.0"

    Before that, `path` was used for both and a subdirectory install could not be configured
    out of it: the form posted to the web server root, the answer never reached the firewall,
    no pass token was minted, and the visitor was challenged again on the next request. A
    challenge rule refused **every human who tried to satisfy it**, while a bot that ignored
    the interstitial was unaffected — and it presented as a broken provider rather than a
    path problem.

## 2. Point a rule at it

Change the rule's `response` from `block` to `challenge`:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: challenge
    weight: -10
    enable: true
    metadata:
      default_expiration_time: 3600   # how long the pass token lasts, in seconds
    config:
      - "asn:AS14618"                 # challenge AWS traffic
```

## 3. Check it before you enforce it

```console
$ firewall-check config/firewall.yml --ip=203.0.113.5 --url=/ --explain
```

A `CHALLENGED` verdict names the rule that asked for it. This runs against a throwaway
store, so checking cannot ban the address you are asking about.

## Which provider

The choice is mostly about what you are willing to depend on:

| | Depends on | Visitor does | Use when |
|---|---|---|---|
| `math` | nothing | answers a sum | You need it to work under a strict CSP, offline, or with no third party involved |
| `altcha` | nothing external | nothing — the browser solves a proof-of-work | You want bots to pay CPU without a visitor clicking anything |
| `turnstile` | Cloudflare, reachable from the browser *and* your server | ticks a widget | You want the strongest bot resistance and already use Cloudflare |
| `recaptcha` | Google, same reachability | ticks a box, or nothing on v3 | You already run reCAPTCHA elsewhere |

Start with `math` if you are unsure. It has no external dependency, so there is nothing to
configure and nothing to break, and swapping it later is a one-line change.

A rule can override the default with `metadata.challenge_provider` — see
[Per-plugin providers](../plugins/challenges.md#per-plugin-providers). A pass token is only
worth the provider it was earned on, so a visitor who solved a `math` challenge will still be
challenged by a `turnstile` rule.

## Then what

| | |
|---|---|
| See it end to end in a browser | [Demo Application](../getting-started/demo.md) |
| How the pass token is signed, bound and delivered | [Challenge Responses](../plugins/challenges.md) |
| Stop a solution being solved once and reused | [Single-use solutions](../plugins/challenges.md#single-use-solutions) |
| Write your own provider | [Writing a custom provider](../plugins/challenges.md#writing-a-custom-provider) |
| Catch the challenge exceptions in your app | [Exceptions](../reference/error-handling.md) |
