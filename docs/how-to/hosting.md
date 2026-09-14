# Host Recipes

Most deployment friction is host-shaped, and almost all of it is configuration. Four questions
decide whether the firewall behaves correctly on a given host:

| | Why it matters if you get it wrong |
|---|---|
| **What sits in front of it?** | Every IP rule and rate limit reads the client address. Get this wrong and either they all see the proxy's address, or a visitor can forge their own |
| **Where can it write?** | The block list and rate-limit counters need a durable, writable location. A read-only filesystem is silent until a rule tries to record |
| **Where do logs go?** | A firewall nobody can read the logs of is a firewall nobody can tune |
| **What backend is already there?** | Most hosts hand you a database or a Redis you are already paying for |

This page answers them for the hosts we have recipes for, and — more usefully — shows how to
**get the answers out of your own environment** for a host that is not listed.

!!! note "Two of these hosts are worked examples; the rest are a procedure"

    Pantheon ships as presets in this repository, and plain nginx is the baseline everything
    else varies from. For other hosts, the values below say *what to look for* rather than
    quoting proxy ranges and mount paths that belong to a vendor and change without telling
    us. The five-minute procedure is a more reliable answer than a table that has gone stale,
    and everything it uses ships in the box.

## Find your host's answers in five minutes

### 1. What does your host actually send?

Drop this somewhere it can be reached once, and then remove it:

```php
<?php
// whats-in-front.php — delete after reading.
header('Content-Type: text/plain');

echo "REMOTE_ADDR: ", $_SERVER['REMOTE_ADDR'] ?? '(none)', "\n\n";

foreach ($_SERVER as $key => $value) {
    if (str_starts_with($key, 'HTTP_') && preg_match('/FORWARD|REAL_IP|CLIENT|TRUE_IP|CF_/i', $key)) {
        echo $key, ': ', $value, "\n";
    }
}
```

Visit it from your phone on mobile data — a network whose address you can recognise and that
is definitely not your office.

- **`REMOTE_ADDR` is your phone's address and there are no forwarding headers** — nothing is in
  front. Set `behind_proxy: false` and you are done. (`firewall-doctor` still reports this as
  unverified: `setTrustedProxies()` is called by your application's bootstrap, which a
  command-line process never runs, so it says so rather than implying it checked.)
- **`REMOTE_ADDR` is an internal or unfamiliar address, and a forwarding header holds your
  phone's** — that address is your proxy, and that header is the one to trust.
- **Two forwarding headers disagree** — read the [trusted proxies](#trusted-proxies-when-the-host-publishes-no-ranges)
  section carefully; this is the case where guessing is expensive.

### 2. Ask the firewall what it can see

```bash
vendor/bin/firewall-doctor firewall.yml
```

It reports whether storage is writable, whether the database is reachable, whether trusted
proxies are configured, and what it cannot verify from a command line. See
[Diagnosing](diagnosing.md).

### 3. Confirm a real request resolves to the right address

```bash
vendor/bin/firewall-check --config=firewall.yml --ip=203.0.113.5 --url=/ --explain
```

That evaluates a synthetic request; the address you pass is the address the rules see. Once
trusted proxies are set, the snippet from step 1 is what confirms a *real* request agrees.

## Trusted proxies, when the host publishes no ranges

Symfony only honours `X-Forwarded-For` after `Request::setTrustedProxies()`, and many hosts do
not publish a stable CIDR list. Two tokens cover that, and they are not equivalent:

```php
use Symfony\Component\HttpFoundation\Request;

// Trust whatever connected to us.
Request::setTrustedProxies(['REMOTE_ADDR'], Request::HEADER_X_FORWARDED_FOR);

// Trust any RFC1918 / loopback peer.
Request::setTrustedProxies(['PRIVATE_SUBNETS'], Request::HEADER_X_FORWARDED_FOR);
```

!!! danger "`REMOTE_ADDR` is only safe when nothing else can reach the origin"

    It means *trust the forwarding header from whoever connected*. Behind a platform whose
    load balancer is the only route in, that is exactly right and needs no range list. If your
    origin also answers on its own public address, it means anyone who finds that address can
    send `X-Forwarded-For: 1.2.3.4` and become whoever they like — which walks straight past
    allow lists and per-IP rate limits.

    So pair it with locking the origin down: a host firewall, a security group, or an
    `allow`/`deny` block in the web server that only admits the platform's own range. If you
    cannot do that, get the real CIDR list.

`PRIVATE_SUBNETS` is the safer default when the proxy is a sidecar or an in-cluster load
balancer, because a private address cannot be reached from the internet in the first place.

Whatever you choose, assert the deployment fact so a mistake is loud:

```yaml
global:
  behind_proxy: true
  require_trusted_proxies: true    # refuse to start without them
```

See [Trusted Proxies](../configuration/global.md#trusted-proxies) for what each setting does.

## Pantheon

Two presets do the wiring, and they read Pantheon's own environment rather than hard-coding
anything:

```yaml
configs:
  - "{presets_dir}/storage-pantheon.yml"    # block list in the site database
  - "{presets_dir}/logging-pantheon.yml"    # logs to /files/private/firewall.log
```

| | |
|---|---|
| **In front** | Fastly. Pantheon does not expose arbitrary VCL, so the [GeoLocation edge headers](../plugins/geolocation.md) available on other Fastly deployments are not there |
| **Storage** | The site database, via `PRESSFLOW_SETTINGS` — no extra service to provision |
| **Logs** | `/files/private/`, which is writable and not web-served |
| **Rate limits** | The same database, or Redis on plans that include it |

The `%env(safe:…)%` chain in `storage-pantheon.yml` is worth reading if you are writing a
recipe for another host: it pulls credentials out of a JSON blob and falls back cleanly when
the variable is absent, so including that preset off-platform degrades to the default storage
instead of crashing. See [Environment Variables](../configuration/environment-variables.md).

!!! warning "`logging-pantheon.yml` is not safe to include off-platform"

    It writes to `/files/private/`, which exists on Pantheon and nowhere else. Included
    anywhere it does not, Monolog cannot create the directory and **the firewall does not
    start at all**:

    ```
    UnexpectedValueException: There is no existing directory at "/files/private"
    and it could not be created: Read-only file system
    ```

    Guard it behind whatever tells your code which environment it is in, rather than
    including it unconditionally in a config shared with local development.

    That a log destination can stop the firewall from starting at all is
    [#346](https://github.com/kanopi/firewall/issues/346); everywhere else in the library, a
    backend that cannot be reached degrades and is reported.

## Plain nginx + php-fpm

The baseline every other host varies from. Nothing is in front unless you put it there:

```yaml
global:
  behind_proxy: false        # nothing between the internet and nginx

storage:
  type: "\\Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/lib/firewall/blocked.data
    offense_file: /var/lib/firewall/offenses.data

logger:
  - class: "\\Monolog\\Handler\\StreamHandler"
    args: ["/var/log/firewall/firewall.log", "Monolog\\Level::INFO"]
```

Both directories must be writable by the php-fpm user and **must not be under the web root**:

```bash
install -d -o www-data -g www-data -m 0750 /var/lib/firewall /var/log/firewall
```

If nginx terminates TLS and proxies to php-fpm on the same host, that is not a proxy in the
sense that matters here — `REMOTE_ADDR` is still the visitor. It becomes one the moment
something sits in front of nginx.

## A Cloudflare-fronted origin

| | |
|---|---|
| **In front** | Cloudflare, which sends the visitor's address in `CF-Connecting-IP` and also in `X-Forwarded-For` |
| **Ranges** | Published at [cloudflare.com/ips](https://www.cloudflare.com/ips/) as `ips-v4` and `ips-v6` |
| **Storage / logs** | Whatever the origin host provides — Cloudflare changes nothing here |

```php
Request::setTrustedProxies(
    array_merge($cloudflareV4, $cloudflareV6),   // fetched and cached; see below
    Request::HEADER_X_FORWARDED_FOR
);
```

!!! warning "The ranges are a moving list, so do not paste them"

    Fetch and cache them, and treat a fetch failure as "keep the last copy" rather than "trust
    nobody" — the same posture [rule sources](../configuration/sources.md#failure-policy) take
    with `on_error: last_known_good`, and for the same reason: an empty list at boot means
    every visitor appears to come from Cloudflare's address.

!!! danger "Lock the origin, or the CDN is decoration"

    If your origin answers on its own address, an attacker skips Cloudflare entirely — no bot
    score, no edge rules, and `X-Forwarded-For` whatever they like. Restrict inbound traffic
    to Cloudflare's ranges at the host firewall, or use their Tunnel/Authenticated Origin
    Pulls.

    This is the same trust boundary the [Edge Signals plugin](../plugins/edge-signals.md)
    enforces for `cf-bot-score` — those headers are ignored unless the request arrived through
    a trusted proxy, precisely because a direct request can carry any value it likes.

## Hosts we do not ship a recipe for yet

WP Engine, Acquia and Platform.sh each need the same four answers, and all four are things
their own documentation and your own environment can tell you:

1. **In front** — run the snippet above. Every one of these platforms has a load balancer, so
   expect a forwarding header, and use `REMOTE_ADDR` or `PRIVATE_SUBNETS` unless the platform
   publishes ranges.
2. **Storage** — find the writable path that is *not* web-served and *not* wiped on deploy.
   On platforms with immutable application code that is a mount or a persistent directory;
   the database is often the better answer, as it is on Pantheon.
3. **Logs** — if the platform aggregates stdout/stderr, a `StreamHandler` to `php://stderr`
   gets firewall records into the same place as everything else. See
   [Send Logs Somewhere](send-logs-somewhere.md).
4. **Backends** — if Redis or Memcache is already provisioned, point the rate limiter at it
   rather than the filesystem. See [Storage](../configuration/storage.md).

`vendor/bin/firewall-doctor firewall.yml` will tell you whether the answers you chose
actually work on that host, which is the part that matters.

!!! tip "Recipes are welcome"

    A recipe is a handful of YAML and the four answers above. If you have one running on a
    host not listed here, a pull request adding it — with the values you verified rather than
    the ones the vendor's marketing page implies — is the best kind of contribution to this
    page.
