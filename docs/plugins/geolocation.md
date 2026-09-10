# GeoLocation Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\GeoLocation`

Evaluates requests based on geographic location using MaxMind GeoIP2 databases.

## Obtaining the databases

The plugin needs a `.mmdb` database. `bin/update_geoip.sh` fetches all three editions the library can use (`GeoLite2-City`, `GeoLite2-Country`, `GeoLite2-ASN` — the last one is for the [ASN Plugin](asn.md)) into a directory you name:

```bash
mkdir -p /var/lib/geoip
bash bin/update_geoip.sh YOUR_MAXMIND_LICENSE_KEY /var/lib/geoip
```

- Both arguments are required and the target directory must already exist.
- The script currently downloads from a public mirror of the GeoLite2 databases, so the license key argument is validated as non-empty but not actually used for the download. Keep passing one — the direct-from-MaxMind path is retained in the script and the argument will be needed again when it is re-enabled.
- MaxMind refreshes GeoLite2 twice weekly. Run this on a schedule (cron, or a build step) rather than once at install; stale geolocation data quietly produces wrong verdicts.

For manual downloads, MaxMind web-service configuration, and Docker volume mounting, see [example/README.md](../how-to/geoip-setup.md).

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: 0
    enable: true
    metadata:
      reader:
        # Option 1: Local database file
        type: reader
        db: /path/to/GeoLite2-City.mmdb

        # Option 2: MaxMind web service
        # type: client
        # accountId: 123456
        # licenseKey: your_license_key
        # languages: ['en', 'es']
        # options: []
    config:
      # Block specific countries
      - "country:CN"
      - "country:RU"
      - "country.isoCode:KP"

      # Block entire continents
      - "continent:AS"
      - "continent.code:AF"

      # Block specific cities
      - "city:Moscow"
      - "city.name@contains:Beijing"

      # Complex location rules
      - variable: location.timeZone
        operator: equals
        value: "Asia/Shanghai"
```

## Available Variables

- `country` - Returns country ISO code (e.g., "US")
- `country.isoCode` - Country ISO code
- `country.name` - Full country name
- `continent` - Returns continent code (e.g., "NA")
- `continent.code` - Continent code
- `continent.name` - Full continent name
- `city` - Returns city name
- `city.name` - City name
- `location.latitude` - Latitude coordinate
- `location.longitude` - Longitude coordinate
- `location.timeZone` - Time zone
- `postal` - Returns postal code
- `postal.code` - Postal/ZIP code


## Caching lookups across requests

Reading the MaxMind database costs about **0.305 ms** per lookup. Within a single request
that is already paid once per address rather than once per rule variable — `country:US`
alongside `city:London` reads one record, not two.

Across requests, an optional PSR-6 cache holds the **resolved values**:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    metadata:
      cache:
        adaptor: "Symfony\\Component\\Cache\\Adapter\\RedisAdapter"
        args: ["redis://127.0.0.1:6379", "geoip", 86400]
        ttl: 86400
      reader:
        type: reader
        db: /path/to/GeoLite2-City.mmdb
    config: ["country:CN"]
```

The shape matches the one [user agent](user-agent.md#caching) and
[rate limiting](rate-limit.md) already accept, so there is a single convention to learn.

### It is off by default, and that is deliberate

| | |
|---|---|
| Database lookup | 0.305 ms |
| Cache **hit** (Redis) | 0.036 ms |
| Cache **write** on a miss | 0.094 ms |

A hit is roughly 8× cheaper than the lookup — but **a miss costs the lookup *plus* the
write**, so it is more expensive than not caching at all. The break-even is about a **26%
hit rate**.

Ordinary traffic clears that comfortably: the same visitors and crawlers return, and their
addresses repeat. A flood arriving from thousands of distinct addresses does not — and that
is exactly when the firewall is busiest. Turning this on by default would make the worst
case worse, so you are asked to decide.

### Use a store that can evict

Cached values are keyed per address, so a busy site accumulates one entry per distinct
client. On a filesystem pool that is one file each — 20,000 addresses measured at 20,000
files and **78 MB**, none of which goes away on its own.

Redis with a `maxmemory-policy` of `allkeys-lru` bounds that: the least-used entries are
evicted and the cache stays the size you allowed it. `ttl` (a day by default) is the other
half of the answer, but eviction is what protects you from address diversity.

### Only scalars are cached

The GeoIP2 model is never stored — only the resolved value, which is a string, a number or
null. A cache is a shared store, and an object in a shared store is an object somebody may
deserialise. This library keeps PHP deserialisation out of everything it writes and reads
back, and a country code is safe wherever it is kept.

A resolved `null` is cached like any other answer: an address with no record will not
acquire one, and re-asking costs the same read that produced the null.

### If the cache cannot be built

The rule still works — every lookup simply goes to the database, which is slower and not
broken. A warning names the adaptor and the reason.

## Reading location from CDN headers

A site behind Cloudflare, CloudFront, Akamai or Fastly has already had the lookup done at
the edge. `source: header` reads the result instead of consulting a MaxMind database, so
there is no database to ship, update, or pay for:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: 0
    enable: true
    metadata:
      source: header          # reader (default) | header
      provider: cloudflare    # cloudflare | cloudfront | akamai | custom
    config:
      - "country@in:CN,RU,KP"
```

The rule vocabulary is unchanged, so a config can move between sources without being
rewritten. `country` and `country.isoCode` both work either way.

!!! danger "A geo header is a claim, and it is only worth anything if it came from the edge"
    Nothing stops a request going straight to your origin with a header of its choosing:

    ```bash
    curl -H "CF-IPCountry: US" https://origin.example.com/
    ```

    Against a `response: block` entry that defeats your geo blocking. Against
    `response: allow` it is far worse — an allow match short-circuits evaluation, so a
    forged country header becomes a **complete firewall bypass**.

    So headers are only believed when the request arrived via a **trusted proxy**:

    ```php
    Request::setTrustedProxies(
        ['173.245.48.0/20', '103.21.244.0/22', /* … your CDN's ranges … */],
        Request::HEADER_X_FORWARDED_FOR
    );
    ```

    A deployment behind a CDN needs this anyway for `getClientIp()` to be correct, so it is
    usually already set. When it is not, the plugin **matches nothing and logs a warning on
    every request** rather than trusting the header — geo blocking being quietly off looks
    exactly like nobody from those countries visiting.

    Keeping that list current is what [rule sources](../configuration/sources.md) are for:
    most CDNs publish their ranges at a stable URL.

### Providers

| `provider` | Header(s) | Sent automatically? |
|---|---|---|
| `cloudflare` | `CF-IPCountry`, plus `CF-IPCity`, `CF-IPContinent`, `CF-Postal-Code`, `CF-Region-Code`, `CF-IPLatitude`, `CF-IPLongitude` | Country yes, rest behind Managed Transforms |
| `cloudfront` | `CloudFront-Viewer-Country`, `-Country-Name`, `-City`, `-Postal-Code`, `-Country-Region`, `-Latitude`, `-Longitude` | No — add them to the cache or origin-request policy |
| `akamai` | `X-Akamai-Edgescape` — one compound header, unpacked here | Only with EdgeScape enabled |
| `fastly` | `X-Geo-Country`, `-Country-Name`, `-Continent`, `-City`, `-Postal`, `-Region`, `-Latitude`, `-Longitude` | **No** — you set them in VCL, see below |
| `gcp` | `X-Client-Geo-Location` — positional `country,city` | **No** — you add it as a custom request header, see below |
| `custom` | Whatever you name in `metadata.headers` | — |

**Only Cloudflare sends anything without being asked**, and only the country. Everything
else in this table is opt-in at the edge. A field the edge did not send resolves to nothing
rather than to a wrong answer, so an unconfigured header shows up as rules that never match
rather than as rules that match wrongly.

### Fastly

Fastly adds no geo header of its own — the data is available in VCL as `client.geo.*` and
you decide what to call it. The `fastly` provider expects the names this snippet sets:

```vcl
sub vcl_miss {
#FASTLY miss
  set bereq.http.X-Geo-Country      = client.geo.country_code;
  set bereq.http.X-Geo-Country-Name = client.geo.country_name;
  set bereq.http.X-Geo-Continent    = client.geo.continent_code;
  set bereq.http.X-Geo-City         = client.geo.city;
  set bereq.http.X-Geo-Postal       = client.geo.postal_code;
  set bereq.http.X-Geo-Region       = client.geo.region;
  set bereq.http.X-Geo-Latitude     = client.geo.latitude;
  set bereq.http.X-Geo-Longitude    = client.geo.longitude;
}
```

Set the same headers in `vcl_pass` if you have uncacheable routes that need geo.

Deliberately **not** `Fastly-Geo-*`: Fastly uses the `Fastly-` prefix for its own headers,
and squatting on it invites a collision. If your VCL already sets different names, use
`custom` rather than renaming to match us.

!!! note "Pantheon and other Fastly-based hosts"
    Pantheon fronts sites with Fastly but does not expose arbitrary VCL, so these headers
    are not available by default. Check what your host actually forwards before assuming
    this provider will work — if nothing arrives, the plugin will match nothing and log
    that the headers carried nothing.

### Google Cloud

Google Cloud's load balancer expands variables inside custom request headers. Add one:

```bash
gcloud compute backend-services update BACKEND_SERVICE \
  --global \
  --custom-request-header='X-Client-Geo-Location:{client_region},{client_city}'
```

For a client in Mountain View that arrives as `X-Client-Geo-Location: US,Mountain View`.
Despite the variable name, `client_region` is the **country code** — which is why the
`gcp` provider maps position 0 to `country`.

The header is positional rather than keyed, but the load balancer expands a variable it
cannot resolve to an empty string rather than dropping it, so the positions stay stable.

### Anything else

`custom` names the headers yourself:

```yaml
metadata:
  source: header
  provider: custom
  headers:
    country: X-My-Geo-Country
    city: X-My-Geo-City
```

`headers` also overrides a named provider one field at a time, so you can take Cloudflare's
defaults and redirect a single field to a header of your own.

### Edges this does not apply to

**Sucuri** does geo blocking at its own firewall — you pick the countries in their
dashboard and they never reach you. It sends `X-Sucuri-ClientIP` and `X-Sucuri-ID`, but the
location encoded in `X-Sucuri-ID` is the *edge node that served the request*, not the
visitor's country. There is nothing here for this plugin to read.

**Azure Front Door** sends `X-Azure-ClientIP` and `X-Azure-SocketIP` but no geo header. Its
geo-filtering lives in the WAF policy. If you want the firewall to make the decision
instead, use the reader source against `X-Azure-ClientIP`.

In both cases the edge is already doing the blocking, which may be all you need — the
question worth asking is whether you want that decision in your config, in version control,
alongside your other rules.

### What you give up against a reader

Edge headers are thinner. Country is reliably present; everything else depends on the CDN
and its configuration, and `country.name` and `continent.name` are unavailable on several
of them. If your rules need the full variable surface — city, timezone, coordinates — the
MaxMind reader remains the source that has all of it.
