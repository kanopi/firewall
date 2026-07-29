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

For manual downloads, MaxMind web-service configuration, and Docker volume mounting, see [example/README.md](../guides/geoip-setup.md).

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
