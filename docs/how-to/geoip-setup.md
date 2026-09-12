# GeoIP Database Setup

The GeoLocation and ASN plugins require MaxMind GeoIP2 databases. You have two options:

## Quickest path: `bin/update_geoip.sh`

The repository ships a helper that downloads all three databases (`GeoLite2-City`, `GeoLite2-Country`, `GeoLite2-ASN`) into a directory you name:

```bash
mkdir -p example/geo
bash bin/update_geoip.sh YOUR_MAXMIND_LICENSE_KEY example/geo
```

Both arguments are required and the target directory must already exist. The script currently pulls from a public GeoLite2 mirror, so the license key is checked for non-emptiness but not used for the download itself — pass any non-empty value if you don't have one yet. Because GeoLite2 is refreshed twice weekly, re-run this periodically rather than once.

The manual options below give you more control (specific editions, MaxMind's official endpoint, or the web service instead of local files).

## Option 1: Download Free GeoLite2 Databases (Recommended for Testing)

1. **Sign up for a free MaxMind account**:
   - Visit https://www.maxmind.com/en/geolite2/signup
   - Create a free account

2. **Generate a license key**:
   - Log into your account
   - Navigate to "My Account" → "Manage License Keys"
   - Generate a new license key
   - Save the key (you'll need it for downloads)

3. **Download the databases**:

   Using `geoipupdate` (recommended):
   ```bash
   # Install geoipupdate
   # macOS:
   brew install geoipupdate

   # Ubuntu/Debian:
   sudo apt install geoipupdate

   # Configure geoipupdate
   # Edit /usr/local/etc/GeoIP.conf (or /etc/GeoIP.conf on Linux)
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   EditionIDs GeoLite2-Country GeoLite2-City GeoLite2-ASN
   DatabaseDirectory /usr/local/share/GeoIP

   # Run update
   geoipupdate
   ```

   OR download manually:
   ```bash
   # Download from MaxMind website after logging in
   # Extract to a local directory, e.g.:
   mkdir -p /usr/local/share/GeoIP
   # Extract .mmdb files to that directory
   ```

4. **Configure the firewall to use the databases**:

   In your `config.yml`:

   **New Format (Recommended):**
   ```yaml
   plugins:
     - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
       response: block
       weight: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-City.mmdb
       config:
         - country:CN    # Block China
         - country:RU    # Block Russia
         - '!country:US' # Block everything except US

     - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
       response: block
       weight: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
       config:
         - asn:AS15169        # Block Google's ASN
         - asn_org@contains:amazon  # Block Amazon ASNs
   ```

   **Legacy Format:**
   ```yaml
   block:
     Kanopi\Firewall\Plugins\GeoLocation:
       priority: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-City.mmdb
       config:
         - country:CN    # Block China
         - country:RU    # Block Russia
         - '!country:US' # Block everything except US

     Kanopi\Firewall\Plugins\Asn:
       priority: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
       config:
         - asn:AS15169        # Block Google's ASN
         - asn_org@contains:amazon  # Block Amazon ASNs
   ```

## Option 2: Use MaxMind Web Service (Paid)

If you have a MaxMind subscription, you can use their web service instead of local databases:

```yaml
block:
  Kanopi\Firewall\Plugins\GeoLocation:
    priority: 0
    enable: true
    metadata:
      reader:
        type: client
        accountId: YOUR_ACCOUNT_ID
        licenseKey: YOUR_LICENSE_KEY
        language: ['en']
    config:
      - country:CN
```

## Docker Volume Mounting (Optional)

To use GeoIP databases inside Docker, mount them as a volume in `docker-compose.yml`:

```yaml
services:
  php:
    volumes:
      - .:/var/www/html
      - /usr/local/share/GeoIP:/usr/local/share/GeoIP:ro
```

## Testing GeoLocation

```bash
# Test with a US IP (Google DNS)
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080

# Test with a Chinese IP
curl -H "X-Forwarded-For: 123.125.114.144" http://localhost:8080

# Test with a Russian IP
curl -H "X-Forwarded-For: 77.88.55.60" http://localhost:8080
```

## GeoIP Database Paths

Common database locations:
- **macOS (Homebrew)**: `/usr/local/share/GeoIP/`
- **Linux**: `/usr/share/GeoIP/` or `/var/lib/GeoIP/`
- **Docker**: Mount wherever convenient, e.g., `/geoip/`

Required database files:
- **GeoLocation plugin**: `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb`
- **ASN plugin**: `GeoLite2-ASN.mmdb`
