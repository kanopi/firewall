# Firewall Performance Testing Suite

This comprehensive performance testing suite simulates various traffic patterns to test the firewall's performance under different conditions, including normal user behavior and malicious attack patterns.

## Features

- **Concurrent Connection Simulation**: Tests with configurable number of concurrent connections
- **Geographic IP Distribution**: Simulates traffic from different countries with realistic IP ranges
- **Mixed Traffic Patterns**: Combines normal and malicious traffic based on configurable ratios
- **Multiple HTTP Methods**: Tests GET, POST, PUT, DELETE, HEAD, OPTIONS requests
- **Attack Pattern Simulation**: 
  - SQL injection attempts
  - Vulnerability scanning (WordPress, phpMyAdmin, etc.)
  - Bot/crawler behavior
  - Rate limit testing
  - Geographic-based attacks
- **Comprehensive Metrics**:
  - Total requests and blocking rates
  - Response time percentiles (P50, P95, P99)
  - Memory and CPU usage
  - False positive/negative rates
  - Plugin-specific performance
- **Multiple Report Formats**: HTML and JSON output
- **Success Criteria Validation**: Automated pass/fail based on configurable thresholds

## Installation

1. Ensure you have PHP 8.0+ and Composer installed
2. Install dependencies:
   ```bash
   composer install
   ```
3. Download GeoIP databases (optional but recommended):
   ```bash
   # Create directory for GeoIP databases
   mkdir -p /tmp/geoip
   
   # Use the provided update script with your MaxMind license key
   bash bin/update_geoip.sh YOUR_MAXMIND_LICENSE_KEY /tmp/geoip
   
   # The script will download:
   # - GeoLite2-City.mmdb
   # - GeoLite2-ASN.mmdb
   # - GeoLite2-Country.mmdb
   ```
   
   To get a MaxMind license key:
   - Sign up at https://www.maxmind.com/en/geolite2/signup
   - Generate a license key in your account area
   - Store it as an environment variable: `export MAXMIND_LICENSE_KEY=your_key_here`

## Configuration

All test parameters are configured in `benchmark-config.yml`. Key sections include:

### Test Parameters
```yaml
test:
  duration_minutes: 10
  concurrent_connections: 50
  ramp_up_seconds: 30
```

### Traffic Distribution
```yaml
traffic:
  distribution:
    normal: 70      # 70% legitimate traffic
    malicious: 30   # 30% malicious traffic
```

### Geographic Distribution
```yaml
geographic:
  distribution:
    US: 40
    CN: 15
    RU: 10
    # ... etc
```

### Success Criteria
```yaml
success_criteria:
  malicious_block_rate: 95      # Must block 95% of malicious traffic
  max_false_positive_rate: 1    # Max 1% false positives
  max_added_latency_ms: 50      # Max 50ms added latency
  max_memory_usage_mb: 512      # Max 512MB memory
  min_requests_per_second: 1000 # Min 1000 RPS
```

## Running Tests

### Quick Start (Local Testing)

The easiest way to run performance tests locally:

```bash
# Set your MaxMind license key (or skip to use example databases)
export MAXMIND_LICENSE_KEY=your_license_key_here

# Run the test (handles all setup automatically)
./tests/Performance/run-local-test.sh

# Or with a custom config
./tests/Performance/run-local-test.sh path/to/custom-config.yml
```

This script will:
- Download/update GeoIP databases (if license key provided)
- Start the test application
- Run the performance tests
- Generate reports
- Open the HTML report in your browser
- Clean up when done

### Manual Local Testing

1. Download GeoIP databases (if not already done):
   ```bash
   # Set your MaxMind license key
   export MAXMIND_LICENSE_KEY=your_license_key_here
   
   # Download databases
   mkdir -p /tmp/geoip
   bash bin/update_geoip.sh $MAXMIND_LICENSE_KEY /tmp/geoip
   ```

2. Start a test application with the firewall:
   ```bash
   # Set GeoIP database paths
   export GEOIP_DB_PATH=/tmp/geoip/GeoLite2-City.mmdb
   export ASN_DB_PATH=/tmp/geoip/GeoLite2-ASN.mmdb
   
   # Using PHP built-in server
   php -S localhost:8080 tests/Performance/test-app.php
   
   # Or with nginx (see nginx configuration below)
   ```

3. Run the benchmark:
   ```bash
   php tests/Performance/run-benchmark.php
   
   # With custom config
   php tests/Performance/run-benchmark.php --config=my-config.yml
   ```

### CircleCI Integration

The suite includes a CircleCI configuration that:
- Sets up nginx with PHP-FPM
- Configures Redis and MySQL
- Runs the performance tests
- Validates success criteria

Add to your `.circleci/config.yml`:
```yaml
workflows:
  version: 2
  test:
    jobs:
      - performance-test
```

### Nginx Configuration

For production-like testing with nginx:

```nginx
server {
    listen 8080;
    root /path/to/firewall;
    
    location / {
        try_files $uri /tests/Performance/test-app.php$is_args$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        
        # Performance optimizations
        fastcgi_buffer_size 128k;
        fastcgi_buffers 256 16k;
        fastcgi_busy_buffers_size 256k;
    }
}
```

## Understanding Results

### Console Output
```
=== Firewall Performance Benchmark ===
Duration: 10 minutes
Concurrent connections: 50
Target URL: http://localhost:8080

[00:05:23] Requests: 15420 | Blocked: 4626 (30.0%) | RPS: 47.8 | Memory: 45.2MB

=== Test Summary ===
Total requests: 30,000
Blocked requests: 9,000 (30%)
Average RPS: 50.0

✅ All success criteria met!
```

### HTML Report

The HTML report includes:
- Executive summary with key metrics
- Performance charts and graphs
- Geographic distribution maps
- Plugin performance breakdown
- System resource usage
- Success criteria validation

### JSON Report

The JSON report contains all raw data for:
- Integration with CI/CD pipelines
- Custom analysis and visualization
- Historical trend tracking
- Automated alerting

## Traffic Patterns

### Normal Traffic Simulation
- Regular page views with realistic delays
- Session-based browsing patterns
- Standard user agents
- Legitimate geographic distribution

### Malicious Traffic Simulation
- Rapid-fire requests (DoS attempts)
- SQL injection in URLs and parameters
- Vulnerability scanning (wp-admin, .env, etc.)
- Suspicious user agents (sqlmap, nikto)
- Requests from blocked countries
- Rate limit violations

## Troubleshooting

### High False Positive Rate
- Review blocking rules in `test-app.php`
- Adjust geographic distribution to match your user base
- Fine-tune rate limiting thresholds

### Low Request Rate
- Increase concurrent connections
- Check system resources (CPU, memory)
- Optimize nginx/PHP-FPM configuration
- Use Redis for rate limit storage

### Memory Issues
- Reduce concurrent connections
- Shorten test duration
- Use file-based storage instead of in-memory

## Extending the Test Suite

### Adding Custom Attack Patterns

Edit `benchmark-config.yml`:
```yaml
traffic:
  urls:
    malicious:
      - "/api/users?id=1'; DROP TABLE users--"
      - "/admin/backup.sql"
      - "/../../../etc/passwd"
```

### Adding Custom Metrics

Extend `MetricsCollector.php`:
```php
public function recordCustomMetric(string $name, $value): void
{
    $this->customMetrics[$name][] = $value;
}
```

### Creating Custom Reports

Extend `ReportGenerator.php`:
```php
private function generateCustomReport(array $metrics): void
{
    // Your custom report logic
}
```

## Best Practices

1. **Baseline Testing**: Run tests without the firewall first to establish baseline performance
2. **Incremental Testing**: Test individual plugins before testing all together
3. **Production-Like Environment**: Use similar hardware and software as production
4. **Regular Testing**: Run performance tests as part of CI/CD pipeline
5. **Monitor Trends**: Track performance metrics over time to catch regressions

## Environment Variables

The performance tests support the following environment variables:

- `MAXMIND_LICENSE_KEY`: Your MaxMind license key for downloading GeoIP databases
- `FIREWALL_TEST_URL`: The URL to test against (default: http://localhost:8080)
- `GEOIP_DB_PATH`: Path to GeoLite2-City.mmdb (default: /tmp/geoip/GeoLite2-City.mmdb)
- `ASN_DB_PATH`: Path to GeoLite2-ASN.mmdb (default: /tmp/geoip/GeoLite2-ASN.mmdb)
- `GEOIP_COUNTRY_DB_PATH`: Path to GeoLite2-Country.mmdb (default: /tmp/geoip/GeoLite2-Country.mmdb)
- `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`: Database connection details
- `REDIS_HOST`, `REDIS_PORT`: Redis connection details

## Security Considerations

- Never run performance tests against production systems
- Ensure test environments are isolated
- Be careful with real GeoIP databases containing sensitive data
- Clean up test data after benchmarks
- Keep your MaxMind license key secure

## Support

For issues or questions:
- Check the main firewall documentation
- Review test logs in `reports/performance/`
- Enable debug mode in `benchmark-config.yml`