# Testing Your Configuration

## Testing malicious-requests.yml (Vulnerability Scoring)

Test various attack patterns to verify scoring and blocking:

```bash
# Test SQL Injection (should score 40+ and block)
curl "http://localhost:8080/?id=1' UNION SELECT * FROM users--"
curl "http://localhost:8080/?search=admin' OR '1'='1"

# Test XSS (should score 35+ and block)
curl "http://localhost:8080/?name=<script>alert(1)</script>"
curl "http://localhost:8080/?redirect=javascript:alert(1)"

# Test Command Injection (should score 35+ and block)
curl "http://localhost:8080/?cmd=ls;cat /etc/passwd"
curl "http://localhost:8080/?file=test|whoami"

# Test Path Traversal (should score 30+ and block)
curl "http://localhost:8080/../../../etc/passwd"
curl "http://localhost:8080/?file=../../wp-config.php"

# Test Web Shell Detection (should score 50+ and block)
curl "http://localhost:8080/c99.php"
curl "http://localhost:8080/shell.php"

# Test with attack tools user agent (should score 50+ and block)
curl -A "sqlmap/1.0" http://localhost:8080/
curl -A "Nikto/2.1.5" http://localhost:8080/

# Test legitimate requests (should allow)
curl http://localhost:8080/
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://localhost:8080/
```

## Testing drupal.yml

```bash
# Should be blocked (403)
curl -i http://localhost:8080/core/CHANGELOG.txt
curl -i http://localhost:8080/core/install.php
curl -i http://localhost:8080/sites/default/settings.php
curl -i http://localhost:8080/sites/default/files/evil.php
curl -i http://localhost:8080/sites/default/files/private/salary.pdf
curl -i http://localhost:8080/composer.lock
curl -i http://localhost:8080/.git/config
curl -i http://localhost:8080/vendor/autoload.php

# Should NOT be blocked — these break the site if the preset is too greedy
curl -i http://localhost:8080/core/misc/drupal.js
curl -i http://localhost:8080/core/assets/vendor/jquery/jquery.min.js
curl -i http://localhost:8080/sites/default/files/2026-09/photo.jpg
curl -i http://localhost:8080/user/42
curl -i http://localhost:8080/.well-known/acme-challenge/token123
```

## Testing drupal-admin.yml

```bash
# Should be blocked (403)
curl -i http://localhost:8080/admin
curl -i http://localhost:8080/admin/reports/status
curl -i http://localhost:8080/user/login
curl -i http://localhost:8080/user/register
curl -i http://localhost:8080/es/user/login
curl -i http://localhost:8080/node/add/article

# Should NOT be blocked
curl -i http://localhost:8080/user/42
curl -i http://localhost:8080/administrative-services
curl -i "http://localhost:8080/search?q=admin"

# From an allowed address, /admin should pass
curl -i --interface 203.0.113.9 http://localhost:8080/admin
```

## Testing malicious-urls.yml

```bash
# Should be blocked (403)
curl -I https://yoursite.com/alfa.php
curl -I https://yoursite.com/shell.php
curl -I https://yoursite.com/wp-config.php
curl -I https://yoursite.com/.env

# Should work (200)
curl -I https://yoursite.com/
curl -I https://yoursite.com/index.php
```

## Testing wordpress.yml

```bash
# Should be blocked (403)
curl -I https://yoursite.com/test.php
curl -I https://yoursite.com/random.php

# Should work if explicitly allowed (response: allow entry)
curl -I https://yoursite.com/contact.php
```

## Testing rate-limiting.yml

Test rate limiting by making rapid requests:

```bash
# Test homepage rate limit (120 requests per minute)
# Make 125 requests rapidly - last 5 should return 429
for i in {1..125}; do
  curl -I http://localhost:8080/ 2>&1 | grep "HTTP/"
  sleep 0.1
done

# Test login rate limit (5 attempts per 5 minutes)
# Make 6 requests - 6th should return 429
for i in {1..6}; do
  curl -I http://localhost:8080/login
  echo "Request $i"
done

# Test API rate limit (100 per minute)
for i in {1..105}; do
  curl -I http://localhost:8080/api/endpoint 2>&1 | grep "HTTP/"
done

# Test with different IPs using X-Forwarded-For
# Each IP gets its own rate limit
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8080/login
curl -H "X-Forwarded-For: 5.6.7.8" http://localhost:8080/login

# Verify rate limiting is working
# Look for 429 status code
curl -I http://localhost:8080/login | grep "429 Too Many Requests"

# Wait for rate limit window to expire, then try again
sleep 300  # Wait 5 minutes for login rate limit to reset
curl -I http://localhost:8080/login  # Should work again
```

## Monitor Logs and Scoring

```bash
# Check what's being blocked
tail -f /var/log/firewall/blocked-requests.log

# Look for false positives
grep "403" /var/log/nginx/access.log | grep -v "alfa.php\|shell.php"

# For VulnerabilityScore plugin, enable debug logging to see scores:
# Add to your config:
# logging:
#   level: debug
#   handlers:
#     - type: stream
#       path: /var/log/firewall-debug.log
#
# Then watch scores in real-time:
tail -f /var/log/firewall-debug.log | grep "Total vulnerability score"
```
