# Simple Firewall

The following library is a simple setup that evaluates the request. The idea of
this library is that the database doesn't need to bootstrap for the CMS therefore
causing more overhead.

## Setup

Include the following snippet early on in the process.

```php
if (
  php_sapi_name() !== 'cli' &&
  class_exists('Kanopi\Firewall\Firewall') &&
  \Kanopi\Firewall\Firewall::create(
    __DIR__ . '/files/private/blocked_urls.txt',
    __DIR__ . '/files/private/blocked_ips.txt'
  )->check()
) {
  header('HTTP/1.0 403 IP Address Blocked');
  exit;
}
```

Alter the following file locations to reflect the location of the site's url and
ip address list.

### Blocked URLs

The blocked URLs are urls that are a text file of URLs where each URL is on
it's own line. An example of that might be the following:

```text
/example-url
/test.php
/home/example.php
```

Regex can also be included as part of the URLs.

```text
^/wp-admin(.*)$
```

### Blocked IPs

IP addresses are in both IPV4 and IPV6. The CIDR can be included as part of the
line.

Examples of this look like:

```text
1.1.1.1
2.2.2.2/32
```

## Starters

The following are start examples that have been included. To use these copy the
file and reference as part of the setup.

 - [Drupal](starters/drupal.txt)
 - [WordPress](starters/wordpress.txt)