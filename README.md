# Simple Firewall

The following library allows for Requests to be evaluated and if a set of predefined configurations have been matched
the request and the IP address is blocked.

## Setup

When using the following library add it within the `settings.php` (Drupal) or the `wp-config.php` (WordPress).

### Configuration

```php
use Kanopi\Firewall\Storage\FileStorage;

if (class_exists('\Kanopi\Firewall\Firewall')) {
    \Kanopi\Firewall\Firewall::create([ __DIR__ . '/config.yml' ])->evaluate();
}
```

A basic configuration file has been included as part of the project in [config/config.default.yml](config/config.default.yml).

### Configuration

Configuring the firewall can either reference the location of the configuration file, or an array of configuration settings.

There are four configuration elements.

| Key     | Description                                                                                   |
|---------|-----------------------------------------------------------------------------------------------|
| storage | Location where the automatically blocked IPs are located.                                     |
| bypass  | List of plugins enabled that should be allowed for bypass or added to the allowed list.       |
| block   | List of plugins enabled that should be evaluated to check if a request to shouold be blocked. |
| logger  | List of logging elements.                                                                     |

#### Storage

Storage plugins are how data is stored within the system. This is used to store the IP addresses that are marked for
blocking.

Available Options:

| Class                                    | Description                   |
|------------------------------------------|-------------------------------|
| \Kanopi\Firewall\Storage\InMemoryStorage | Stores the items in memory    |
| \Kanopi\Firewall\Storage\FileStorage     | Stores the contents in a file |

#### Plugins

Plugins are used to evaluate a set of requests. They can either be used within the `bypass` or the `block` section to
allow or deny a request.

Available Options:

| Class                                | Description                                                                     |
|--------------------------------------|---------------------------------------------------------------------------------|
| \Kanopi\Firewall\Plugins\IpAddress   | Evaluate specific IP addresses and/or CIDR blocks                               |
| \Kanopi\Firewall\Plugins\GeoLocation | Evaluate Geographic elements based on the IP address and the MaxMind GeoLite DB |
| \Kanopi\Firewall\Plugins\Url         | Evaluate requests based on Host, URL, Method, and Parameters                    |
| \Kanopi\Firewall\Plugins\UserAgent   | Evaluate the requests User Agent                                                |
| \Kanopi\Firewall\Plugins\Asn         | Review the requests ASN (Automous System Network)                               |
| \Kanopi\Firewall\Plugins\RateLimit   | Rate limit the request to stop bot traffic from abusing the site                |

**\Kanopi\Firewall\Plugins\IpAddress**

Configuration for the following can either be a single IP or a CIDR block.

To set the list of IP addresses

```yaml
  Kanopi\Firewall\Plugins\IpAddress:
    config:
      - 127.0.0.1
      - ::1
      - 10.0.0.0/24
      - 2001:0db8:85a3::/64
```

**\Kanopi\Firewall\Plugins\GeoLocation**

Configuration for the following uses the [MaxMind GeoLite database](https://dev.maxmind.com/geoip/docs/databases/city-and-country/#binary-databases).

To reference the location of the database set the metadata 

```yaml
  Kanopi\Firewall\Plugins\GeoLocation:
    metadata:
      reader:
        db: /tmp/GeoLite2-City.mmdb
```

Once referenced set the configuration settings.

```yaml
  Kanopi\Firewall\Plugins\GeoLocation:
    config:
      - 'country:CN'
```

Available options:

- country
- continent
- city
- location
- postal

For more details on how to form a conditional see the [Forming Conditional Statements](#forming-conditional-statements) section.

**\Kanopi\Firewall\Plugins\Url**

Available options:

- method
- host
- path
- query

For more details on how to form a conditional see the [Forming Conditional Statements](#forming-conditional-statements) section.

**\Kanopi\Firewall\Plugins\UserAgent**

Available options:

- bot
- device
- client
- os
- brand
- model

For more details on how to form a conditional see the [Forming Conditional Statements](#forming-conditional-statements) section.

**\Kanopi\Firewall\Plugins\Asn**

Available options:

- asn
- asn_org

For more details on how to form a conditional see the [Forming Conditional Statements](#forming-conditional-statements) section.

**\Kanopi\Firewall\Plugins\RateLimit**

Changing the default rate and sample size can be done by setting the `default_rate` and `default_sample` metadata variables.

```yaml
  Kanopi\Firewall\Plugins\RateLimit:
    metadata:
      default_rate: 500
      default_sample: 10
```

`default_rate` refers to the number of requests that are made.
`default_sample` refers to the sample size to count for the requsts.

These variables are globally used.

In the event there is a need to configure rate limiting per URL these can be set as part of the configuration.

```yaml
  Kanopi\Firewall\Plugins\RateLimit:
    config:
      - path: '/example/*'
      - path: '/example'
        rate: 100
        sample: 10
```

##### Forming Conditional Statements

**Simple**

Simple conditionals refer to making it a single string.

```yaml
  - "variable:value"                 # (defaults to 'equals')
  - "variable@operator:value"
  - "!variable:value"                # (negated equals)
  - "!variable@operator:value"       # (negated custom operator)
```

**Expanded**

Expanded conditionals are formatted within an array.

```yaml
-
  variable: method. # Variable name to reference based on the plugin.
  operator: equal   # Possible values [equals, starts_with, contains, regex, in, matches_any]
  value: GET        # Values to check against. If using the operator in or matches_any use an array.
  negate: true      # Set to true if should be negate or remove if not.
-
  
```

##### Custom Plugins

Creating custom plugins are possible by implementing the `\Kanopi\Firewall\Plugins\PluginInterface` interface.

Once created referencing the full namespace can allow for it to be used.

#### Logger

Loggers are used as a method for outputting logging data. Classes are provided from the [Monolog Library](https://seldaek.github.io/monolog/).

Available Options:

| Class                          | Description          |
|--------------------------------|----------------------|
| \Monolog\Handler\StreamHandler | Write logs to a file |

### Override Values

There are times where the underlying environment is dynamic and requires variables to change based on the hosting.
In that instance the override variables are the second parameter to be passed in. The syntax follows the [Symfony Property Access](https://symfony.com/doc/current/components/property_access.html#writing-to-arrays).

An example of that is the following:

```php
[
    '[logger][0][args][0]' => __DIR__ . '/data/firewall.log',
    '[block][Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]' => __DIR__ . '/GeoLite2-City.mmdb',
    '[block][Kanopi\Firewall\Plugins\Asn][metadata][reader][db]' => __DIR__ . '/GeoLite2-ASN.mmdb',
]
```

### Usage

Setting up the library for use requires minimal setup process.  

#### Drupal

When adding to Drupal 10+ add the following to the `settings.php` file towards the top of the file before the following
snippet.

```php
<?php

/** Insert snippet here */

/**
 * Load services definition file.
 */
$settings['container_yamls'][] = __DIR__ . '/services.yml';
```

#### WordPress

DESCRIBE HOW TO ADD TO WORDPRESS

#### Other

DESCRIBE HOW TO ADD TO OTHER PROJECTS

## Testing

TBD