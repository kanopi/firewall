# Getting Started

Read these start to finish, at least once. They are written to be *followed*, not consulted
— every step has a result you can see, so you can tell whether it worked before moving on.

| | |
|---|---|
| [Quick Start](quick-start.md) | Installed and blocking something, from nothing |
| [Test Drive](test-drive.md) | Try it against your own traffic without enforcing anything |
| [Demo Application](demo.md) | Watch a challenge and a repeat-offender ban happen end to end |
| [Local Example Environment](example-environment.md) | The Docker sandbox, where you can spoof a client IP and see what happens |

Once something is working and you have a specific goal, the
[How-to Guides](../how-to/index.md) take over.

## Requirements

- PHP 8.1 or higher
- Composer
- Symfony components 6.4, 7.3, or 8.1 (Composer picks whichever line your PHP version and application allow)
- Optional: MaxMind GeoIP2 databases for geolocation features
- Optional: Redis for distributed rate limiting

## Installation

Install via Composer:

```bash
composer require kanopi/firewall
```
