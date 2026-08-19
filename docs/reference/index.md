# Reference

Lookup material — dense, tabular, and meant to be scanned rather than read
start to finish.

<div class="grid cards" markdown>

-   :material-speedometer:{ .lg .middle } **Rate Limiting Reference**

    ---

    Every rule in the shipped `rate-limiting.yml` preset, grouped by category,
    with the exact rate and sample window for each path.

    [:octicons-arrow-right-24: Rate limiting reference](rate-limiting.md)

-   :material-history:{ .lg .middle } **Legacy Config Format**

    ---

    The deprecated top-level `bypass:` / `block:` shape, what it normalizes to,
    and side-by-side migration examples.

    [:octicons-arrow-right-24: Legacy config format](legacy-format.md)

</div>

## Class reference

The PHP API is documented in source via PHPDoc. The types most integrators
touch directly:

| Class | Purpose |
|---|---|
| `Kanopi\Firewall\Firewall` | Entry point. `Firewall::create(...)->evaluate()`. |
| `Kanopi\Firewall\FirewallMode` | Backed enum for `global.mode` — `Block`, `Log`, `Exception`, `Disabled`. |
| `Kanopi\Firewall\Plugins\PluginInterface` | Contract for request evaluators. See [Custom Plugins](../guides/custom-plugins.md). |
| `Kanopi\Firewall\Storage\StorageInterface` | Contract for block persistence. See [Custom Storage](../guides/custom-storage.md). |
| `Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface` | Contract for rate-limit counters. |
| `Kanopi\Firewall\Challenge\ChallengeProviderInterface` | Contract for interstitial providers. See [Challenge Responses](../plugins/challenges.md). |
| `Kanopi\Firewall\Challenge\SingleUseSolutionInterface` | Opt-in marker making a solved challenge redeemable once. |
| `Kanopi\Firewall\Exception\FirewallException` | Base class for everything the library throws. See [Error Handling](../guides/error-handling.md). |
| `Kanopi\Firewall\Exception\StorageConnectionException` | A storage backend could not reach its backing service; a `StorageException`. See [Storage](../configuration/storage.md). |
| `Kanopi\Firewall\Utility\Config` | Config loading, merging, and `getLoadErrors()`. |
| `Kanopi\Firewall\Utility\TokenSubstitute` | `%env(...)%` resolution and the filesystem-processor opt-in. |

Browse the annotated source on
[GitHub](https://github.com/kanopi/firewall/tree/2.x/src).
