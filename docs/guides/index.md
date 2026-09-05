# Guides

Task-oriented walkthroughs. The [Configuration](../configuration/index.md) and
[Plugins](../plugins/index.md) sections describe *what every key does*; these
pages describe *how to accomplish something*.

<div class="grid cards" markdown>

-   :material-alert-octagon-outline:{ .lg .middle } **Error Handling**

    ---

    Every exception the library throws, which mode throws it, and how to decide
    between failing open and failing closed.

    [:octicons-arrow-right-24: Error handling](error-handling.md)

-   :material-puzzle-plus-outline:{ .lg .middle } **Custom Plugins**

    ---

    Implement `PluginInterface` to evaluate requests against your own logic.

    [:octicons-arrow-right-24: Custom plugins](custom-plugins.md)

-   :material-database-cog-outline:{ .lg .middle } **Custom Storage**

    ---

    Persist blocks and rate-limit counters anywhere — Memcached, DynamoDB, your
    app's ORM.

    [:octicons-arrow-right-24: Custom storage](custom-storage.md)

-   :material-layers-triple-outline:{ .lg .middle } **Advanced Examples**

    ---

    A full multi-layered production configuration, annotated.

    [:octicons-arrow-right-24: Advanced examples](advanced-examples.md)

-   :material-cloud-download-outline:{ .lg .middle } **Syncing Rule Sources**

    ---

    Refresh remote rule lists at deploy time and on a cron, then take the
    request path offline so a visitor never waits on somebody else's server.

    [:octicons-arrow-right-24: Syncing rule sources](syncing-sources.md)

-   :material-map-marker-radius-outline:{ .lg .middle } **GeoIP Setup**

    ---

    Obtain, install, and refresh the MaxMind GeoLite2 databases the
    GeoLocation and ASN plugins need.

    [:octicons-arrow-right-24: GeoIP setup](geoip-setup.md)

-   :material-docker:{ .lg .middle } **Local Example Environment**

    ---

    The Docker sandbox in `example/` — spoofing client IPs, testing rules, and
    troubleshooting.

    [:octicons-arrow-right-24: Example environment](example-environment.md)

-   :material-play-box-outline:{ .lg .middle } **Demo Application**

    ---

    A runnable demo showing the challenge interstitial and repeat-offender
    escalation end to end.

    [:octicons-arrow-right-24: Demo application](demo.md)

</div>
