# How-to Guides

You know what you want; these are the steps. Each page starts from a goal and ends with it
done.

If you are still deciding *what* you want, start with
[Getting Started](../getting-started/index.md). If you want to know what a setting does,
that is [Configuration](../configuration/index.md) and [Plugins](../plugins/index.md).

<div class="grid cards" markdown>

-   :material-connection:{ .lg .middle } **Integrate With Your Platform**

    ---

    Wire the firewall into Drupal, WordPress, Laravel or a plain front
    controller, in the right place in the bootstrap.

    [:octicons-arrow-right-24: Platform integration](platform-integration.md)

-   :material-shield-account-outline:{ .lg .middle } **Add a Challenge**

    ---

    Make suspicious traffic prove it is human instead of refusing it outright —
    configured, pointed at a rule, and checked before it enforces.

    [:octicons-arrow-right-24: Add a challenge](add-a-challenge.md)

-   :material-format-list-bulleted-type:{ .lg .middle } **Add a Rule Source**

    ---

    Point a rule at a list that lives somewhere else — a file, a URL, a feed
    someone else publishes — in whatever shape it already has.

    [:octicons-arrow-right-24: Add a rule source](add-a-rule-source.md)

-   :material-text-box-outline:{ .lg .middle } **Send Logs Somewhere**

    ---

    A file, a rotating file, a queryable table, or a Slack channel that only
    speaks up when something is actually broken.

    [:octicons-arrow-right-24: Send logs somewhere](send-logs-somewhere.md)

-   :material-lifebuoy:{ .lg .middle } **Troubleshooting**

    ---

    Organised by the sentence you would actually type — "my allow rule isn't
    working", "I locked myself out", "the challenge loops forever" — with the
    one command that confirms each.

    [:octicons-arrow-right-24: Troubleshooting](troubleshooting.md)

-   :material-magnify-scan:{ .lg .middle } **Check a Request**

    ---

    Ask whether a given request would be blocked, and by which rule, from a
    terminal — without banning the address you are asking about.

    [:octicons-arrow-right-24: Checking a request](checking-requests.md)

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

-   :material-database-arrow-up-outline:{ .lg .middle } **Schema Migrations**

    ---

    Add the columns and indexes an existing database table is missing, without
    dropping it. Only ever additive, so no run can lose a row.

    [:octicons-arrow-right-24: Schema migrations](schema-migrations.md)

-   :material-stethoscope:{ .lg .middle } **Diagnosing an Installation**

    ---

    Run against the real environment and find out what is wrong with it: rules
    that are not running, stores that cannot be reached, a stale GeoIP database.

    [:octicons-arrow-right-24: Diagnosing an installation](diagnosing.md)

-   :material-playlist-edit:{ .lg .middle } **Managing Rules**

    ---

    Add, remove and disable rules from the command line, without opening a YAML
    file and without losing the comments in it.

    [:octicons-arrow-right-24: Managing rules](managing-rules.md)

-   :material-broadcast:{ .lg .middle } **Reacting to Decisions**

    ---

    Have the firewall tell your application what it decided about each request,
    over PSR-14 — for metrics, notifications or an audit trail, without parsing
    logs.

    [:octicons-arrow-right-24: Reacting to decisions](decision-events.md)

-   :material-map-marker-radius-outline:{ .lg .middle } **GeoIP Setup**

    ---

    Obtain, install, and refresh the MaxMind GeoLite2 databases the
    GeoLocation and ASN plugins need.

    [:octicons-arrow-right-24: GeoIP setup](geoip-setup.md)

</div>
