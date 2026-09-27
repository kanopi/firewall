<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Event;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Metrics\DecisionMetricsListener;
use Kanopi\Firewall\Metrics\StatsdRecorder;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Decision listeners declared in the configuration (#396).
 *
 * ```yaml
 * events:
 *   listeners:
 *     - class: "App\\Firewall\\NotifyOnPermanentBan"
 *       args: ["%env(SLACK_WEBHOOK)%"]
 *       events: [RequestBlocked]        # optional; every decision when omitted
 *
 * metrics:
 *   statsd: { host: 127.0.0.1, port: 8125, prefix: "site1." }
 * ```
 *
 * The dispatcher is a `create()` argument on purpose -- a dispatcher is an object the host
 * already has, and YAML cannot name one (#218). That is right for a host that has one and
 * leaves out the one that does not: a plain PHP site, or a CMS integration whose only
 * integration point is a config file, for whom "count blocks in StatsD" meant writing a
 * bootstrap. This is that list, built from configuration.
 *
 * It is not a dispatcher, and adds none. PSR-14 has no `addListener()`, so these cannot be
 * attached to the host's -- `Firewall::announce()` tells the host's dispatcher first and
 * then this, and a host that passes one and configures these gets both.
 *
 * **Read-only, as #218 settled.** A listener here receives the same events a PHP one does,
 * after the decision is made, and its return value is ignored.
 *
 * **A listener must not slow or break a request** (#222, #379). Each is called on its own,
 * so one that throws does not stop the rest; what it threw is logged and recorded in
 * `DegradedBackends`, so a status page can say a listener is failing rather than leaving it
 * to somebody reading logs.
 *
 * **A listener that cannot be built is a startup failure,** not an error on the first
 * blocked visitor: a class that does not exist, one that is not callable, an event name
 * that is not an event, a StatsD port that is not a port.
 */
final class ConfiguredListeners
{
    use LoggingTrait;

    /**
     * @param array<int, array{listener: callable, events: array<int, class-string<DecisionEvent>>|null, name: string}> $listeners
     *   Each listener, the events it wants (null for every one), and how to name it.
     */
    private function __construct(private readonly array $listeners)
    {
    }

    /**
     * The listeners a configuration declares.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     *
     * @throws ConfigurationException
     *   For a listener that cannot be built.
     */
    public static function fromConfig(array $config): self
    {
        $listeners = [];
        $events = is_array($config['events'] ?? null) ? $config['events'] : [];
        $declared = $events['listeners'] ?? [];

        if (!is_array($declared)) {
            throw new ConfigurationException('events.listeners must be a list of {class, args, events} entries');
        }

        foreach (array_values($declared) as $index => $entry) {
            $listeners[] = self::build($entry, sprintf('events.listeners.%d', $index));
        }

        $metrics = is_array($config['metrics'] ?? null) ? $config['metrics'] : [];

        if (($metrics['statsd'] ?? null) !== null) {
            $listeners[] = self::statsd($metrics['statsd']);
        }

        return new self($listeners);
    }

    /**
     * Tell every listener that wants it.
     *
     * Each on its own, so one that throws costs only itself.
     */
    public function dispatch(DecisionEvent $decisionEvent): void
    {
        foreach ($this->listeners as $listener) {
            if ($listener['events'] !== null && !in_array($decisionEvent::class, $listener['events'], true)) {
                continue;
            }

            try {
                ($listener['listener'])($decisionEvent);
            } catch (\Throwable $throwable) {
                $this->getLogger()->error('A configured decision listener threw, and was ignored', [
                    'listener' => $listener['name'],
                    'event' => $decisionEvent::class,
                    'listener_error' => $throwable->getMessage(),
                    'listener_error_type' => $throwable::class,
                ]);

                DegradedBackends::record('decision listener', $listener['name'], $throwable->getMessage());
            }
        }
    }

    /**
     * Whether there is anything to tell.
     */
    public function isEmpty(): bool
    {
        return $this->listeners === [];
    }

    /**
     * What is registered, for `firewall-doctor`.
     *
     * @return array<int, string>
     *   One line per listener.
     */
    public function describe(): array
    {
        return array_map(
            static fn (array $listener): string => $listener['events'] === null
                ? $listener['name']
                : sprintf('%s (%s)', $listener['name'], implode(', ', array_map(self::shortName(...), $listener['events']))),
            $this->listeners
        );
    }

    /**
     * Build one `events.listeners` entry.
     *
     * @param mixed $entry
     *   The entry.
     * @param string $path
     *   Where it is, for an error message.
     *
     * @return array{listener: callable, events: array<int, class-string<DecisionEvent>>|null, name: string}
     *
     * @throws ConfigurationException
     *   When it cannot be built.
     */
    private static function build(mixed $entry, string $path): array
    {
        if (is_string($entry)) {
            $entry = ['class' => $entry];
        }

        $class = is_array($entry) ? ($entry['class'] ?? null) : null;

        if (!is_string($class) || $class === '') {
            throw new ConfigurationException(sprintf('%s needs a class', $path));
        }

        $class = ltrim($class, '\\');

        if (!class_exists($class)) {
            throw new ConfigurationException(sprintf('%s: listener class %s does not exist', $path, $class));
        }

        $args = is_array($entry['args'] ?? null) ? $entry['args'] : [];

        try {
            $listener = new $class(...$args);
        } catch (\Throwable $throwable) {
            throw new ConfigurationException(sprintf('%s: %s could not be built: %s', $path, $class, $throwable->getMessage()), 0, $throwable);
        }

        if (!is_callable($listener)) {
            throw new ConfigurationException(sprintf(
                '%s: %s is not callable. A listener implements __invoke(DecisionEvent $event), as DecisionMetricsListener does',
                $path,
                $class
            ));
        }

        return [
            'listener' => $listener,
            'events' => self::events($entry['events'] ?? null, $path),
            'name' => $class,
        ];
    }

    /**
     * The StatsD exporter, from `metrics.statsd`.
     *
     * The same thing `docs/how-to/metrics.md` wires in PHP: `DecisionMetricsListener` over
     * `StatsdRecorder`, for every decision event. UDP only, as #222 settled: a metrics box
     * having a bad afternoon must not become a slow site.
     *
     * @param mixed $settings
     *   `metrics.statsd`: a map, or `true` for every default.
     *
     * @return array{listener: callable, events: null, name: string}
     *
     * @throws ConfigurationException
     *   For a setting of the wrong type.
     */
    private static function statsd(mixed $settings): array
    {
        if ($settings === true) {
            $settings = [];
        }

        if (!is_array($settings)) {
            throw new ConfigurationException('metrics.statsd must be a map of host, port, prefix, tags and rule_limit, or true');
        }

        $host = $settings['host'] ?? '127.0.0.1';
        $port = $settings['port'] ?? 8125;
        $prefix = $settings['prefix'] ?? '';
        $tags = $settings['tags'] ?? true;
        $ruleLimit = $settings['rule_limit'] ?? DecisionMetricsListener::DEFAULT_RULE_LIMIT;

        if (!is_string($host) || $host === '') {
            throw new ConfigurationException('metrics.statsd.host must be a host name or address');
        }

        if (!is_numeric($port) || (int) $port < 1 || (int) $port > 65535) {
            throw new ConfigurationException('metrics.statsd.port must be a port number');
        }

        if (!is_string($prefix)) {
            throw new ConfigurationException('metrics.statsd.prefix must be a string');
        }

        if (!is_numeric($ruleLimit) || (int) $ruleLimit < 0) {
            throw new ConfigurationException('metrics.statsd.rule_limit must be zero or more');
        }

        return [
            'listener' => new DecisionMetricsListener(
                new StatsdRecorder($host, (int) $port, $prefix, (bool) $tags),
                (int) $ruleLimit
            ),
            'events' => null,
            'name' => sprintf('StatsD to %s:%d', $host, (int) $port),
        ];
    }

    /**
     * The event classes an entry asks for.
     *
     * Short names -- `RequestBlocked` -- or full ones. Checked against the shipped events,
     * because a PSR-14 listener registered for a name that is not one is a listener that
     * never runs, and nothing says so.
     *
     * @param mixed $declared
     *   The `events:` value, or null for every event.
     *
     * @return array<int, class-string<DecisionEvent>>|null
     *
     * @throws ConfigurationException
     *   For a name that is not an event.
     */
    private static function events(mixed $declared, string $path): ?array
    {
        if ($declared === null) {
            return null;
        }

        $known = DecisionMetricsListener::eventClasses();
        $byShortName = array_combine(array_map(self::shortName(...), $known), $known);
        $classes = [];

        foreach (is_array($declared) ? $declared : [$declared] as $name) {
            $name = is_string($name) ? ltrim($name, '\\') : '';
            $class = $byShortName[$name] ?? (in_array($name, $known, true) ? $name : null);

            if ($class === null) {
                throw new ConfigurationException(sprintf(
                    '%s.events: "%s" is not a decision event (%s)',
                    $path,
                    $name,
                    implode(', ', array_keys($byShortName))
                ));
            }

            $classes[] = $class;
        }

        return array_values(array_unique($classes));
    }

    /**
     * An event class without its namespace.
     */
    private static function shortName(string $class): string
    {
        return substr((string) strrchr('\\' . $class, '\\'), 1);
    }
}
