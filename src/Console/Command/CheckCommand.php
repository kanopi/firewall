<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PanicSwitch;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Kanopi\Firewall\Utility\RequestPath;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\HttpFoundation\Request;

/**
 * `firewall check`: ask whether a given request would be blocked, and by what (#105).
 *
 * Assembling the call by hand has three edges that fail quietly: `evaluate()` returns
 * TRUE under the CLI unless the mode is `exception`; overrides are bracket paths, not
 * nested arrays; and a block writes to storage, records an offense and escalates. This
 * handles all three. Storage is swapped for a throwaway by default, so a check cannot
 * ban anyone; --live-storage consults the real block list on purpose.
 *
 * The exit status is the verdict, which is why "blocked" is not lumped in with "error".
 */
final class CheckCommand extends FirewallCommand
{
    private const EXIT_ALLOWED = 0;

    private const EXIT_BLOCKED = 1;

    private const EXIT_CHALLENGED = 2;

    private const EXIT_REDIRECTED = 3;

    protected const EXIT_USAGE = 64;

    private const EXIT_INTERNAL = 70;

    protected function configure(): void
    {
        $this
            ->setName('check')
            ->setDescription('Ask whether a given request would be blocked, and by what')
            ->addOption('config', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Firewall config file. Repeatable; merged in order')
            ->addOption('ip', null, InputOption::VALUE_REQUIRED, 'Client IP (IPv4 or IPv6). Default 127.0.0.1')
            ->addOption('url', null, InputOption::VALUE_REQUIRED, 'Path, with optional query string. Default /')
            ->addOption('method', null, InputOption::VALUE_REQUIRED, 'HTTP method. Default GET, or POST with --body')
            ->addOption('header', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, '"Name: value". Repeatable')
            ->addOption('body', null, InputOption::VALUE_REQUIRED, 'Request body')
            ->addOption('script-name', null, InputOption::VALUE_REQUIRED, 'The .php file the server ran, such as /wp-login.php')
            ->addOption('explain', null, InputOption::VALUE_NONE, 'Every rule consulted, and how long each took')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->addOption('lint', null, InputOption::VALUE_NONE, 'Check the configuration itself, with no request')
            ->addOption('live-storage', null, InputOption::VALUE_NONE, 'Consult the real block list. A block is then recorded')
            ->setHelp(<<<'TEXT'
            Storage is a throwaway unless --live-storage is given, so a check cannot ban
            the address it was asked about.

            Exit codes:
              0  allowed          64  usage error
              1  blocked          70  internal error
              2  challenged
              3  redirected

            Examples:
              firewall check --config=firewall.yml --ip=203.0.113.5 --url=/wp-admin/
              firewall check --config=firewall.yml --url='/search?q=1%27+UNION+SELECT' --explain
              firewall check --config=firewall.yml --header='User-Agent: sqlmap/1.8' --json
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        // The options as getopt() returned them, which is the shape everything below
        // was written against: a key only for what was given, a flag as FALSE, and a
        // value given more than once as a list.
        $options = [];

        foreach (['config', 'header'] as $name) {
            /** @var array<int, string> $values */
            $values = $input->getOption($name);

            if ($values !== []) {
                $options[$name] = $values;
            }
        }

        foreach (['ip', 'url', 'method', 'body', 'script-name'] as $name) {
            $value = $input->getOption($name);

            if (is_string($value) && $value !== '') {
                $options[$name] = $value;
            }
        }

        foreach (['explain', 'json', 'lint', 'live-storage'] as $name) {
            if ($input->getOption($name) === true) {
                $options[$name] = false;
            }
        }

        $configs = $this->repeatable($options, 'config');

        if ($configs === []) {
            $this->err("Error: at least one --config=FILE is required.\n\n");
            $this->usage();
            return self::EXIT_USAGE;
        }

        foreach ($configs as $config) {
            if (!is_file($config) || !is_readable($config)) {
                $this->err(sprintf('Error: config file not readable: %s%s', $config, PHP_EOL));
                return self::EXIT_USAGE;
            }
        }

        // --lint answers a different question and answers it before anything else:
        // what is wrong with these rules, regardless of any request. It takes no --url,
        // --ip or --header, so it is handled here rather than threaded through the
        // evaluation below, and it exits on its own terms.
        if (isset($options['lint'])) {
            $findings = (new \Kanopi\Firewall\Diagnostics\ConfigLinter($configs))->run();
            $tally = \Kanopi\Firewall\Diagnostics\Doctor::tally($findings);

            if (isset($options['json'])) {
                $this->out(json_encode([
                    'findings' => array_map(
                        static fn(\Kanopi\Firewall\Diagnostics\Diagnosis $diagnosis): array => $diagnosis->toArray(),
                        $findings
                    ),
                    'summary' => $tally,
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

                return $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::ERROR] > 0 ? self::EXIT_BLOCKED : self::EXIT_ALLOWED;
            }

            $marks = [
                \Kanopi\Firewall\Diagnostics\Diagnosis::OK => '  ✓ ',
                \Kanopi\Firewall\Diagnostics\Diagnosis::WARNING => '  ! ',
                \Kanopi\Firewall\Diagnostics\Diagnosis::ERROR => '  ✗ ',
            ];

            $this->out("\n");

            foreach ($findings as $finding) {
                $write = $finding->status === \Kanopi\Firewall\Diagnostics\Diagnosis::ERROR ? $this->err(...) : $this->out(...);
                $write($marks[$finding->status] . $finding->title . "\n");

                if ($finding->detail !== null) {
                    $write('      ' . $finding->detail . "\n");
                }
            }

            $this->out(sprintf(
                "\n  %d error%s, %d warning%s\n",
                $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::ERROR],
                $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::ERROR] === 1 ? '' : 's',
                $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::WARNING],
                $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::WARNING] === 1 ? '' : 's'
            ));

            return $tally[\Kanopi\Firewall\Diagnostics\Diagnosis::ERROR] > 0 ? self::EXIT_BLOCKED : self::EXIT_ALLOWED;
        }

        $ip = (string) $this->single($options, 'ip', '127.0.0.1');

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->err(sprintf('Error: --ip is not a valid address: %s%s', $ip, PHP_EOL));
            return self::EXIT_USAGE;
        }

        $url = (string) $this->single($options, 'url', '/');
        $body = array_key_exists('body', $options) ? (string) $this->single($options, 'body', '') : null;
        // A body without a method almost always means POST; defaulting to GET would
        // quietly test something the caller did not describe.
        $method = strtoupper((string) $this->single($options, 'method', $body === null ? 'GET' : 'POST'));

        $server = ['REMOTE_ADDR' => $ip];

        // A directly requested file is its own SCRIPT_NAME, which is what makes
        // getPathInfo() come back as "/" in production (#414). Request::create() sets
        // no script at all, so without this the check answers for a request the site
        // never receives, and says a rule matches that never does.
        $scriptName = $this->single($options, 'script-name');

        if ($scriptName !== null) {
            if ($scriptName === '' || $scriptName[0] !== '/' || !str_ends_with(strtolower($scriptName), '.php')) {
                $this->err("Error: --script-name must be a path to a .php file, such as /wp-login.php\n");
                return self::EXIT_USAGE;
            }

            $server['SCRIPT_NAME'] = $scriptName;
            $server['PHP_SELF'] = $scriptName;
            $server['SCRIPT_FILENAME'] = $scriptName;
        }

        foreach ($this->repeatable($options, 'header') as $header) {
            if (!str_contains($header, ':')) {
                $this->err(sprintf('Error: --header must be NAME:VALUE, got: %s%s', $header, PHP_EOL));
                return self::EXIT_USAGE;
            }

            [$name, $value] = explode(':', $header, 2);
            $name = strtoupper(str_replace('-', '_', trim($name)));
            $value = ltrim($value);

            // Content-Type and Content-Length are CGI variables in their own right,
            // not HTTP_ prefixed. Symfony reads them from those exact keys, so a
            // --header='Content-Type: application/json' would otherwise be ignored and
            // the body would parse as the wrong type.
            $server[in_array($name, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $name : 'HTTP_' . $name] = $value;
        }

        $testHandler = new TestHandler(Level::Debug);

        // The two overrides that make this work at all. Bracket paths, not nested
        // arrays — see the header comment.
        $overrides = [
            // Without this, evaluate() short-circuits in CLI and reports everything as
            // allowed.
            '[global][mode]' => 'exception',

            // And without this, a panic file would win the argument -- it overrides
            // `global.mode` by design (#207), which is exactly the override above, so
            // an active switch would land this script back in the "everything is
            // allowed" hole the mode override exists to avoid.
            //
            // Suppressed for the evaluation, reported separately below. The question
            // this tool answers is "which rule matches this request", and that answer
            // does not change when the switch is on; what changes is what the firewall
            // then does about it, and saying both is more useful than either.
            '[global][panic_file]' => '',

            // Same reasoning for lockdown: it refuses before any bucket is consulted,
            // so leaving it on would make this report "refused" for every request and
            // tell you nothing about which rule would match (#304). Suppressed here,
            // reported below.
            //
            // The `mode` override above only removes the `mode: lockdown` shorthand.
            // The flag is the spelling a `mode: exception` host has to use, and without
            // this line every request it asked about came back refused (#409).
            '[global][lockdown]' => false,
        ];

        $lockdown = ($loadedGlobal = Config::load(array_merge([dirname(__DIR__, 3) . '/config/config.yml'], $configs))['global'] ?? [])
            && (($loadedGlobal['mode'] ?? null) === 'lockdown' || ($loadedGlobal['lockdown'] ?? false) === true)
            ? array_values(array_filter(
                is_array($loadedGlobal['lockdown_allow'] ?? null) ? $loadedGlobal['lockdown_allow'] : [],
                static fn($v): bool => is_string($v) && trim($v) !== ''
            ))
            : null;

        // Read before the overrides above hide it. Config::load() does not throw --
        // it collects failures rather than raising them -- so a broken config still
        // reaches the firewall build below, which reports it properly.
        $panic = PanicSwitch::read(
            Config::load(array_merge([dirname(__DIR__, 3) . '/config/config.yml'], $configs))['global']['panic_file'] ?? null
        );

        $liveStorage = isset($options['live-storage']);

        if ($liveStorage) {
            // On stderr so it cannot corrupt --json on stdout. Worth saying out loud:
            // the block path records an offense and applies blocking_escalation, so a
            // "check" against live storage can ban the address being asked about.
            $this->err(
                "Warning: --live-storage is on. A blocked verdict will be RECORDED in the\n"
                . "         configured backend, which can ban the address you are testing.\n"
            );
        }

        if (!$liveStorage) {
            // A check must not be able to ban anyone. The block path writes to
            // storage, records an offense and escalates; swapping in a per-process
            // store makes all of that inert.
            $overrides['[storage][type]'] = InMemoryStorage::class;
        }

        try {
            $inputs = $configs;
            $inputs[] = ['logger' => [['class' => $testHandler]]];

            $firewall = Firewall::create($inputs, $overrides);
        } catch (\Throwable $throwable) {
            $this->err(sprintf(
                "Error: could not build the firewall from that configuration.\n  %s: %s\n",
                $throwable::class,
                $throwable->getMessage(),
            ));
            return self::EXIT_INTERNAL;
        }

        // A form body is what the application would read as post fields, and what
        // `post.*` rules match on. Request::create() keeps it as raw content, so
        // without this no `post.*` rule could ever match a check. Parsed as
        // Symfony's createFromGlobals() parses one -- for the methods that send a
        // form -- and when the Content-Type says form, or says nothing, as `curl -d`
        // assumes.
        $parameters = [];
        $contentType = strtolower($server['CONTENT_TYPE'] ?? 'application/x-www-form-urlencoded');
        $sendsForm = $body !== null
            && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
            && str_starts_with($contentType, 'application/x-www-form-urlencoded');

        if ($sendsForm) {
            parse_str($body, $parameters);
            $server['CONTENT_TYPE'] ??= 'application/x-www-form-urlencoded';
        }

        $request = Request::create($url, $method, $parameters, [], [], $server, $body);

        // A .php URL other than the front controller is the case this check gets
        // wrong by default: here it matches the path as typed, while a site serving
        // that file directly matches "/" (#414). On stderr, so --json stays parseable.
        $urlPath = (string) parse_url($url, PHP_URL_PATH);

        $servedDirectly = $scriptName === null
            && ($loadedGlobal['path_source'] ?? RequestPath::PATHINFO) !== RequestPath::SCRIPT_NAME
            && str_ends_with(strtolower($urlPath), '.php')
            && strtolower(basename($urlPath)) !== 'index.php';

        if ($servedDirectly) {
            $this->err(sprintf(
                "Note: %s is a PHP file. If the web server runs it directly, as WordPress runs\n"
                . "      wp-login.php, the firewall on the site matches it as \"/\" under the default\n"
                . "      global.path_source, not as the path checked here. Add --script-name=%s to\n"
                . "      check what the site sees, or set path_source: script_name.\n",
                $urlPath,
                $urlPath,
            ));
        }

        $verdict = 'allowed';
        $status = null;
        $reason = null;
        $location = null;

        try {
            $firewall->evaluate($request);
        } catch (FirewallBlockedException $exception) {
            $verdict = 'blocked';
            $status = $exception->getCode();
            $reason = $exception->getMessage();
        } catch (FirewallRedirectException $exception) {
            // Its own verdict, not a block: the visitor is sent somewhere rather than
            // refused, and a CI gate asserting a redirect rule works needs to be able to
            // tell the two apart (#406). Before this was caught it fell through to the
            // Throwable arm below and reported an internal error.
            $verdict = 'redirected';
            $status = $exception->getStatusCode();
            $location = $exception->getLocation();
        } catch (ChallengeRequiredException $exception) {
            $verdict = 'challenged';
            $reason = $exception->getMessage();
        } catch (ChallengeSolvedException) {
            $verdict = 'allowed';
            $reason = 'a challenge solution was accepted';
        } catch (\Throwable $exception) {
            $this->err(sprintf(
                "Error: evaluation threw unexpectedly.\n  %s: %s\n",
                $exception::class,
                $exception->getMessage(),
            ));
            return self::EXIT_INTERNAL;
        }

        // -----------------------------------------------------------------------
        // Attribution and per-plugin detail, read back out of the log.
        //
        // FirewallBlockedException carries only a message and a status code, so the
        // responsible plugin comes from the log line the block path already writes.
        // Reading the log rather than re-evaluating each plugin matters: a second pass
        // would repeat every side effect, including any outbound reputation lookup.
        // -----------------------------------------------------------------------

        $plugin = null;
        $pluginRole = null;
        $recorded = null;
        $marks = [];
        $lastMatched = null;
        $evaluated = [];

        foreach ($testHandler->getRecords() as $logRecord) {
            $context = $logRecord->context;

            // Attribution is keyed on the firewall's own decision messages, NOT on the
            // mere presence of a `plugin` context key. Individual plugins log their own
            // debug lines carrying that key, so a looser match reports a "matched
            // plugin" on requests where nothing matched at all.
            $decision = match (true) {
                str_contains($logRecord->message, 'Request blocked by plugin') => 'blocked by',
                str_contains($logRecord->message, 'Request bypassed') => 'allowed by',
                str_contains($logRecord->message, 'Sending redirect response') => 'redirected by',
                str_contains($logRecord->message, 'would be blocked') => 'would be blocked by',
                str_contains($logRecord->message, 'would be challenged') => 'would be challenged by',
                default => null,
            };

            if ($decision !== null && isset($context['plugin_name']) && is_string($context['plugin_name'])) {
                $plugin = $context['plugin_name'];
                $pluginRole = $decision;
            }

            // PluginManager logs this only when a plugin actually returns TRUE, so it
            // is a safe fallback for paths that do not emit one of the messages above
            // — the challenge flow among them.
            $matched = str_contains($logRecord->message, 'Plugin evaluation matched')
                && isset($context['plugin'])
                && is_string($context['plugin']);

            if ($matched) {
                $lastMatched = $context['plugin'];
            }

            // Non-terminal outcomes throw nothing, so the verdict cannot come from an
            // exception. They are still what happened to the request, and a checker that
            // reported "allowed" for a honeypot hit would be describing the response and
            // hiding the consequence (#202).
            if (str_contains($logRecord->message, 'Client recorded without being refused')) {
                $recorded = is_string($context['plugin_name'] ?? null) ? $context['plugin_name'] : true;
            }

            if (str_contains($logRecord->message, 'Request marked') && isset($context['mark']) && is_string($context['mark'])) {
                $marks[] = $context['mark'];
            }

            if (isset($context['evaluated_plugins']) && is_array($context['evaluated_plugins'])) {
                foreach ($context['evaluated_plugins'] as $entry) {
                    if (is_array($entry) && isset($entry['plugin'])) {
                        $evaluated[] = [
                            'plugin' => (string) $entry['plugin'],
                            'matched' => (bool) ($entry['result'] ?? false),
                            'time_ms' => is_numeric($entry['time_ms'] ?? null) ? (float) $entry['time_ms'] : 0.0,
                            // A scheduled rule outside its window did not evaluate at
                            // all. Reporting it as a rule that ran and matched nothing
                            // would be the wrong answer to "why wasn't this caught?"
                            // (#205).
                            'asleep' => ($entry['active'] ?? true) === false,
                            'window' => is_string($entry['window'] ?? null) ? $entry['window'] : null,
                        ];
                    }
                }
            }
        }

        // A verdict that is not "allowed" must have had something behind it; fall back
        // to the last confirmed plugin match rather than reporting no attribution.
        if ($plugin === null && $verdict !== 'allowed' && $lastMatched !== null) {
            $plugin = $lastMatched;
            $pluginRole = ['challenged' => 'challenged by', 'redirected' => 'redirected by'][$verdict] ?? 'blocked by';
        }

        // Configured inventory, so --explain can also show what never ran.
        $configured = [];

        try {
            $merged = PluginConfigNormalizer::normalize(
                Config::load(
                    array_merge([dirname(__DIR__, 3) . '/config/config.yml'], $configs),
                    $overrides,
                )
            );

            foreach (PluginConfigNormalizer::partitionAndSort($merged['plugins'] ?? []) as $response => $plugins) {
                foreach ($plugins as $entry) {
                    $class = is_string($entry['plugin'] ?? null) ? $entry['plugin'] : '';

                    if ($class !== '') {
                        // The name the log will call it by, resolved the same way
                        // AbstractPluginBase::getName() resolves it: `metadata.name`
                        // when set, the class otherwise. Without this the inventory
                        // knows a rule only by its class, and a rule that was given a
                        // name -- which #182 added and the docs recommend, so two
                        // IpAddress rules can be told apart -- never matches what ran
                        // and is reported as unreached directly below a line saying it
                        // MATCHed.
                        $declaredName = $entry['metadata']['name'] ?? null;
                        $name = is_string($declaredName) && $declaredName !== ''
                            ? $declaredName
                            : substr((string) strrchr('\\' . $class, '\\'), 1);

                        $configured[] = [
                            'response' => (string) $response,
                            'class' => $class,
                            'name' => $name,
                            'weight' => is_numeric($entry['weight'] ?? null) ? (int) $entry['weight'] : 0,
                        ];
                    }
                }
            }
        } catch (\Throwable) {
            // Inventory is a convenience for --explain; the verdict above stands
            // regardless, and failing here must not change the exit code.
            $configured = [];
        }

        $evaluatedNames = array_column($evaluated, 'plugin');

        // Recorded outranks allowed as a description: the request was served, and the
        // client is on the block list from here on. Anything terminal outranks both.
        if ($verdict === 'allowed' && $recorded !== null) {
            $verdict = 'recorded';
            $plugin = is_string($recorded) ? $recorded : $plugin;
            $pluginRole = 'recorded by';
        }

        $result = [
            'verdict' => $verdict,
            'plugin' => $plugin,
            'marks' => array_values(array_unique($marks)),
            'status' => $status,
            'reason' => $reason,
            'location' => $location,
            'request' => [
                'ip' => $ip,
                'method' => $request->getMethod(),
                // The path the rules were matched against, which is not always the
                // URL's: see path_source (#414).
                'path' => RequestPath::of($request),
                'query' => $request->getQueryString(),
            ],
            'storage' => $liveStorage ? 'configured backend' : 'throwaway (in-memory)',
        ];

        if ($lockdown !== null) {
            $result['lockdown'] = ['active' => true, 'allowed' => $lockdown];
        }

        if ($panic['active'] && $panic['mode'] !== null) {
            $result['panic_switch'] = [
                'active' => true,
                'path' => $panic['path'],
                'mode' => $panic['mode']->value,
            ];
        } elseif ($panic['problem'] !== null) {
            $result['panic_switch'] = [
                'active' => false,
                'path' => $panic['path'],
                'problem' => $panic['problem'],
            ];
        }

        if (isset($options['explain'])) {
            $result['evaluated'] = $evaluated;
            $result['configured'] = $configured;
        }

        // -----------------------------------------------------------------------
        // Output
        // -----------------------------------------------------------------------

        if (isset($options['json'])) {
            $this->out(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        } else {
            $label = [
                'allowed' => 'ALLOWED',
                'blocked' => 'BLOCKED',
                'challenged' => 'CHALLENGED',
                'redirected' => 'REDIRECTED',
                'recorded' => 'RECORDED',
            ][$verdict];

            $this->out(sprintf("%s  %s %s\n", $label, $request->getMethod(), $url));
            $this->out(sprintf("  client            %s\n", $ip));

            // Only when it differs from what was typed, which is exactly when it
            // explains a surprising verdict.
            if (RequestPath::of($request) !== (string) parse_url($url, PHP_URL_PATH)) {
                $this->out(sprintf("  matched as path   %s\n", RequestPath::of($request)));
            }

            if ($plugin !== null) {
                $this->out(sprintf("  %-17s %s\n", $pluginRole ?? 'matched plugin', $plugin));
            }

            if ($status !== null) {
                $this->out(sprintf("  status            %d\n", $status));
            }

            if ($location !== null) {
                $this->out(sprintf("  location          %s\n", $location));
            }

            if ($reason !== null && $reason !== '') {
                $this->out(sprintf("  reason            %s\n", $reason));
            }

            $this->out(sprintf("  storage           %s\n", $result['storage']));

            if ($verdict === 'recorded') {
                $this->out("  effect            served now, refused from the next request onward\n");
            }

            if ($marks !== []) {
                $this->out(sprintf("  marked            %s\n", implode(', ', array_unique($marks))));
            }

            if (isset($result['lockdown'])) {
                $this->out(sprintf(
                    "  lockdown          ACTIVE — only %s %s served; this verdict describes the rules, not what the site is doing\n",
                    $lockdown === [] ? 'nobody' : implode(', ', $lockdown),
                    $lockdown === [] ? 'is' : 'are'
                ));
            }

            // On stdout with the rest of the verdict, not stderr: this changes how to
            // read the line above it, so it has to travel with it.
            // The same two conditions that put `panic_switch` in the result.
            if ($panic['active'] && $panic['mode'] !== null) {
                $this->out(sprintf(
                    "  panic switch      ACTIVE — %s is forcing mode %s, so the site is not behaving as this verdict says\n",
                    $panic['path'],
                    $panic['mode']->value
                ));
            } elseif ($panic['problem'] !== null) {
                $this->out(sprintf("  panic switch      IGNORED — %s %s\n", $panic['path'], $panic['problem']));
            }

            if (isset($options['explain'])) {
                $this->out("\nPlugins evaluated, in order:\n");

                if ($evaluated === []) {
                    $this->out("  (none — no plugins were reached)\n");
                }

                foreach ($evaluated as $entry) {
                    if ($entry['asleep']) {
                        $this->out(sprintf(
                            "  %-7s %-28s %s\n",
                            'ASLEEP',
                            $entry['plugin'],
                            $entry['window'] === null ? 'outside its active window' : 'awake ' . $entry['window'],
                        ));

                        continue;
                    }

                    $this->out(sprintf(
                        "  %-7s %-28s %6.2f ms\n",
                        $entry['matched'] ? 'MATCH' : 'pass',
                        $entry['plugin'],
                        $entry['time_ms'],
                    ));
                }

                // What did not run is often the actual answer to "why wasn't this
                // caught?" — an earlier plugin matched and short-circuited the chain.
                //
                // The log records a plugin's *display* name ("IP Address") while the
                // config carries its FQCN (...\IpAddress), so both sides are reduced to
                // lowercase alphanumerics before comparing. A case-sensitive match here
                // reported every plugin as unreached, including ones that had visibly
                // just run.
                $fold = static fn(string $value): string
                    => strtolower((string) preg_replace('/[^A-Za-z0-9]/', '', $value));

                $ran = array_map($fold, $evaluatedNames);

                $skipped = array_values(array_filter(
                    $configured,
                    static fn(array $entry): bool => !in_array($fold((string) $entry['name']), $ran, true),
                ));

                if ($skipped !== []) {
                    $this->out("\nConfigured but not reached:\n");

                    foreach ($skipped as $entry) {
                        // The name first, because that is what the section above calls
                        // it and what a log line will say. The class stays, because a
                        // name is only unique if somebody made it so.
                        $this->out(sprintf(
                            "  %-9s %-30s %-40s weight %d\n",
                            $entry['response'],
                            $entry['name'],
                            $entry['class'],
                            $entry['weight']
                        ));
                    }
                }
            }
        }

        return match ($verdict) {
            'blocked' => self::EXIT_BLOCKED,
            'challenged' => self::EXIT_CHALLENGED,
            'redirected' => self::EXIT_REDIRECTED,
            default => self::EXIT_ALLOWED,
        };
    }

    /**
     * Print usage.
     */
    private function usage(): void
    {
        $script = 'firewall check';

        $this->out(<<<TXT
        Check whether a request would be blocked by a firewall configuration.

        USAGE
          {$script} --config=FILE [options]

        REQUIRED
          --config=FILE      Firewall config file. Repeatable; merged in order,
                             exactly as Firewall::create() merges them.

        REQUEST
          --ip=ADDRESS       Client IP (IPv4 or IPv6). Default 127.0.0.1
          --url=URL          Path, with optional query string. Default /
          --method=VERB      HTTP method. Default GET, or POST when --body is given
          --header=NAME:VAL  Request header. Repeatable
          --body=STRING      Request body
          --script-name=FILE The PHP file the web server runs for this URL. Default:
                             the front controller. Set it to check a file served
                             directly, as WordPress serves /wp-login.php:
                             --url=/wp-login.php --script-name=/wp-login.php

        OUTPUT
          --explain          Show every plugin that evaluated, with result and
                             timing, plus the plugins that never ran
          --json             Machine-readable output
          --lint             Report what is wrong with the rules and exit, without
                             evaluating a request. Takes no --url or --ip.

        BEHAVIOUR
          --live-storage     Use the configured storage backend instead of a
                             throwaway. The durable blocklist is then consulted —
                             but a block will also be RECORDED, which can ban the
                             address you are asking about. Off by default.

        EXIT CODES
          0  allowed          64  usage error
          1  blocked          70  internal error
          2  challenged
          3  redirected

        EXAMPLES
          {$script} --config=firewall.yml --ip=203.0.113.5 --url=/wp-admin/
          {$script} --config=firewall.yml --url='/search?q=1%27+UNION+SELECT' --explain
          {$script} --config=firewall.yml --header='User-Agent: sqlmap/1.8' --json

        TXT);
    }

    /**
     * Normalise a repeatable option into a list.
     *
     * getopt() hands back a string for one occurrence and an array for several,
     * which is a reliable source of "works with two headers, breaks with one".
     *
     * @param array<string, mixed> $options
     *
     * @return array<int, string>
     */
    private function repeatable(array $options, string $name): array
    {
        if (!isset($options[$name])) {
            return [];
        }

        $value = $options[$name];

        return array_values(array_map(strval(...), is_array($value) ? $value : [$value]));
    }

    /**
     * Read a single-valued option.
     *
     * getopt() hands back an array when a flag is repeated, so a bare
     * `(string) $options['ip']` emits "Array to string conversion" the moment
     * someone passes `--ip` twice. Last occurrence wins, which is what a reader
     * would assume from the command line they typed.
     *
     * @param array<string, mixed> $options
     *
     */
    private function single(array $options, string $name, ?string $default = null): ?string
    {
        if (!array_key_exists($name, $options)) {
            return $default;
        }

        // One value: Console keeps the last of a repeated single-valued option, so
        // this never sees the list getopt() used to hand back.
        $value = $options[$name];

        return is_scalar($value) ? (string) $value : $default;
    }
}
