<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\CrsVerdict;
use Kanopi\Crs\Request\RequestData;
use Symfony\Component\HttpFoundation\Request;

/**
 * OWASP Core Rule Set plugin.
 *
 * Adapts kanopi/crs-engine to the firewall's plugin contract. The engine
 * parses CRS rule files and evaluates HTTP requests against them; this
 * plugin translates Symfony Request to the engine's framework-agnostic DTO,
 * runs evaluation, and maps the engine's verdict to the firewall's
 * allow/block decision.
 *
 * Response-side evaluation (RESPONSE-* rules for SQL error / stack-trace
 * leakage) lives in a follow-up — see firewall issue #69.
 *
 * A note on thresholds, because it surprises people arriving from stock CRS:
 * a rule carrying a `block` / `deny` / `drop` action rejects on first match
 * without consulting the anomaly score, and in the bundled rule set every
 * score-contributing rule carries one. The threshold is therefore inert as
 * shipped, and raising it is not the false-positive lever it looks like —
 * `disabled_rules` / `disabled_categories` are. See anomalyThresholds().
 *
 * The cause is upstream: crs-engine's parser inlines `%{tx.*}` macros at
 * build time and flattens the runtime accumulators feeding 949110 / 959100
 * to a literal 0, so CRS's own anomaly-evaluation rules never fire. Nothing
 * here can fix that; when it is fixed the threshold goes live as-is.
 */
class Crs extends AbstractPluginBase
{
    /**
     * Default inbound (request-side) anomaly score threshold.
     */
    protected const DEFAULT_INBOUND_THRESHOLD = 5;

    /**
     * Default outbound (response-side) anomaly score threshold.
     */
    protected const DEFAULT_OUTBOUND_THRESHOLD = 4;

    /**
     * Engine threshold key => the config spellings that set it, preferred
     * spelling first.
     *
     * The engine names its two thresholds after CRS severities, which reads
     * as though there is one threshold per severity. There is not: `critical`
     * is the single inbound threshold and `error` the single outbound one.
     * `inbound` / `outbound` are the honest names and the ones documented;
     * the severity names stay accepted so existing config keeps working.
     *
     * @var array<string, list<string>>
     */
    protected const THRESHOLD_KEYS = [
        'critical' => ['inbound', 'critical'],
        'error'    => ['outbound', 'error'],
    ];

    /**
     * Constructed once on first evaluate(); subsequent calls reuse it.
     * The engine itself memoises the loaded ruleset per directory for the
     * lifetime of the PHP process, so this object is cheap to hold.
     */
    protected ?CrsEngine $engine = null;

    /**
     * Last verdict produced by evaluate(), so getStatusCode() and
     * getExpirationTime() can answer based on what fired.
     */
    protected ?CrsVerdict $lastVerdict = null;

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'CRS';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Evaluate requests against the OWASP Core Rule Set (SQLi, XSS, LFI, RCE, scanner detection, protocol enforcement)';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $crsVerdict = $this->getEngine()->evaluate($this->adaptRequest($request));
        $this->lastVerdict = $crsVerdict;

        // TRUE means "this plugin matched", not "allow the request" — the
        // PluginManager applies the entry's `response:` when we return TRUE.
        // See PluginInterface::evaluate().
        if ($crsVerdict->isBlocked()) {
            $this->getLogger()->info('CRS blocked request', $this->getContext($request, [
                'rule_id'      => $crsVerdict->blockingRuleId,
                'total_score'  => $crsVerdict->totalScore,
                'scores'       => $crsVerdict->scores,
                'matched_rule' => $crsVerdict->matchedRules[0]['msg'] ?? '',
                'matched_data' => $crsVerdict->matchedRules[0]['matched_data'] ?? '',
            ]));
            return true;
        }

        // Rules fired but the anomaly score stayed under threshold, or the
        // plugin is in monitor mode. Report no match so the request proceeds.
        if ($crsVerdict->matchedRules !== []) {
            $this->getLogger()->debug('CRS matched but did not block', $this->getContext($request, [
                'action'          => $crsVerdict->action,
                'matched_rules'   => count($crsVerdict->matchedRules),
                'total_score'     => $crsVerdict->totalScore,
            ]));
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return (int) ($this->config['block_status'] ?? 403);
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return (int) ($this->config['block_duration'] ?? 3600);
    }

    /**
     * Expose the most recent verdict to integrators that want richer
     * decision context than just the bool from evaluate().
     */
    public function getLastVerdict(): ?CrsVerdict
    {
        return $this->lastVerdict;
    }

    /**
     * Lazily construct the CRS engine using plugin config. The engine
     * memoises its compiled ruleset per process, so re-instantiating here
     * across requests is cheap.
     */
    protected function getEngine(): CrsEngine
    {
        if (!$this->engine instanceof CrsEngine) {
            $this->engine = new CrsEngine(new CrsConfig(
                paranoia:           (int) ($this->config['paranoia'] ?? 1),
                mode:               (string) ($this->config['mode'] ?? CrsConfig::MODE_BLOCK),
                anomalyThresholds:  $this->anomalyThresholds(),
                disabledRules:      array_map(intval(...), $this->config['disabled_rules'] ?? []),
                disabledCategories: $this->config['disabled_categories'] ?? [],
                rulesPath:          $this->config['rules_path'] ?? null,
            ));
        }

        return $this->engine;
    }

    /**
     * Normalise `anomaly_thresholds` into the two thresholds the engine reads.
     *
     * The engine has exactly two: inbound (the request-side anomaly score at
     * or above which a request is blocked) and outbound (the response-side
     * equivalent, inert until response evaluation lands — see issue #69). It
     * keys them `critical` and `error`, which invites operators to supply a
     * `warning` and a `notice` alongside them and believe all four do
     * something. They do not — anything beyond the two is read nowhere, so
     * say so rather than accepting it in silence (#93).
     *
     * @return array<string, int>
     *   Engine-shaped thresholds, always with both keys populated.
     */
    protected function anomalyThresholds(): array
    {
        $configured = $this->config['anomaly_thresholds'] ?? [];
        if (!is_array($configured)) {
            $this->getLogger()->warning('CRS anomaly_thresholds must be a mapping — ignoring it and using defaults', [
                'plugin' => $this->getName(),
                'given'  => get_debug_type($configured),
            ]);
            $configured = [];
        }

        $thresholds = [
            'critical' => self::DEFAULT_INBOUND_THRESHOLD,
            'error'    => self::DEFAULT_OUTBOUND_THRESHOLD,
        ];

        // The preferred spelling is tried first, so it wins when both are
        // present — config migrated key by key behaves the same in either
        // write order.
        foreach (self::THRESHOLD_KEYS as $engineKey => $names) {
            foreach ($names as $name) {
                if (!isset($configured[$name])) {
                    continue;
                }

                if (!is_numeric($configured[$name])) {
                    $this->getLogger()->warning('CRS anomaly threshold is not a number — using the default', [
                        'plugin'  => $this->getName(),
                        'key'     => $name,
                        'given'   => get_debug_type($configured[$name]),
                        'default' => $thresholds[$engineKey],
                    ]);
                    continue;
                }

                $thresholds[$engineKey] = (int) $configured[$name];
                break;
            }
        }

        $accepted = array_merge(...array_values(self::THRESHOLD_KEYS));
        $inert = array_values(array_diff(array_map(strval(...), array_keys($configured)), $accepted));

        if ($inert !== []) {
            $this->getLogger()->warning('CRS anomaly_thresholds keys are ignored — the engine has only an inbound and an outbound threshold', [
                'plugin'   => $this->getName(),
                'ignored'  => $inert,
                'accepted' => $accepted,
                'hint'     => 'Per-severity score contributions are fixed by CRS and are not configurable. To silence a false positive use disabled_rules or disabled_categories.',
            ]);
        }

        return $thresholds;
    }

    /**
     * Adapt a Symfony Request to the engine's framework-agnostic DTO.
     *
     * The engine deliberately does not depend on Symfony — this is the
     * single integration seam between the firewall and crs-engine.
     */
    protected function adaptRequest(Request $request): RequestData
    {
        // Symfony's FileBag guarantees each leaf is an UploadedFile — single
        // uploads as objects, multi-uploads (`<input multiple>`) as arrays
        // of objects. No null / non-object cases reach us.
        $files = [];
        foreach ($request->files->all() as $name => $upload) {
            $list = is_array($upload) ? $upload : [$upload];
            foreach ($list as $file) {
                $files[] = [
                    'name'     => (string) $name,
                    'filename' => $file->getClientOriginalName(),
                    'mime'     => $file->getClientMimeType(),
                    'size'     => (int) $file->getSize(),
                    'tmp_name' => (string) $file->getRealPath(),
                ];
            }
        }

        return new RequestData(
            method:      $request->getMethod(),
            uri:         $request->getRequestUri(),
            rawUri:      (string) ($request->server->get('REQUEST_URI') ?? $request->getRequestUri()),
            queryString: $request->getQueryString() ?? '',
            protocol:    (string) ($request->server->get('SERVER_PROTOCOL') ?? 'HTTP/1.1'),
            remoteAddr:  $request->getClientIp() ?? '0.0.0.0',
            queryArgs:   $request->query->all(),
            postArgs:    $request->request->all(),
            cookies:     $request->cookies->all(),
            headers:     $request->headers->all(),
            body:        $request->getContent(),
            files:       $files,
        );
    }
}
