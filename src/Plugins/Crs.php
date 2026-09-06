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
 * Requires crs-engine ^1.0. In 0.1.0 the anomaly-evaluation rules could never
 * fire, so the threshold was inert and blocking came from whichever rule
 * happened to carry a `block` action. 1.0.0 fixed that: score accumulates,
 * 949110 denies once it crosses the threshold, and `anomaly_thresholds` is
 * now the primary tuning lever. The practical effect of that upgrade is that
 * traffic which used to pass is now blocked — see the README's CRS section
 * before rolling it out.
 *
 * One consequence worth knowing when reading logs: an anomaly-score block is
 * attributed to rule 949110, not to the rule that found the payload. The
 * rules that actually contributed are in `contributing_rules` on the log
 * context, and those are what belong in `disabled_rules`.
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
     * There are two thresholds and they are directional. Before crs-engine
     * 1.0.0 they were keyed `critical` / `error`, which read as though there
     * were one per CRS severity; the engine still accepts those spellings but
     * emits a deprecation for them. Translating here means config written
     * either way keeps working without the host application seeing a
     * deprecation on every request.
     *
     * @var array<string, list<string>>
     */
    protected const THRESHOLD_KEYS = [
        'inbound'  => ['inbound', 'critical'],
        'outbound' => ['outbound', 'error'],
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
    protected function defaultName(): string
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
                'rule_id'            => $crsVerdict->blockingRuleId,
                'contributing_rules' => $this->contributingRuleIds($crsVerdict),
                'total_score'        => $crsVerdict->totalScore,
                'scores'             => $crsVerdict->scores,
                'matched_rule'       => $crsVerdict->matchedRules[0]['msg'] ?? '',
                'matched_data'       => $crsVerdict->matchedRules[0]['matched_data'] ?? '',
                'operator_errors'    => $crsVerdict->operatorErrors,
                'truncations'        => $crsVerdict->truncations,
            ]));
            return true;
        }

        // Rules fired but the anomaly score stayed under threshold, or the
        // plugin is in monitor mode. Report no match so the request proceeds.
        if ($crsVerdict->matchedRules !== []) {
            $this->getLogger()->debug('CRS matched but did not block', $this->getContext($request, [
                'action'             => $crsVerdict->action,
                'matched_rules'      => count($crsVerdict->matchedRules),
                'contributing_rules' => $this->contributingRuleIds($crsVerdict),
                'total_score'        => $crsVerdict->totalScore,
            ]));
        }

        // An operator error or a truncation means part of the request went
        // uninspected, so "no match" is weaker evidence than it looks. Say so
        // even when nothing fired — a clean verdict is the case where a silent
        // gap in coverage is most likely to be believed.
        if ($crsVerdict->hasOperatorErrors() || $crsVerdict->wasTruncated()) {
            $this->getLogger()->warning('CRS inspected less of the request than it appears', $this->getContext($request, [
                'action'          => $crsVerdict->action,
                'operator_errors' => $crsVerdict->operatorErrors,
                'truncations'     => $crsVerdict->truncations,
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
     * The rules that actually found something, in match order.
     *
     * `blockingRuleId` is 949110 for every anomaly-score block, because that
     * is the CRS rule that compares the accumulated score to the threshold.
     * It says nothing about what was detected and must never be fed to
     * `disabled_rules` — doing so would switch off anomaly blocking wholesale.
     * The IDs here are the ones worth excluding, so drop the blocking-
     * evaluation bookkeeping and keep the detections.
     *
     * @return array<int, int>
     */
    protected function contributingRuleIds(CrsVerdict $crsVerdict): array
    {
        $ids = [];
        foreach ($crsVerdict->matchedRules as $matchedRule) {
            if ($matchedRule['category'] === 'blocking_evaluation') {
                continue;
            }

            $ids[] = $matchedRule['id'];
        }

        return $ids;
    }

    /**
     * Normalise `anomaly_thresholds` into the two thresholds the engine reads.
     *
     * There are exactly two: inbound (the request-side score at or above which
     * a request is rejected) and outbound (the response-side equivalent, which
     * this plugin does not yet reach — see issue #69). Pre-1.0 config keyed
     * them by CRS severity, which invited operators to supply a `warning` and
     * a `notice` alongside and believe all four did something. They never did
     * (#93), so name the inert ones rather than accepting them in silence.
     *
     * Deliberately more forgiving than the engine, which throws
     * `ConfigurationException` on an unrecognised key. A typo in a YAML file
     * should not take a site down: drop the key, say so at warning level, and
     * carry on protecting the site with the rest of the config.
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
            'inbound'  => self::DEFAULT_INBOUND_THRESHOLD,
            'outbound' => self::DEFAULT_OUTBOUND_THRESHOLD,
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
            $this->getLogger()->warning('CRS anomaly_thresholds keys are ignored — there are only an inbound and an outbound threshold', [
                'plugin'   => $this->getName(),
                'ignored'  => $inert,
                'accepted' => $accepted,
                'hint'     => 'Severity names are not thresholds. Raise or lower `inbound` to tune sensitivity, or use disabled_rules / disabled_categories to silence a specific false positive.',
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
