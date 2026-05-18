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
 */
class Crs extends AbstractPluginBase
{
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

        if ($crsVerdict->isBlocked()) {
            $this->getLogger()->info('CRS blocked request', $this->getContext($request, [
                'rule_id'      => $crsVerdict->blockingRuleId,
                'total_score'  => $crsVerdict->totalScore,
                'scores'       => $crsVerdict->scores,
                'matched_rule' => $crsVerdict->matchedRules[0]['msg'] ?? '',
                'matched_data' => $crsVerdict->matchedRules[0]['matched_data'] ?? '',
            ]));
            return false;
        }

        if ($crsVerdict->matchedRules !== []) {
            $this->getLogger()->debug('CRS matched but did not block', $this->getContext($request, [
                'action'          => $crsVerdict->action,
                'matched_rules'   => count($crsVerdict->matchedRules),
                'total_score'     => $crsVerdict->totalScore,
            ]));
        }

        return true;
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
                anomalyThresholds:  $this->config['anomaly_thresholds'] ?? [
                    'critical' => 5,
                    'error'    => 4,
                    'warning'  => 3,
                    'notice'   => 2,
                ],
                disabledRules:      array_map(intval(...), $this->config['disabled_rules'] ?? []),
                disabledCategories: $this->config['disabled_categories'] ?? [],
                rulesPath:          $this->config['rules_path'] ?? null,
            ));
        }

        return $this->engine;
    }

    /**
     * Adapt a Symfony Request to the engine's framework-agnostic DTO.
     *
     * The engine deliberately does not depend on Symfony — this is the
     * single integration seam between the firewall and crs-engine.
     */
    protected function adaptRequest(Request $request): RequestData
    {
        $files = [];
        foreach ($request->files->all() as $name => $upload) {
            if ($upload === null) {
                continue;
            }

            $list = is_array($upload) ? $upload : [$upload];
            foreach ($list as $file) {
                if (!is_object($file)) {
                    continue;
                }

                $files[] = [
                    'name'     => (string) $name,
                    'filename' => method_exists($file, 'getClientOriginalName') ? (string) $file->getClientOriginalName() : '',
                    'mime'     => method_exists($file, 'getClientMimeType') ? (string) $file->getClientMimeType() : '',
                    'size'     => method_exists($file, 'getSize') ? (int) $file->getSize() : 0,
                    'tmp_name' => method_exists($file, 'getRealPath') ? (string) $file->getRealPath() : '',
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
