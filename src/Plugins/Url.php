<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Traits\RequestValueTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * URL Plugin used for referring a list of items that are blocked.
 */
class Url extends AbstractPluginBase
{
    use EvaluateTrait;
    use RequestValueTrait;

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'URL';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Block access based on the URL being requested.';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $this->getLogger()->debug('URL evaluation started', $this->getContext($request));

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('URL matched blocking rule', $this->getContext($request));
        }

        return $result;
    }

    /**
     * Extract the value for a given variable name from the Request object.
     *
     * Supported variables:
     * - method: HTTP method (GET, POST, etc.)
     * - host: Hostname
     * - path: URI path (e.g. /admin)
     * - any other string: attempts to fetch from query parameters or POST data
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param string $variable
     *   Variable name to extract from the request.
     *
     * @return mixed
     *   The value of the variable or empty string if not found.
     */
    protected function getValue(Request $request, string $variable): mixed
    {
        $segments = $this->splitQuery($variable);

        if ($segments === []) {
            $this->getLogger()->warning('Empty variable provided for URL evaluation', $this->getContext($request, [
                'variable' => $variable,
            ]));

            return null;
        }

        $this->getLogger()->debug('Extracting URL variable', $this->getContext($request, [
            'variable' => $variable,
            'segments' => $segments,
        ]));

        // The resolution itself lives in RequestValueTrait, because rate-limit
        // keys read the same vocabulary and two implementations of `header.*`
        // would drift (#200). The logging stays here: it is about URL rule
        // evaluation, which is not what every caller is doing.
        return $this->resolveRequestValue($request, $variable);
    }

    /**
     * {@inheritdoc}
     *
     * Mirrors the switch in `getValue()` and the variable list in
     * `docs/plugins/url.md`.
     */
    protected function knownRuleVariables(): array
    {
        return ['method', 'host', 'path', 'query', 'scheme', 'port', 'post', 'header', 'cookie'];
    }
}
