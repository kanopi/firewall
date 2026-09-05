<?php

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Traits\EvaluateTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * URL Plugin used for referring a list of items that are blocked.
 */
class Url extends AbstractPluginBase
{
    use EvaluateTrait;

    /**
     * {@inheritdoc}
     */
    public function getName(): string
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

        $isHeader = false;

        switch (strtolower((string) $segments[0])) {
            case 'method':
                return $request->getMethod();

            case 'host':
                return $request->getHost();

            case 'path':
                return $request->getPathInfo();

            case 'query':
                if (count($segments) === 1) {
                    return $request->getQueryString();
                }

                $data = $request->query->all();
                break;

            case 'scheme':
                return $request->getScheme();

            case 'port':
                return $request->getPort();

            case 'post':
                $data = $request->request->all();
                break;

            case 'header':
                $data = $request->headers->all();
                $isHeader = true;
                // Header names are case-insensitive by spec, and Symfony
                // lowercases them on the way in. Without this, `header.User-Agent`
                // — the natural way to write it — resolves to nothing.
                $segments = array_map(
                    strtolower(...),
                    $segments
                );
                break;

            case 'cookie':
                $data = $request->cookies->all();
                break;

            default:
                return null;
        }

        if (count($segments) === 1) {
            return http_build_query($data, '', ' ');
        }

        // Traverse nested keys
        foreach (array_slice($segments, 1) as $segment) {
            if (!is_array($data) || !array_key_exists($segment, $data)) {
                return null;
            }

            $data = $data[$segment];
        }

        if ($isHeader && is_array($data)) {
            // Symfony's HeaderBag stores every header as a *list* of values,
            // because HTTP permits a field to appear more than once. Returning
            // NULL for that array is what made every `header.*` rule match
            // nothing at all, silently (#169). Fold repeats the way the spec
            // does, so `header.user-agent` is the string it looks like.
            //
            // Deliberately limited to headers. An array under `query` or
            // `post` — `?items[]=a&items[]=b` — is what the client actually
            // sent, not a storage artefact, and flattening it would let a
            // `contains` rule match across values the client never put
            // together. Those keep resolving to NULL.
            foreach ($data as $value) {
                if ($value !== null && !is_scalar($value)) {
                    return null;
                }
            }

            return implode(', ', array_map(
                static fn (mixed $value): string => (string) $value,
                $data
            ));
        }

        return is_string($data) ? $data : null;
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
