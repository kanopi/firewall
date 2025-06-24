<?php

namespace Kanopi\Firewall\Plugins;

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
        return $this->evaluateRequest($request, $this->config);
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
            return null;
        }

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

        return is_string($data) ? $data : null;
    }
}
