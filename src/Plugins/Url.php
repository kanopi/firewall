<?php

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * URL Plugin used for referring a list of items that are blocked.
 */
class Url extends AbstractPluginBase
{
    use EvaluateTrait {
        getRequestValue as _getRequestValue;
    }

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
     * @return bool|float|int|string|null
     *   The value of the variable or empty string if not found.
     */
    protected function getRequestValue(Request $request, string $variable): bool|float|int|string|null
    {
        switch (strtolower($variable)) {
            case 'method':
                return $request->getMethod();

            case 'host':
                return $request->getHost();

            case 'path':
                return $request->getPathInfo();

            default:
                if ($request->query->has($variable)) {
                    return $request->query->get($variable);
                }

                if ($request->request->has($variable)) {
                    return $request->request->get($variable);
                }

                return '';
        }
    }
}
