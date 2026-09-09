<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Declares its rule variables as something that is not a list of them.
 *
 * `knownRuleVariables()` is reached by reflection, so nothing enforces its
 * return type at the call site. A plugin outside this package can return
 * whatever it likes, and the linter has to decline rather than misreport.
 */
class TestOddVariablesPlugin implements PluginInterface
{
    public function __construct(array $metadata = [], array $config = [])
    {
    }

    public function getName(): string
    {
        return 'odd-variables';
    }

    public function getDescription(): string
    {
        return 'Returns a non-array from knownRuleVariables()';
    }

    public function evaluate(Request $request): bool
    {
        return false;
    }

    public function getStatusCode(?Request $request = null): int
    {
        return 403;
    }

    public function getExpirationTime(?Request $request = null): int
    {
        return 0;
    }

    /**
     * Deliberately not a list of strings.
     *
     * @return mixed
     *   Not an array.
     */
    protected function knownRuleVariables(): mixed
    {
        return 'path';
    }
}
