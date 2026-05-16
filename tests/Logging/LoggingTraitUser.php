<?php

namespace Kanopi\Firewall\Tests\Logging;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Basic stub class using the LoggingTrait for test purposes.
 */
class LoggingTraitUser
{
    use LoggingTrait;

    public function logSomething(): void
    {
        $this->log('warning', 'Trait-based warning log', ['type' => 'example']);
    }

    /**
     * Expose `getContext()` so tests can assert the CRLF-stripping
     * behaviour without standing up a real plugin instance.
     */
    public function publicGetContext(\Symfony\Component\HttpFoundation\Request $request, array $additional = []): array
    {
        return $this->getContext($request, $additional);
    }

    /**
     * Expose `sanitizeContext()` directly.
     */
    public function publicSanitizeContext(array $context): array
    {
        return $this->sanitizeContext($context);
    }
}