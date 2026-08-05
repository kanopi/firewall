<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Challenge;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\SingleUseSolutionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A single-use provider that declines to identify this particular solution.
 *
 * `getSolutionReceipt()` is documented as returning NULL to opt one request
 * out of replay tracking — a provider whose solutions are not always unique
 * per render needs that escape. The firewall must then wave the submission
 * through rather than treating "no receipt" as "already spent", which would
 * reject a legitimate solver outright.
 */
class ReceiptlessSingleUseProvider implements ChallengeProviderInterface, SingleUseSolutionInterface
{
    public function getName(): string
    {
        return 'receiptless';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        return '<!DOCTYPE html><html lang="en"><body>stub</body></html>';
    }

    public function verifySolution(Request $request): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getSolutionReceipt(Request $request): ?array
    {
        return null;
    }
}
