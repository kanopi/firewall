<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Traits\GeoLocationTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate the ASN of the request.
 */
class Asn extends AbstractPluginBase
{
    use EvaluateTrait;
    use GeoLocationTrait;

    /**
     * Generates a new ASN Object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);

        if ($this->reader === null) {
            $this->getLogger()->warning('ASN reader not configured or failed to initialize', [
                'reader_type' => $metadata['reader']['type'] ?? 'none',
            ]);
        } else {
            $this->getLogger()->debug('ASN reader initialized', [
                'reader_type' => $metadata['reader']['type'] ?? 'default',
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return "Autonomous System Network";
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return "Evaluate the GeoLocation Details";
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        if ($this->reader === null) {
            $this->getLogger()->debug('ASN evaluation skipped - no reader available', [
                'request_id' => $request->attributes->get('x-request-id'),
            ]);
            return false;
        }

        $this->getLogger()->debug('ASN evaluation started', [
            'plugin' => $this->getName(),
            'request_id' => $request->attributes->get('x-request-id'),
            'client_ip' => $request->getClientIp(),
        ]);

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('ASN matched blocking rule', [
                'plugin' => $this->getName(),
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
            ]);
        }

        return $result;
    }

    /**
     * Extract the value for a given variable name from the IP Address object.
     *
     * Supported variables:
     * - asn: ASN Number
     * - asn_org: ASN Organization
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
        if ($this->reader === null) {
            return false;
        }

        if (!method_exists($this->reader, 'asn')) {
            $this->getLogger()->warning('ASN method not available on reader', [
                'reader_class' => $this->reader::class,
            ]);
            return false;
        }

        try {
            $clientIp = $request->getClientIp();
            $record = $this->reader->asn($clientIp);

            $this->getLogger()->debug('ASN lookup successful', [
                'client_ip' => $clientIp,
                /** @phpstan-ignore-next-line  */
                'asn' => $record->autonomousSystemNumber ?? 'unknown',
                /** @phpstan-ignore-next-line  */
                'asn_org' => $record->autonomousSystemOrganization ?? 'unknown',
                'variable' => $variable,
            ]);
        } catch (\Exception $exception) {
            $this->getLogger()->warning('ASN lookup failed', [
                'client_ip' => $request->getClientIp(),
                'variable' => $variable,
                'error' => $exception->getMessage(),
            ]);
            return null;
        }

        return match ($variable) {
            /** @phpstan-ignore-next-line  */
            'asn' => $record->autonomousSystemNumber,
            /** @phpstan-ignore-next-line  */
            'asn_org' => $record->autonomousSystemOrganization,
            default => null,
        };
    }
}
