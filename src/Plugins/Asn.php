<?php

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate the ASN of the request.
 */
class Asn extends AbstractPluginBase
{
    use EvaluateTrait {
        getRequestValue as _getRequestValue;
    }

    use GeoLocationTrait;

    /**
     * Generates a new ASN Object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);
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
            return false;
        }

        return $this->evaluateRequest($request, $this->config);
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
    protected function getRequestValue(Request $request, string $variable): mixed
    {
        if ($this->reader === null) {
            return false;
        }

        if (!method_exists($this->reader, 'asn')) {
            return false;
        }

        try {
            $record = $this->reader->asn($request->getClientIp());
        } catch (\Exception $e) {
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
