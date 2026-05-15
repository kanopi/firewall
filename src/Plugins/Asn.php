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
     * Whether the operator configured a reader at all (vs. an init failure).
     */
    private bool $readerConfigured;

    /**
     * Generates a new ASN Object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        $this->readerConfigured = isset($metadata['reader']);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);

        if ($this->reader === null) {
            // Init failure on a configured reader is a security-relevant
            // event: pre-fix we silently fail-open. Surface it loudly so
            // ops notice; the evaluate() path now fails closed unless the
            // operator explicitly opted in via metadata.fail_open.
            $level = $this->readerConfigured ? 'error' : 'debug';
            $this->getLogger()->log($level, 'ASN reader not available', [
                'reader_type' => $metadata['reader']['type'] ?? 'none',
                'reader_configured' => $this->readerConfigured,
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
            // Two cases:
            //   1. Operator never configured a reader -> plugin is a no-op
            //      and must allow the request through (returning true here
            //      would block everything for an opt-out user).
            //   2. Operator configured a reader but init failed -> the
            //      block list is silently disabled. Fail closed by default;
            //      operators that prefer availability over enforcement set
            //      metadata.fail_open = true.
            if (!$this->readerConfigured) {
                $this->getLogger()->debug('ASN evaluation skipped - no reader configured', [
                    'request_id' => $request->attributes->get('x-request-id'),
                ]);
                return false;
            }

            $failOpen = (bool) ($this->metadata['fail_open'] ?? false);
            $this->getLogger()->error('ASN reader unavailable - failing ' . ($failOpen ? 'open' : 'closed'), $this->getContext($request, [
                'fail_open' => $failOpen,
            ]));
            return !$failOpen;
        }

        $this->getLogger()->debug('ASN evaluation started', $this->getContext($request));

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('ASN matched blocking rule', $this->getContext($request));
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

            $this->getLogger()->debug('ASN lookup successful', $this->getContext($request, [
                /** @phpstan-ignore-next-line  */
                'asn' => $record->autonomousSystemNumber ?? 'unknown',
                /** @phpstan-ignore-next-line  */
                'asn_org' => $record->autonomousSystemOrganization ?? 'unknown',
                'variable' => $variable,
            ]));
        } catch (\Exception $exception) {
            $this->getLogger()->warning('ASN lookup failed', $this->getContext($request, [
                'variable' => $variable,
                'error' => $exception->getMessage(),
            ]));
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
