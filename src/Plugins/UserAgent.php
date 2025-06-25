<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use DeviceDetector\ClientHints;
use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\AbstractDeviceParser;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate a User Agent.
 */
class UserAgent extends AbstractPluginBase
{
    use EvaluateTrait;

    /**
     * Device Detector for the current request.
     */
    protected DeviceDetector $deviceDetector;

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'User Agent';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Evaluate the User Agent';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $userAgent = $request->headers->get('User-Agent', '');
        $this->deviceDetector = $this->detectDevice($userAgent);

        $this->getLogger()->debug('User Agent evaluation started', [
            'plugin' => $this->getName(),
            'request_id' => $request->attributes->get('x-request-id'),
            'user_agent' => $userAgent,
            'is_bot' => $this->deviceDetector->isBot(),
            'device_type' => $this->deviceDetector->getDeviceName(),
            'client' => $this->deviceDetector->getClient(),
            'os' => $this->deviceDetector->getOs(),
        ]);

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('User Agent matched blocking rule', [
                'plugin' => $this->getName(),
                'request_id' => $request->attributes->get('x-request-id'),
                'user_agent' => $userAgent,
                'is_bot' => $this->deviceDetector->isBot(),
            ]);
        }

        return $result;
    }

    /**
     * Parse the UserAgent and create a Device Detector.
     *
     * @param string $userAgent
     *   The user agent to parse.
     *
     * @return DeviceDetector
     *   Return Device Detector.
     */
    protected function detectDevice(string $userAgent): DeviceDetector
    {
        AbstractDeviceParser::setVersionTruncation(AbstractDeviceParser::VERSION_TRUNCATION_NONE);
        $clientHints = ClientHints::factory($_SERVER);

        $deviceDetector = new DeviceDetector($userAgent, $clientHints);
        $deviceDetector->parse();
        return $deviceDetector;
    }

    /**
     * Extract the value for a given variable name from the User Agent object.
     *
     * Supported variables:
     * - bot: Is the User Agent a Bot
     * - device: Type of the device
     * - client: Client information
     * - os: Type of OS being used
     * - brand: Device brand
     * - model: The model of the device
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
            $this->getLogger()->warning('Empty variable provided for User Agent evaluation', [
                'variable' => $variable,
            ]);
            return null;
        }

        $this->getLogger()->debug('Extracting User Agent variable', [
            'variable' => $variable,
            'segments' => $segments,
        ]);

        switch (strtolower((string) $segments[0])) {
            case 'bot':
                if (count($segments) === 1) {
                    return $this->deviceDetector->isBot() ? 'true' : 'false';
                }

                $data = $this->deviceDetector->isBot() ? $this->deviceDetector->getBot() : [];
                break;
            case 'device':
                $data = ['type' => $this->deviceDetector->getDeviceName()];
                break;
            case 'client':
                $data = $this->deviceDetector->getClient(); // name, type, version
                break;
            case 'os':
                $data = $this->deviceDetector->getOs(); // name, short_name, version
                break;
            case 'brand':
                return $this->deviceDetector->getBrandName();
            case 'model':
                return $this->deviceDetector->getModel();
            default:
                return null;
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
