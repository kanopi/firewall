<?php

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
    use EvaluateTrait {
        getRequestValue as _getRequestValue;
    }

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
        $this->deviceDetector = $this->detectDevice($request->headers->get('User-Agent', ''));
        return $this->evaluateRequest($request, $this->config);
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
    protected function getRequestValue(Request $request, string $variable): mixed
    {

        $segments = explode('.', trim($variable));

        /** @phpstan-ignore-next-line  */
        if ($segments === []) {
            return null;
        }

        switch ($segments[0]) {
            case 'bot':
                return $this->deviceDetector->isBot() ? 'true' : 'false';
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
