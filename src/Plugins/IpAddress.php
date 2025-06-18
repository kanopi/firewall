<?php

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Implement IP Address.
 */
class IpAddress extends AbstractPluginBase
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return "IP Address";
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return "Evaluate IP Addresses and see in the provided list";
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        return $this->inList($request->getClientIp(), $this->config);
    }

    /**
     * Check to see if the provided IP is in the list of IPs.
     *
     * @param string $ip
     *   IP to check if within the list.
     * @param array $ips
     *   Array of IPs and CIDR lists.
     *
     * @return bool
     *   Return TRUE if found. FALSE if not.
     */
    protected function inList(string $ip, array $ips = []): bool
    {
        if (!$in_list = in_array($ip, $ips)) {
            foreach ($ips as $ip_set) {
                if (str_contains((string) $ip_set, '-')) {
                    if ($this->inRange($ip,  $ip_set)) {
                        return true;
                    }
                }
                elseif (str_contains((string) $ip_set, '/')) {
                    if ($this->isInBlock($ip, (string) $ip_set)) {
                        return true;
                    }
                }
            }
        }

        return $in_list;
    }

    /**
     * Check to see if the IP is within a CIDR block.
     *
     * @param string $ip
     *   IP to check against.
     * @param string $cidr
     *   CIDR block to check against. (Example: 127.0.0.1/25)
     *
     * @return bool
     *   Return true if within that block.
     */
    protected function isInBlock(string $ip, string $cidr): bool
    {
        // Split CIDR into base address and prefix length
        [$subnet, $prefixLength] = explode('/', $cidr, 2);

        $ipPacked = inet_pton($ip);
        $subnetPacked = inet_pton($subnet);

        // Validate both IPs
        if ($ipPacked === false || $subnetPacked === false) {
            return false;
        }

        // Must be the same type (IPv4 = 4 bytes, IPv6 = 16 bytes)
        if (strlen($ipPacked) !== strlen($subnetPacked)) {
            return false;
        }

        $bytes = (int) floor($prefixLength / 8);          // Fully matched bytes
        $bits  = (int) ($prefixLength % 8);                // Remaining bits to match

        // Compare full bytes
        if (strncmp($ipPacked, $subnetPacked, $bytes) !== 0) {
            return false;
        }

        // If there are no partial bits, match is successful
        if ($bits === 0) {
            return true;
        }

        // Compare the remaining bits
        $mask = ~(0xFF >> $bits) & 0xFF;

        $ipByte     = ord($ipPacked[$bytes]);
        $subnetByte = ord($subnetPacked[$bytes]);

        return ($ipByte & $mask) === ($subnetByte & $mask);
    }

    /**
     * Check to see if the IP is within a specific range.
     *
     * @param string $ip
     *   IP address to check against.
     * @param string $range
     *   Range formatted as a start - end notation. (Example 127.0.0.1-127.0.0.3).
     */
    protected function inRange(string $ip, string $range): bool
    {
        [$startIp, $endIp] = explode('-', $range);
        $startIp = trim($startIp);
        $endIp = trim($endIp);
        if (empty($startIp) || empty($endIp)) {
            return false;
        }

        // Convert all IPs to their long integer representation
        $ipLong      = ip2long($ip);
        $startIpLong = ip2long($startIp);
        $endIpLong   = ip2long($endIp);

        // Handle invalid IP addresses
        if ($ipLong === false || $startIpLong === false || $endIpLong === false) {
            return false;
        }

        // Compare numerically
        return ($ipLong >= $startIpLong && $ipLong <= $endIpLong);
    }
}
