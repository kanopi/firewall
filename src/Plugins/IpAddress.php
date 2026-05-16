<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
        $clientIp = $request->getClientIp();
        $result = $this->inList($clientIp, $this->config);

        $this->getLogger()->debug('IP Address evaluation started', $this->getContext($request, [
            'result' => $result ? 'matched' : 'not_matched',
            'checked_patterns_count' => count($this->config),
        ]));

        return $result;
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
                    if ($this->inRange($ip, $ip_set)) {
                        $this->getLogger()->debug('IP matched range', [
                            'ip' => $ip,
                            'range' => $ip_set,
                        ]);
                        return true;
                    }
                } elseif (str_contains((string) $ip_set, '/')) {
                    if ($this->isInBlock($ip, (string) $ip_set)) {
                        $this->getLogger()->debug('IP matched CIDR block', [
                            'ip' => $ip,
                            'cidr' => $ip_set,
                        ]);
                        return true;
                    }
                }
            }
        } else {
            $this->getLogger()->debug('IP matched exact', [
                'ip' => $ip,
            ]);
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
        if (!str_contains($cidr, '/')) {
            $this->getLogger()->warning('Invalid CIDR format', ['cidr' => $cidr]);
            return false;
        }

        // Split CIDR into base address and prefix length
        [$subnet, $prefixLength] = explode('/', $cidr, 2);

        $ipPacked = inet_pton($ip);
        $subnetPacked = inet_pton($subnet);

        // Validate both IPs
        if ($ipPacked === false || $subnetPacked === false) {
            $this->getLogger()->warning('Invalid IP format for CIDR check', [
                'ip' => $ip,
                'subnet' => $subnet,
                'cidr' => $cidr,
            ]);
            return false;
        }

        // Must be the same type (IPv4 = 4 bytes, IPv6 = 16 bytes)
        if (strlen($ipPacked) !== strlen($subnetPacked)) {
            $this->getLogger()->warning('IP type mismatch in CIDR check', [
                'ip' => $ip,
                'cidr' => $cidr,
                'ip_type' => strlen($ipPacked) === 4 ? 'IPv4' : 'IPv6',
                'cidr_type' => strlen($subnetPacked) === 4 ? 'IPv4' : 'IPv6',
            ]);
            return false;
        }

        // Validate the prefix length: must be a non-negative integer, no
        // sign character, and within the allowed range for the address
        // family (0..32 for IPv4, 0..128 for IPv6). Pre-fix any string
        // after `/` was cast to int and used as-is, so a typo like
        // `10.0.0.0/300` produced nonsense byte/bit math that on some
        // inputs degenerated into "match everything" or "match nothing".
        $maxPrefix = strlen($ipPacked) === 4 ? 32 : 128;
        if (!ctype_digit($prefixLength) || (int) $prefixLength > $maxPrefix) {
            $this->getLogger()->warning('Invalid CIDR prefix length', [
                'cidr' => $cidr,
                'prefix_length' => $prefixLength,
                'max_allowed' => $maxPrefix,
            ]);
            return false;
        }

        $bytes = intdiv((int) $prefixLength, 8);          // Fully matched bytes
        $bits  = (int) $prefixLength % 8;                // Remaining bits to match

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
        if ($startIp === '' || $startIp === '0' || ($endIp === '' || $endIp === '0')) {
            $this->getLogger()->warning('Invalid IP range format', ['range' => $range]);
            return false;
        }

        // Convert all IPs to their long integer representation
        $ipLong      = ip2long($ip);
        $startIpLong = ip2long($startIp);
        $endIpLong   = ip2long($endIp);

        // Handle invalid IP addresses
        if ($ipLong === false || $startIpLong === false || $endIpLong === false) {
            $this->getLogger()->warning('Invalid IP in range check', [
                'ip' => $ip,
                'range' => $range,
                'start_ip' => $startIp,
                'end_ip' => $endIp,
            ]);
            return false;
        }

        // Compare numerically
        return ($ipLong >= $startIpLong && $ipLong <= $endIpLong);
    }
}
