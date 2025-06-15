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
     *   IP to check.
     * @param array $ips
     *   Array of IPs and CIDR lists.
     *
     * @return bool
     *   Return TRUE if found. FALSE if not.
     */
    protected function inList(string $ip, array $ips = []): bool
    {
        if (!$in_list = in_array($ip, $ips)) {
            // Check if this IP is in CIDR list.
            foreach ($ips as $_cidr) {
                if (str_contains($_cidr, '/') !== false) {
                    $_ip = ip2long($ip);
                    [$_net, $_mask] = explode('/', $_cidr, 2);
                    $_ip_net = ip2long($_net);
                    /** @phpstan-ignore-next-line  */
                    $_ip_mask = ~((1 << (32 - $_mask)) - 1);

                    if ($in_list = ($_ip & $_ip_mask) == ($_ip_net & $_ip_mask)) {
                        break;
                    }
                }
            }
        }
        return $in_list;
    }
}
