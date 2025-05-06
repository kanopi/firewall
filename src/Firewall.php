<?php

namespace Kanopi\Firewall;

/**
 * Firewall base classed used for evaluating IPs and Request URLs.
 */
final class Firewall {

  /**
   * IP List File.
   *
   * @var string
   */
  private string $ipsFile;

  /**
   * URLs List File.
   *
   * @var string
   */
  private string $urlsFile;

  /**
   * List of IPs to block.
   */
  private array $ips = [];

  /**
   * List of URLs to block.
   */
  private array $urls = [];

  /**
   * Create a new Instance.
   */
  public static function create(string $urls, string $ips): self {
    return new static($urls, $ips);
  }

  /**
   * Constructs a new Firewall Object.
   */
  protected function __construct(string $urls, string $ips) {
    $this->urlsFile = $urls;
    $this->ipsFile = $ips;
    $this->urls = $this->loadData($urls);
    $this->ips = $this->loadData($ips);
  }

  /**
   * Parse the files and get the data.
   *
   * @param string $file
   *   File to parse and import.
   *
   * @return array
   *   Return the data parsed into an array.
   */
  protected function loadData(string $file): array {
    if (!file_exists($file)) {
      @touch($file);
    }
    return array_filter(explode(PHP_EOL, trim(file_get_contents($file))));
  }

  /**
   * Review the request and choose to auto block the IP address.
   *
   * @param string $ip
   *   IP Address to review.
   * @param string $url
   *   URL to review.
   * @param string $method
   *   Method of the request.
   * @param bool $autoBlock
   *   Should the Request be autoblocked.
   *
   * @return bool
   *   Return TRUE if the request should be denied.
   */
  public function check(
    ?string $ip = null,
    ?string $url = null,
    ?string $method = null,
    bool $autoBlock = TRUE
  ): bool {
    $ip = $ip ?? $_SERVER['REMOTE_ADDR'];
    $url = $url ?? $_SERVER['REQUEST_URI'];
    $method = $method ?? $_SERVER['REQUEST_METHOD'];

    if ($this->denyRequest($url, $method) || $this->denyIp($ip)) {
      if ($autoBlock && !in_array($ip, $this->ips)) {
        $this->ips[] = $ip;
        $this->updateIps($this->ips);
      }
      return true;
    }

    return false;
  }

  /**
   * Should the request be denied.
   *
   * @param string $url
   *   Url of the request.
   * @param string $method
   *   Method of the request.
   *
   * @return bool
   *   Return TRUE if the request should be denied.
   */
  protected function denyRequest(
    string $url,
    string $method
  ): bool {
    foreach ($this->urls as $pattern) {
      // If the pattern looks like a regex (starts with ^ or ends with $ or contains .* or similar)
      if (preg_match('/[^\w]/', $pattern)) {
        // Treat it as a regular expression
        $regex = '#' . $pattern . '#';
        if (@preg_match($regex, $url)) {
          return true;
        }
      } else {
        // Treat it as a simple string prefix match
        if (str_starts_with($url, $pattern)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check to see if the IP address is denied.
   *
   * @param string $ip
   *   IP address to evaluate.
   *
   * @return bool
   *   Return TRUE if deny the IP address.
   */
  protected function denyIp(string $ip): bool {
    if (!$forbidden = in_array($ip, $this->ips)) {
      // Check if this IP is in CIDR block list.
      foreach ($this->ips as $_cidr) {
        if (str_contains($_cidr, '/') !== FALSE) {
          $_ip = ip2long($ip);
          [$_net, $_mask] = explode('/', $_cidr, 2);
          $_ip_net = ip2long($_net);
          $_ip_mask = ~((1 << (32 - $_mask)) - 1);

          if ($forbidden = ($_ip & $_ip_mask) == ($_ip_net & $_ip_mask)) {
            break;
          }
        }
      }
    }
    return $forbidden;
  }

  /**
   * Update the IPs file.
   */
  protected function updateIps(array $ips): void {
    $output = implode(PHP_EOL, $ips);
    @file_put_contents($this->ipsFile, $output);
  }

}

