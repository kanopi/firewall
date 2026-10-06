<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * The URL a DNS-over-HTTPS provider is asked, with placeholders for each lookup.
 *
 * One template serves both lookups a verification makes, so it carries the parts that
 * change between them as placeholders, in the `{{ }}` syntax `global.banning_message`
 * already uses:
 *
 * | Placeholder            | Reverse (PTR) lookup   | Forward lookup                |
 * |------------------------|------------------------|-------------------------------|
 * | `{{ dns.name }}`       | `4.3.2.1.in-addr.arpa` | the hostname the PTR returned |
 * | `{{ dns.type }}`       | `PTR`                  | `A` or `AAAA`                 |
 * | `{{ client.ip }}`      | `1.2.3.4`              | `1.2.3.4`                     |
 * | `{{ client.ip_arpa }}` | `4.3.2.1.in-addr.arpa` | `4.3.2.1.in-addr.arpa`        |
 *
 * **A template with `type=PTR` written into it is refused.** It could never make the
 * forward lookup, and verification without the forward lookup is spoofable: whoever owns an
 * address block controls its PTR records. So a single template must carry both
 * `{{ dns.name }}` and `{{ dns.type }}`. A provider that needs different URLs for the two
 * steps gives a map instead:
 *
 * ```yaml
 * endpoint:
 *   ptr: "https://resolver.internal/ptr/{{ client.ip }}"
 *   forward: "https://resolver.internal/lookup?name={{ dns.name }}&type={{ dns.type }}"
 * ```
 *
 * Every value is URL-encoded as it is substituted, and placeholders are allowed only after
 * the host: a template cannot choose where it connects per lookup.
 */
final class EndpointTemplate
{
    /**
     * Placeholders a template may use.
     *
     * @var list<string>
     */
    public const PLACEHOLDERS = ['dns.name', 'dns.type', 'client.ip', 'client.ip_arpa'];

    /**
     * Any `{{ ... }}`, so an unknown name is reported rather than left in the URL.
     */
    private const PATTERN = '/\{\{\s*([^{}]*?)\s*\}\}/';

    /**
     * @param string $ptr
     *   Template for the reverse lookup.
     * @param string $forward
     *   Template for the forward lookup.
     */
    private function __construct(
        private readonly string $ptr,
        private readonly string $forward
    ) {
    }

    /**
     * Build a template from configuration.
     *
     * @param mixed $value
     *   A string, or a map with `ptr` and `forward`.
     *
     * @throws ConfigurationException
     *   Naming every problem with it.
     */
    public static function fromConfig(mixed $value): self
    {
        $problems = self::problems($value);

        if ($problems !== []) {
            throw new ConfigurationException('endpoint: ' . implode('; ', $problems));
        }

        /** @var string|array{ptr: string, forward: string} $value */
        return is_string($value)
            ? new self($value, $value)
            : new self($value['ptr'], $value['forward']);
    }

    /**
     * Everything wrong with a template, without building it.
     *
     * @param mixed $value
     *   A string, or a map with `ptr` and `forward`.
     *
     * @return list<string>
     *   Problems, empty when it can be used.
     */
    public static function problems(mixed $value): array
    {
        if (is_string($value)) {
            $problems = self::urlProblems($value, 'the template');

            foreach (['dns.name', 'dns.type'] as $required) {
                if (!in_array($required, self::placeholdersIn($value), true)) {
                    $problems[] = sprintf(
                        'the template must contain {{ %s }}, so one template can make both the reverse and the forward lookup',
                        $required
                    );
                }
            }

            return $problems;
        }

        if (!is_array($value)) {
            return [sprintf('must be a URL template, or a map with ptr and forward; got %s', get_debug_type($value))];
        }

        $problems = [];

        foreach (array_diff(array_map(strval(...), array_keys($value)), ['ptr', 'forward']) as $unknown) {
            $problems[] = sprintf('unknown key "%s"; a map takes only ptr and forward', $unknown);
        }

        foreach (['ptr', 'forward'] as $step) {
            if (!is_string($value[$step] ?? null)) {
                $problems[] = sprintf('%s must be a URL template', $step);
                continue;
            }

            foreach (self::urlProblems($value[$step], $step) as $problem) {
                $problems[] = $problem;
            }
        }

        if (is_string($value['ptr'] ?? null) && array_intersect(['dns.name', 'client.ip', 'client.ip_arpa'], self::placeholdersIn($value['ptr'])) === []) {
            $problems[] = 'ptr must contain {{ dns.name }}, {{ client.ip }} or {{ client.ip_arpa }}';
        }

        if (is_string($value['forward'] ?? null) && !in_array('dns.name', self::placeholdersIn($value['forward']), true)) {
            $problems[] = 'forward must contain {{ dns.name }}';
        }

        // One provider, one place to connect: `address` pins a single host and port, and a
        // second host would be resolved by the operating system -- the stall #473 removes.
        if (is_string($value['ptr'] ?? null) && is_string($value['forward'] ?? null) && $problems === []) {
            $ptr = new self($value['ptr'], $value['ptr']);
            $forward = new self($value['forward'], $value['forward']);

            if (strtolower($ptr->host()) !== strtolower($forward->host()) || $ptr->port() !== $forward->port()) {
                $problems[] = 'ptr and forward must use the same host and port';
            }
        }

        return $problems;
    }

    /**
     * The URL for the reverse lookup of an address.
     *
     * @param string $ip
     *   A valid client address.
     */
    public function ptrUrl(string $ip): string
    {
        $arpa = self::arpa($ip);

        return $this->render($this->ptr, [
            'dns.name' => $arpa,
            'dns.type' => 'PTR',
            'client.ip' => $ip,
            'client.ip_arpa' => $arpa,
        ]);
    }

    /**
     * The URL for the forward lookup of a hostname.
     *
     * @param string $hostname
     *   The validated hostname.
     * @param string $type
     *   `A` or `AAAA`.
     * @param string $ip
     *   The client address being confirmed.
     */
    public function forwardUrl(string $hostname, string $type, string $ip): string
    {
        return $this->render($this->forward, [
            'dns.name' => $hostname,
            'dns.type' => $type,
            'client.ip' => $ip,
            'client.ip_arpa' => self::arpa($ip),
        ]);
    }

    /**
     * The host every lookup connects to.
     */
    public function host(): string
    {
        return (string) parse_url($this->ptr, PHP_URL_HOST);
    }

    /**
     * The port every lookup connects to.
     */
    public function port(): int
    {
        $port = parse_url($this->ptr, PHP_URL_PORT);

        return is_int($port) ? $port : 443;
    }

    /**
     * The reverse-DNS name of an address: `4.3.2.1.in-addr.arpa`, or the nibble form under
     * `ip6.arpa` for IPv6.
     *
     * @param string $ip
     *   The address.
     *
     * @return string
     *   The name, or an empty string for something that is not an address.
     */
    public static function arpa(string $ip): string
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return '';
        }

        if (strlen($packed) === 4) {
            return implode('.', array_reverse(explode('.', (string) inet_ntop($packed)))) . '.in-addr.arpa';
        }

        return implode('.', array_reverse(str_split(bin2hex($packed)))) . '.ip6.arpa';
    }

    /**
     * Substitute placeholders, URL-encoding every value.
     *
     * @param string $template
     *   A validated template.
     * @param array<string, string> $values
     *   Values by placeholder name.
     */
    private function render(string $template, array $values): string
    {
        return (string) preg_replace_callback(
            self::PATTERN,
            static fn(array $match): string => rawurlencode($values[$match[1]] ?? ''),
            $template
        );
    }

    /**
     * Problems with one URL template.
     *
     * @param string $template
     *   The template.
     * @param string $label
     *   How to name it in a message.
     *
     * @return list<string>
     *   Problems.
     */
    private static function urlProblems(string $template, string $label): array
    {
        $problems = [];

        foreach (self::placeholdersIn($template) as $name) {
            if (!in_array($name, self::PLACEHOLDERS, true)) {
                $problems[] = sprintf(
                    '%s uses {{ %s }}, which is not a placeholder; the placeholders are %s',
                    $label,
                    $name,
                    implode(', ', array_map(static fn(string $known): string => '{{ ' . $known . ' }}', self::PLACEHOLDERS))
                );
            }
        }

        // Read with every placeholder blanked, so a URL built from it can be judged.
        $blank = (string) preg_replace(self::PATTERN, 'x', $template);
        $scheme = parse_url($blank, PHP_URL_SCHEME);
        $host = parse_url($blank, PHP_URL_HOST);

        if (!is_string($scheme) || strtolower($scheme) !== 'https') {
            $problems[] = sprintf('%s must be an https:// URL', $label);
        }

        if (!is_string($host) || $host === '') {
            $problems[] = sprintf('%s has no host', $label);
        } elseif (preg_match(self::PATTERN, (string) preg_replace('#^[a-z]+://([^/?\#]*).*$#is', '$1', $template)) === 1) {
            $problems[] = sprintf('%s puts a placeholder in the host; placeholders are allowed only in the path and query', $label);
        }

        return $problems;
    }

    /**
     * Placeholder names a template uses.
     *
     * @param string $template
     *   The template.
     *
     * @return list<string>
     *   Names, in order of appearance.
     */
    private static function placeholdersIn(string $template): array
    {
        preg_match_all(self::PATTERN, $template, $matches);

        return $matches[1];
    }
}
