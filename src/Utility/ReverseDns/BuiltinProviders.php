<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

/**
 * Providers the library ships, available by name (#473).
 *
 * **Available is not selected.** Nothing here is used until a site's own configuration
 * names a provider with `global.reverse_dns.provider` or a rule's `verify_provider`. Naming
 * it is the opt-in: it is the moment a site chooses who receives the reverse-DNS names of
 * its visitors' addresses, and the library never makes that choice for it.
 *
 * Defined in code rather than in a preset file, so they take no part in config merging --
 * an included file merges *over* the one including it (`ConfigLoader::mergeConfigs()`), and
 * a provider assembled from two files' settings once paired Google's endpoint with
 * Cloudflare's address in testing, which fails every lookup and reports no error.
 *
 * Each is documented in `docs/configuration/reverse-dns.md` -- operator, what is sent, what
 * the operator says it logs, terms -- and `BuiltinProvidersDocumentationTest` fails the
 * build for a provider that is not. Every endpoint below was tested on 2026-10-05 with a PTR
 * lookup, the forward lookup and a name with no record.
 */
final class BuiltinProviders
{
    /**
     * Provider definitions, by name.
     *
     * @var array<string, array{resolver: class-string<ReverseDnsResolverInterface>, options: array<string, mixed>}>
     */
    public const ALL = [
        'cloudflare' => [
            'resolver' => DnsOverHttpResolver::class,
            'options' => [
                'endpoint' => 'https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}',
                'address' => '1.1.1.1',
                'headers' => ['Accept' => 'application/dns-json'],
                'response' => 'dns-json',
            ],
        ],
        'google' => [
            'resolver' => DnsOverHttpResolver::class,
            'options' => [
                'endpoint' => 'https://dns.google/resolve?name={{ dns.name }}&type={{ dns.type }}',
                'address' => '8.8.8.8',
                'headers' => ['Accept' => 'application/dns-json'],
                'response' => 'dns-json',
            ],
        ],
    ];

    /**
     * Whether a name is a built-in provider's.
     *
     * @param string $name
     *   A provider name.
     */
    public static function has(string $name): bool
    {
        return isset(self::ALL[$name]);
    }

    /**
     * Built-in provider names.
     *
     * @return list<string>
     *   Names.
     */
    public static function names(): array
    {
        return array_keys(self::ALL);
    }
}
