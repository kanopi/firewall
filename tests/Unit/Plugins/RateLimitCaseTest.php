<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rate-limit paths ignore case, as Url's path conditions already do (#426).
 *
 * On a case-insensitive filesystem `/WP-LOGIN.PHP` runs `wp-login.php`. Url's
 * `path:/wp-login.php` already matched it; a rate limit on `/wp-login.php` did not, and
 * the upper-case spelling got a budget of its own.
 */
final class RateLimitCaseTest extends AbstractTestCase
{
    /**
     * @param array<string, mixed> $entry
     */
    private function firewall(array $entry): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception', 'path_source' => 'script_name'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
                'response' => 'block',
                'enable' => true,
                'config' => [$entry],
            ]],
        ]]);
    }

    private function direct(string $script): Request
    {
        return new Request([], [], [], [], [], [
            'REQUEST_URI' => $script,
            'SCRIPT_NAME' => $script,
            'PHP_SELF' => $script,
            'SCRIPT_FILENAME' => '/var/www/html' . $script,
            'REQUEST_METHOD' => 'POST',
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_HOST' => 'example.com',
        ]);
    }

    /**
     * @param array<int, string> $scripts
     * @param array<string, mixed> $entry
     */
    private function outcomes(array $entry, array $scripts): string
    {
        $firewall = $this->firewall($entry);
        $out = [];

        foreach ($scripts as $script) {
            try {
                $firewall->evaluate($this->direct($script));
                $out[] = 'ok';
            } catch (FirewallBlockedException) {
                $out[] = 'refused';
            }
        }

        return implode(',', $out);
    }

    public function testEverySpellingSharesOneBudget(): void
    {
        $this->assertSame(
            'ok,ok,refused',
            $this->outcomes(['path' => '/wp-login.php', 'rate' => 2, 'window' => 60], ['/wp-login.php', '/WP-LOGIN.PHP', '/Wp-Login.php'])
        );
    }

    public function testAWildcardPatternIgnoresCase(): void
    {
        $this->assertSame(
            'ok,ok,refused',
            $this->outcomes(['path' => '/wp-*', 'rate' => 2, 'window' => 60], ['/WP-LOGIN.PHP', '/wp-cron.php', '/WP-ADMIN/edit.php'])
        );
    }

    /**
     * A pattern written as a regex keeps the flags its author chose.
     */
    public function testARegexPatternKeepsItsOwnFlags(): void
    {
        $this->assertSame(
            'ok,ok,ok',
            $this->outcomes(['path' => '#^/wp-login\.php$#', 'rate' => 1, 'window' => 60], ['/wp-login.php', '/WP-LOGIN.PHP', '/WP-LOGIN.PHP'])
        );
        $this->assertSame(
            'ok,refused',
            $this->outcomes(['path' => '#^/wp-login\.php$#i', 'rate' => 1, 'window' => 60], ['/wp-login.php', '/WP-LOGIN.PHP'])
        );
    }

    /**
     * A key that counts by the request path counts every spelling as one path, and a path
     * already in lower case keys exactly as it did before, so no counter resets for it.
     */
    public function testThePathKeyComponentIgnoresCase(): void
    {
        $plugin = new class([], []) extends RateLimit {
            /**
             * @param array<string, mixed> $rule
             */
            public function key(Request $request, array $rule): string
            {
                return $this->buildRateKey($request, $rule);
            }
        };
        $rule = ['path' => '/wp-*', 'key' => ['client_ip', 'path']];

        $lower = $plugin->key(Request::create('/wp-login.php', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']), $rule);
        $upper = $plugin->key(Request::create('/WP-LOGIN.PHP', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']), $rule);

        $this->assertSame($lower, $upper);
        $this->assertSame('rate:' . hash('xxh128', "client_ip=203.0.113.9\0path=/wp-login.php"), $lower);
    }
}
