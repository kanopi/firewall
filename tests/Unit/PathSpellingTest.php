<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Spelling around a rule on a front-controller route (#425).
 *
 * The web server normalises a URL before it routes it to `index.php`, and `getPathInfo()`
 * does not, so `//wp-json/wp/v2/users` reached the rules as written while WordPress
 * served it as the REST route. Every request here is shaped as the server hands it to PHP:
 * `SCRIPT_NAME` is the front controller, `REQUEST_URI` is what the client sent.
 */
class PathSpellingTest extends AbstractTestCase
{
    private function firewall(array $plugins, string $source = 'pathinfo'): Firewall
    {
        return Firewall::create([
            __DIR__ . '/../../presets/wordpress.yml',
            [
                'global' => ['mode' => 'exception', 'path_source' => $source],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
                'plugins' => $plugins,
            ],
        ]);
    }

    private function throughIndex(string $uri): Request
    {
        return new Request([], [], [], [], [], [
            'REQUEST_URI' => $uri,
            'SCRIPT_NAME' => '/index.php',
            'PHP_SELF' => '/index.php',
            'SCRIPT_FILENAME' => '/var/www/html/index.php',
            'REQUEST_METHOD' => 'GET',
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_HOST' => 'example.com',
        ]);
    }

    private function refuses(Firewall $firewall, Request $request): bool
    {
        try {
            $firewall->evaluate($request);

            return false;
        } catch (FirewallBlockedException) {
            return true;
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function spellings(): array
    {
        return [
            'as written' => ['/wp-json/wp/v2/users'],
            'a doubled slash' => ['//wp-json/wp/v2/users'],
            'a dot segment' => ['/./wp-json/wp/v2/users'],
            'a dot-dot segment' => ['/x/../wp-json/wp/v2/users'],
            'percent-encoded' => ['/%77p-json/wp/v2/users'],
            'a segment parameter' => ['/wp-json;x/wp/v2/users'],
        ];
    }

    /**
     * `presets/wordpress.yml` blocks `path@starts_with:/wp-json/`, under either source.
     */
    #[DataProvider('spellings')]
    public function testEverySpellingMeetsTheRule(string $uri): void
    {
        foreach (['pathinfo', 'script_name'] as $source) {
            $this->assertTrue($this->refuses($this->firewall([], $source), $this->throughIndex($uri)), $source);
        }
    }

    /**
     * And a rate limit on the route counts every spelling against one budget.
     */
    #[DataProvider('spellings')]
    public function testEverySpellingCountsTowardOneLimit(string $uri): void
    {
        $firewall = Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
                'response' => 'block',
                'enable' => true,
                'config' => [['path' => '/wp-json/*', 'rate' => 2, 'window' => 60]],
            ]],
        ]]);

        $this->assertFalse($this->refuses($firewall, $this->throughIndex('/wp-json/wp/v2/users')));
        $this->assertFalse($this->refuses($firewall, $this->throughIndex('/wp-json/wp/v2/users')));
        $this->assertTrue($this->refuses($firewall, $this->throughIndex($uri)), 'The third request is the same route.');
    }

    /**
     * A public page is still served.
     */
    public function testAPublicPageIsServed(): void
    {
        $this->assertTrue($this->firewall([])->evaluate($this->throughIndex('/2026/09/a-post/')));
    }
}
