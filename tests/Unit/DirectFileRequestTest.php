<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Files served directly, not through a front controller (#414).
 *
 * WordPress serves `wp-login.php`, `xmlrpc.php` and every `/wp-admin/*.php` as files of
 * their own, and Drupal does the same for `core/install.php` and its siblings. For each,
 * `SCRIPT_NAME` is the file, Symfony takes it as the base URL, and `getPathInfo()` is `/`,
 * so under the default `path_source` the shipped presets never fired on the paths they
 * name, and a negated path condition fired on all of them.
 *
 * Every request here is shaped the way `Request::createFromGlobals()` shapes one on a real
 * server, which is what `evaluate()` builds when it is called with no argument -- the
 * integration the platform docs show.
 */
class DirectFileRequestTest extends AbstractTestCase
{
    private const PRESETS = __DIR__ . '/../../presets/';

    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    /**
     * @param array<int, string> $presets
     * @param array<string, mixed> $global
     * @param array<int, array<string, mixed>> $plugins
     */
    private function firewall(
        array $presets,
        array $global = [],
        array $plugins = [],
        ?TestHandler $handler = null
    ): Firewall {
        $inputs = array_map(static fn(string $preset): string => self::PRESETS . $preset, $presets);
        $inputs[] = [
            'global' => $global + ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => $plugins,
        ];

        if ($handler instanceof TestHandler) {
            $inputs[] = ['logger' => [['class' => $handler]]];
        }

        return Firewall::create($inputs);
    }

    /**
     * A request for a file PHP runs directly, as the web server hands it over.
     *
     * @param array<string, string> $headers
     */
    private function direct(string $uri, ?string $script = null, string $method = 'POST', array $headers = []): Request
    {
        $script ??= (string) parse_url($uri, PHP_URL_PATH);

        // As createFromGlobals() would have it: $_GET and QUERY_STRING from the URI.
        $queryString = str_contains($uri, '?') ? explode('?', $uri, 2)[1] : '';
        parse_str($queryString, $query);

        return new Request($query, [], [], [], [], [
            'REQUEST_URI' => $uri,
            'QUERY_STRING' => $queryString,
            'SCRIPT_NAME' => $script,
            'PHP_SELF' => $script,
            'SCRIPT_FILENAME' => '/var/www/html' . $script,
            'REQUEST_METHOD' => $method,
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_HOST' => 'example.com',
        ] + $headers);
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
     * The WordPress back end.
     *
     * @return array<string, array{string, string|null}>
     */
    public static function wordpressEntryPoints(): array
    {
        return [
            'wp-login.php' => ['/wp-login.php', null],
            'xmlrpc.php' => ['/xmlrpc.php', null],
            'an admin screen' => ['/wp-admin/edit.php', null],
            'the admin index' => ['/wp-admin/', '/wp-admin/index.php'],
            'wp-cron.php' => ['/wp-cron.php', null],
        ];
    }

    /**
     * The bug, pinned: under the default source the WordPress preset does not see these.
     *
     * Kept as a test rather than deleted with the fix because it is the reason
     * `script_name` exists, and the default is not changing in 2.x. If this starts
     * failing, the default changed -- which is a 3.0 decision, not an accident.
     */
    #[DataProvider('wordpressEntryPoints')]
    public function testTheDefaultSourceMissesADirectFile(string $uri, ?string $script): void
    {
        $this->assertFalse($this->refuses($this->firewall(['wordpress.yml']), $this->direct($uri, $script)));
    }

    #[DataProvider('wordpressEntryPoints')]
    public function testRequestUriSeesADirectFile(string $uri, ?string $script): void
    {
        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'script_name']);

        $this->assertTrue($this->refuses($firewall, $this->direct($uri, $script)));
    }

    /**
     * A subdirectory install with `base_path` matches the preset as written.
     */
    #[DataProvider('wordpressEntryPoints')]
    public function testASubdirectoryInstallMatchesWithABasePath(string $uri, ?string $script): void
    {
        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'script_name', 'base_path' => '/blog']);

        $this->assertTrue($this->refuses(
            $firewall,
            $this->direct('/blog' . $uri, '/blog' . ($script ?? $uri))
        ));
    }

    /**
     * And ordinary pages through the front controller are served either way.
     */
    public function testAPublicPageIsStillServed(): void
    {
        foreach (['pathinfo', 'script_name'] as $source) {
            $firewall = $this->firewall(['wordpress.yml'], ['path_source' => $source]);

            $this->assertTrue(
                $firewall->evaluate($this->direct('/2026/09/a-post/', '/index.php', 'GET')),
                $source
            );
        }
    }

    /**
     * Drupal's real-file entry points, which also load `settings.php`.
     *
     * @return array<string, array{string}>
     */
    public static function drupalEntryPoints(): array
    {
        return [
            'core/install.php' => ['/core/install.php'],
            'core/rebuild.php' => ['/core/rebuild.php'],
            'core/authorize.php' => ['/core/authorize.php'],
        ];
    }

    #[DataProvider('drupalEntryPoints')]
    public function testDrupalEntryPointsAreSeenWithRequestUri(string $uri): void
    {
        $this->assertFalse($this->refuses($this->firewall(['drupal.yml']), $this->direct($uri)));
        $this->assertTrue($this->refuses(
            $this->firewall(['drupal.yml'], ['path_source' => 'script_name']),
            $this->direct($uri)
        ));
    }

    /**
     * The negated condition, which is worse than a rule that does not fire.
     *
     * `search-bots.yml` allows a verified search crawler everywhere *except* the back
     * end, written as `!path@regex:#^/(wp-admin|wp-login|…)`. Matched against `/`, the
     * exclusion is always true, so the allow -- which short-circuits everything after it
     * -- covered exactly the paths it was written to keep out.
     */
    public function testTheSearchBotExclusionHoldsOnADirectFile(): void
    {
        $request = fn(): Request => $this->direct('/wp-login.php', null, 'POST', ['HTTP_USER_AGENT' => self::GOOGLEBOT]);

        $this->assertFalse(
            $this->refuses($this->firewall(['search-bots.yml', 'wordpress.yml']), $request()),
            'Under pathinfo the crawler allow pre-empts the block: the bug.'
        );

        $this->assertTrue($this->refuses(
            $this->firewall(['search-bots.yml', 'wordpress.yml'], ['path_source' => 'script_name']),
            $request()
        ));
    }

    /**
     * A `/wp-login.php` rate limit counts, which under pathinfo it never did.
     */
    public function testALoginRateLimitCounts(): void
    {
        $rule = [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
            'response' => 'block',
            'enable' => true,
            'config' => [['path' => '/wp-login.php', 'rate' => 2, 'window' => 60]],
        ]];

        foreach (['pathinfo' => false, 'script_name' => true] as $source => $limited) {
            $firewall = $this->firewall([], ['path_source' => $source], $rule);
            $refused = false;

            foreach (range(1, 3) as $ignored) {
                $refused = $this->refuses($firewall, $this->direct('/wp-login.php'));
            }

            $this->assertSame($limited, $refused, $source);
        }
    }

    /**
     * The log line carries the path the rules matched, not `/` beside a URL naming the
     * file.
     */
    public function testTheLogCarriesTheMatchedPath(): void
    {
        $handler = new TestHandler(Level::Debug);

        $this->refuses(
            $this->firewall(['wordpress.yml'], ['path_source' => 'script_name'], [], $handler),
            $this->direct('/wp-login.php')
        );

        $paths = array_values(array_unique(array_filter(array_map(
            static fn($record): mixed => $record->context['path'] ?? null,
            $handler->getRecords()
        ))));

        $this->assertSame(['/wp-login.php'], $paths);
    }

    /**
     * An unknown source falls back to pathinfo, with a warning, rather than refusing to
     * start.
     */
    public function testAnUnknownSourceFallsBackWithAWarning(): void
    {
        $handler = new TestHandler(Level::Debug);

        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'requesturi'], [], $handler);

        $this->assertTrue($handler->hasRecordThatContains('Unknown global.path_source', Level::Warning));
        $this->assertFalse($this->refuses($firewall, $this->direct('/wp-login.php')));
    }

    /**
     * An unusable base path strips nothing, with a warning.
     */
    public function testAnUnusableBasePathStripsNothing(): void
    {
        $handler = new TestHandler(Level::Debug);

        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'script_name', 'base_path' => '/blog?x'], [], $handler);

        $this->assertTrue($handler->hasRecordThatContains('Unusable global.base_path', Level::Warning));
        $this->assertTrue($this->refuses($firewall, $this->direct('/wp-login.php')));
    }

    /**
     * The spellings a server runs as `wp-login.php`, which a raw-URI source would let past
     * both the preset and the rate limit -- adding a bypass to the change meant to close
     * one.
     *
     * @return array<string, array{string}>
     */
    public static function alternateSpellings(): array
    {
        return [
            'a doubled slash' => ['//wp-login.php'],
            'a dot segment' => ['/./wp-login.php'],
            'a dot-dot segment' => ['/x/../wp-login.php'],
            'percent-encoded' => ['/%77p-login.php'],
            'a semicolon parameter' => ['/wp-login.php;x'],
        ];
    }

    #[DataProvider('alternateSpellings')]
    public function testAnAlternateSpellingIsStillRefused(string $uri): void
    {
        $this->assertTrue($this->refuses(
            $this->firewall(['wordpress.yml'], ['path_source' => 'script_name']),
            $this->direct($uri, '/wp-login.php')
        ));
    }

    #[DataProvider('alternateSpellings')]
    public function testAnAlternateSpellingStillCountsTowardTheLimit(string $uri): void
    {
        $firewall = $this->firewall([], ['path_source' => 'script_name'], [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
            'response' => 'block',
            'enable' => true,
            'config' => [['path' => '/wp-login.php', 'rate' => 2, 'window' => 60]],
        ]]);

        $this->assertFalse($this->refuses($firewall, $this->direct('/wp-login.php')));
        $this->assertFalse($this->refuses($firewall, $this->direct('/wp-login.php')));
        $this->assertTrue(
            $this->refuses($firewall, $this->direct($uri, '/wp-login.php')),
            'A third attempt, spelled differently, is the same login page and the same budget.'
        );
    }

    /**
     * The block record names the matched path, and the URL the client asked for -- not
     * `/wp-login.php/`, which is what joining the base URL and `/` produced.
     */
    public function testTheBlockRecordNamesTheFile(): void
    {
        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'script_name']);
        $request = $this->direct('/wp-login.php?redirect_to=x', '/wp-login.php');

        $this->assertTrue($this->refuses($firewall, $request));

        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $record = $storage->isBlocked($storage->getKey($request));

        $this->assertIsArray($record);
        $this->assertSame('/wp-login.php', $record['request']['path']);
        $this->assertSame('http://example.com/wp-login.php?redirect_to=x', $record['request']['uri']);
    }

    /**
     * The log names the URL the client asked for, as the block record does (#419).
     *
     * It used getUri(), which joins the base URL and the path info. For a file served
     * directly those are the file and `/`, so the log said `/wp-login.php/?...` beside a
     * block record that, since 2.34.0, said `/wp-login.php?...`.
     */
    public function testTheLogAndTheBlockRecordAgreeOnTheUrl(): void
    {
        $handler = new TestHandler(Level::Debug);
        $firewall = $this->firewall(['wordpress.yml'], ['path_source' => 'script_name'], [], $handler);
        $request = $this->direct('/wp-login.php?redirect_to=x', '/wp-login.php');

        $this->assertTrue($this->refuses($firewall, $request));

        $urls = array_values(array_unique(array_filter(array_map(
            static fn($record): mixed => $record->context['url'] ?? null,
            $handler->getRecords()
        ))));

        $this->assertSame(['http://example.com/wp-login.php?redirect_to=x'], $urls);

        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $this->assertSame($urls[0], $storage->isBlocked($storage->getKey($request))['request']['uri']);
    }
}
