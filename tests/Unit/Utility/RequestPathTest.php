<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Utility\RequestPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * `global.path_source` and `global.base_path` (#414).
 *
 * Every request here is built the way `Request::createFromGlobals()` builds one on a real
 * server -- with `SCRIPT_NAME` set to the file PHP is running -- because that is the input
 * that makes `getPathInfo()` come back as `/`. `Request::create()` sets no script, and a
 * test written with it would pass against the bug.
 */
class RequestPathTest extends TestCase
{
    private function request(string $uri, string $script, ?string $pathInfo = null): Request
    {
        return new Request([], [], [], [], [], [
            'REQUEST_URI' => $uri,
            'SCRIPT_NAME' => $script,
            'PHP_SELF' => $script . ($pathInfo ?? ''),
            'SCRIPT_FILENAME' => '/var/www/html' . $script,
        ] + ($pathInfo === null ? [] : ['PATH_INFO' => $pathInfo]));
    }

    /**
     * The reproduction from the issue, and the reason the key exists.
     *
     * @param string $uri
     *   REQUEST_URI.
     * @param string $script
     *   SCRIPT_NAME.
     * @param string|null $pathInfo
     *   PATH_INFO, when the server set one.
     * @param string $pathinfo
     *   What `pathinfo` gives.
     * @param string $scriptName
     *   What `script_name` gives.
     */
    #[DataProvider('requests')]
    public function testEachSource(
        string $uri,
        string $script,
        ?string $pathInfo,
        string $pathinfo,
        string $scriptName
    ): void {
        $request = $this->request($uri, $script, $pathInfo);

        $this->assertSame($pathinfo, RequestPath::resolve($request, RequestPath::PATHINFO));
        $this->assertSame($scriptName, RequestPath::resolve($request, RequestPath::SCRIPT_NAME));
    }

    /**
     * @return array<string, array{string, string, string|null, string, string}>
     */
    public static function requests(): array
    {
        return [
            'wp-login.php, served directly' => ['/wp-login.php', '/wp-login.php', null, '/', '/wp-login.php'],
            'an admin screen' => ['/wp-admin/edit.php', '/wp-admin/edit.php', null, '/', '/wp-admin/edit.php'],
            'the admin index' => ['/wp-admin/', '/wp-admin/index.php', null, '/', '/wp-admin/index.php'],
            'xmlrpc.php' => ['/xmlrpc.php', '/xmlrpc.php', null, '/', '/xmlrpc.php'],
            'a custom endpoint, with a query' => ['/sso/oauth.php?x=1', '/sso/oauth.php', null, '/', '/sso/oauth.php'],
            'a path-info suffix' => ['/wp-login.php/extra', '/wp-login.php', '/extra', '/extra', '/wp-login.php/extra'],
            'drupal core/install.php' => ['/core/install.php', '/core/install.php', null, '/', '/core/install.php'],
            // Through the front controller the two agree, because script_name
            // defers to the path the front controller routes.
            'through the front controller' => ['/learning/?a=1', '/index.php', null, '/learning/', '/learning/'],
            'the site root' => ['/', '/index.php', null, '/', '/'],
            'the front controller in the URL' => ['/index.php/foo', '/index.php', '/foo', '/foo', '/foo'],
        ];
    }

    /**
     * The reason this is not `REQUEST_URI`.
     *
     * The web server decodes and normalises the URL before it chooses a file, so every one
     * of these runs `wp-login.php`. Matched as the raw string, each would walk past a
     * `path:/wp-login.php` rate limit -- adding a bypass to the change that exists to close
     * one. `SCRIPT_NAME` is what the server ran, after all of that.
     *
     * @param string $uri
     *   A spelling of wp-login.php that the server runs as wp-login.php.
     */
    #[DataProvider('alternateSpellings')]
    public function testAnAlternateSpellingResolvesToTheFileThatRan(string $uri): void
    {
        $this->assertSame(
            '/wp-login.php',
            RequestPath::resolve($this->request($uri, '/wp-login.php'), RequestPath::SCRIPT_NAME)
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function alternateSpellings(): array
    {
        return [
            'plain' => ['/wp-login.php'],
            'a doubled slash' => ['//wp-login.php'],
            'a dot segment' => ['/./wp-login.php'],
            'a dot-dot segment' => ['/x/../wp-login.php'],
            'percent-encoded' => ['/%77p-login.php'],
            'a semicolon parameter' => ['/wp-login.php;x'],
        ];
    }

    /**
     * `base_path` names the application root, so presets written for the site root match
     * a subdirectory install, and its own index.php is still the front controller.
     *
     * @param string $uri
     *   REQUEST_URI.
     * @param string $script
     *   SCRIPT_NAME.
     * @param string $expected
     *   The resolved path with `base_path: /blog`.
     */
    #[DataProvider('subdirectoryRequests')]
    public function testASubdirectoryInstall(string $uri, string $script, string $expected): void
    {
        $this->assertSame(
            $expected,
            RequestPath::resolve($this->request($uri, $script), RequestPath::SCRIPT_NAME, '/blog')
        );
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function subdirectoryRequests(): array
    {
        return [
            'a direct file' => ['/blog/wp-login.php', '/blog/wp-login.php', '/wp-login.php'],
            'an admin screen' => ['/blog/wp-admin/edit.php', '/blog/wp-admin/edit.php', '/wp-admin/edit.php'],
            'the front controller' => ['/blog/learning/', '/blog/index.php', '/learning/'],
            'the application root' => ['/blog/', '/blog/index.php', '/'],
            // The site root's index.php is not this application's front
            // controller, so it is a file like any other.
            'another index.php' => ['/index.php', '/index.php', '/index.php'],
            // On a segment boundary: /blogroll is not inside /blog.
            'a longer segment is not stripped' => ['/blogroll/x.php', '/blogroll/x.php', '/blogroll/x.php'],
            'outside the base is left whole' => ['/other/x.php', '/other/x.php', '/other/x.php'],
        ];
    }

    /**
     * `pathinfo` ignores `base_path`.
     */
    public function testPathinfoIgnoresTheBasePath(): void
    {
        $request = $this->request('/blog/wp-login.php', '/blog/wp-login.php');

        $this->assertSame('/', RequestPath::resolve($request, RequestPath::PATHINFO, '/blog'));
    }

    /**
     * A request with no script -- one a host or `Request::create()` built by hand -- falls
     * back to the path, because no file ran.
     */
    public function testNoScriptIsThePath(): void
    {
        $request = Request::create('/wp-login.php');
        $request->server->remove('SCRIPT_NAME');

        $this->assertSame('/wp-login.php', RequestPath::resolve($request, RequestPath::SCRIPT_NAME));
        $this->assertSame('/wp-login.php', RequestPath::resolve(Request::create('/wp-login.php'), RequestPath::SCRIPT_NAME));
    }

    /**
     * A script with no leading slash, which a hand-built bridge request can carry, still
     * resolves to a path rules can match.
     */
    public function testAScriptWithoutALeadingSlashIsRooted(): void
    {
        $this->assertSame(
            '/wp-login.php',
            RequestPath::resolve($this->request('/wp-login.php', 'wp-login.php'), RequestPath::SCRIPT_NAME)
        );
    }

    /**
     * Read from the Request, never from `$_SERVER`.
     *
     * Under Octane, RoadRunner or Swoole one worker serves many requests and `$_SERVER` is
     * the worker's, so a resolver reading it would give every request somebody else's path.
     */
    public function testTheRequestIsReadRatherThanTheGlobals(): void
    {
        $saved = $_SERVER;
        $_SERVER['SCRIPT_NAME'] = '/xmlrpc.php';
        $_SERVER['REQUEST_URI'] = '/xmlrpc.php';

        try {
            $this->assertSame(
                '/wp-login.php',
                RequestPath::resolve($this->request('/wp-login.php', '/wp-login.php'), RequestPath::SCRIPT_NAME)
            );
        } finally {
            $_SERVER = $saved;
        }
    }

    /**
     * @param mixed $configured
     *   The configured `base_path`.
     * @param string|null $expected
     *   What it normalises to.
     */
    #[DataProvider('basePaths')]
    public function testBasePathNormalisation(mixed $configured, ?string $expected): void
    {
        $this->assertSame($expected, RequestPath::normaliseBasePath($configured));
    }

    /**
     * @return array<string, array{mixed, string|null}>
     */
    public static function basePaths(): array
    {
        return [
            'unset' => [null, ''],
            'empty' => ['', ''],
            'the root' => ['/', ''],
            'plain' => ['/blog', '/blog'],
            'trailing slash' => ['/blog/', '/blog'],
            'no leading slash' => ['blog', '/blog'],
            'nested' => ['/sites/blog/', '/sites/blog'],
            'padded' => ['  /blog  ', '/blog'],
            'a query is not a path' => ['/blog?x=1', null],
            'a fragment is not a path' => ['/blog#top', null],
            'not a string' => [['/blog'], null],
        ];
    }

    public function testOnlyTheTwoSourcesAreValid(): void
    {
        $this->assertTrue(RequestPath::isValidSource('pathinfo'));
        $this->assertTrue(RequestPath::isValidSource('script_name'));
        $this->assertFalse(RequestPath::isValidSource('SCRIPT_NAME'));
        $this->assertFalse(RequestPath::isValidSource('request_uri'));
        $this->assertFalse(RequestPath::isValidSource(null));
    }

    /**
     * Until the firewall attaches a path, of() is getPathInfo(), so a plugin evaluated on
     * its own behaves exactly as it did before the key existed.
     */
    public function testOfFallsBackToPathinfo(): void
    {
        $request = $this->request('/wp-login.php', '/wp-login.php');

        $this->assertSame('/', RequestPath::of($request));

        RequestPath::attach($request, RequestPath::SCRIPT_NAME);
        $this->assertSame('/wp-login.php', RequestPath::of($request));

        // And a second firewall with other settings reads it on its own terms.
        RequestPath::attach($request, RequestPath::PATHINFO);
        $this->assertSame('/', RequestPath::of($request));
    }
}
