<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Symfony\Component\HttpFoundation\Request;

/**
 * The path every rule, rate limit, log line and block record calls `path` (#414).
 *
 * Symfony's `getPathInfo()` is the path relative to the front controller. That is right
 * where every request passes through one `index.php` -- Drupal's routes, Symfony, Laravel
 * -- and wrong where the application serves pages from other files. WordPress serves
 * `wp-login.php`, `xmlrpc.php` and every `/wp-admin/*.php` directly, Drupal serves
 * `core/install.php` and `core/authorize.php`, and for each of them `SCRIPT_NAME` is the
 * requested file, Symfony takes it as the base URL, and `getPathInfo()` is `/`. A rule on
 * `/wp-login.php` then never fires, and a negated one fires on every admin screen.
 *
 * `global.path_source` chooses:
 *
 * - `pathinfo` (the default): `getPathInfo()`, exactly as every earlier release.
 * - `script_name`: the file the web server actually ran. `getPathInfo()` when that is the
 *   front controller, and `SCRIPT_NAME` plus `PATH_INFO` when it is any other file.
 *
 * **Not `REQUEST_URI`, deliberately.** The web server decodes and normalises the URL
 * before it chooses a file; `REQUEST_URI` is the raw string the client sent. `/./wp-login.php`,
 * `/%77p-login.php`, `//wp-login.php` and `/x/../wp-login.php` all run `wp-login.php`, and
 * matching the raw string would let every one of them past a `path:/wp-login.php` rate
 * limit. `SCRIPT_NAME` is `/wp-login.php` for all of them.
 *
 * `global.base_path` names where the application starts, because on a direct-file request
 * nothing in the request says (`getBasePath()` for `/wp-admin/edit.php` is `/wp-admin`). It
 * is what tells the front controller (`<base_path>/index.php`) from any other file, and it
 * is taken off the front of a direct file's path, so a site installed at `/blog/` matches
 * rules written for the root.
 *
 * Resolved once per evaluation from the Request itself, never from `$_SERVER` -- which
 * under Octane, RoadRunner or Swoole belongs to the worker, not the request -- and carried
 * on the request, because the plugins that read it never see the global configuration.
 */
final class RequestPath
{
    /**
     * Where the resolved path travels.
     */
    public const ATTRIBUTE = '_kanopi_firewall.path';

    public const PATHINFO = 'pathinfo';

    public const SCRIPT_NAME = 'script_name';

    /**
     * The path to match, log and record for this request.
     *
     * @param Request $request
     *   The request.
     *
     * @return string
     *   The resolved path when the firewall has resolved one, `getPathInfo()` otherwise --
     *   so a plugin evaluated on its own behaves as it always has.
     */
    public static function of(Request $request): string
    {
        $path = $request->attributes->get(self::ATTRIBUTE);

        // Normalised here too, so a plugin evaluated on its own sees the same
        // path the firewall would have given it.
        return is_string($path) ? $path : self::normalise($request->getPathInfo());
    }

    /**
     * Resolve the path from a request and put it where of() finds it.
     *
     * Always overwrites, so a Request handed to two firewalls with different settings is
     * read by each on its own terms.
     *
     * @param Request $request
     *   The request.
     * @param string $source
     *   A valid `path_source`; see isValidSource().
     * @param string $basePath
     *   A normalised `base_path`; see normaliseBasePath().
     */
    public static function attach(Request $request, string $source, string $basePath = ''): void
    {
        $request->attributes->set(self::ATTRIBUTE, self::resolve($request, $source, $basePath));
    }

    /**
     * Resolve the path without attaching it.
     *
     * @param Request $request
     *   The request.
     * @param string $source
     *   A valid `path_source`.
     * @param string $basePath
     *   A normalised `base_path`.
     *
     * @return string
     *   The path, starting with `/`.
     */
    public static function resolve(Request $request, string $source, string $basePath = ''): string
    {
        return self::normalise(self::unnormalised($request, $source, $basePath));
    }

    /**
     * The path as the source gives it, before normalise().
     *
     * @param Request $request
     *   The request.
     * @param string $source
     *   A valid `path_source`.
     * @param string $basePath
     *   A normalised `base_path`.
     *
     * @return string
     *   The path.
     */
    private static function unnormalised(Request $request, string $source, string $basePath): string
    {
        if ($source !== self::SCRIPT_NAME) {
            return $request->getPathInfo();
        }

        $script = $request->server->get('SCRIPT_NAME');

        // No script is a request some host built by hand, or a CLI one. Nothing
        // ran a file, so there is no other file to prefer over the path.
        if (!is_string($script) || $script === '') {
            return $request->getPathInfo();
        }

        // Through the front controller, the path it routes is the answer, and it
        // is already relative to the application.
        if ($script === $basePath . '/index.php') {
            return $request->getPathInfo();
        }

        $pathInfo = $request->server->get('PATH_INFO');
        $path = $script . (is_string($pathInfo) ? $pathInfo : '');

        if ($path[0] !== '/') {
            $path = '/' . $path;
        }

        // On a segment boundary, so `base_path: /blog` does not turn
        // `/blogroll` into `roll`.
        if ($basePath !== '' && str_starts_with($path, $basePath . '/')) {
            return substr($path, strlen($basePath));
        }

        return $path;
    }

    /**
     * The URL the client asked for, without its query (#419).
     *
     * Not `getUri()`: that joins the base URL and the path info, and for a file served
     * directly those are the file and `/`, so `/wp-login.php` comes out as
     * `/wp-login.php/`. Logs and block records both build their URL from this, so the two
     * cannot disagree about it.
     *
     * @param Request $request
     *   The request.
     *
     * @return string
     *   Scheme, host and the requested path, as the client sent the path.
     */
    public static function urlWithoutQuery(Request $request): string
    {
        return $request->getSchemeAndHttpHost() . explode('?', $request->getRequestUri(), 2)[0];
    }

    /**
     * The URL the client asked for, with its query in Symfony's normalised form.
     *
     * @param Request $request
     *   The request.
     *
     * @return string
     *   The URL.
     */
    public static function url(Request $request): string
    {
        $query = $request->getQueryString();

        return self::urlWithoutQuery($request) . ($query === null ? '' : '?' . $query);
    }

    /**
     * Put a path in the one spelling every rule is written against (#425).
     *
     * `getPathInfo()` comes from the raw request URI, and the web server normalises the URL
     * before it routes to the front controller, so different spellings of one route reach
     * the rules with different paths. `//wp-json/wp/v2/users` is served by WordPress as the
     * REST route -- `WP::parse_request()` trims every leading slash -- while missing a rule
     * on `path@starts_with:/wp-json/`. The same goes for `/./wp-json`, `/x/../wp-json` and
     * `/%77p-json` wherever the application accepts them. So, the way RFC 3986 and the
     * servers do it:
     *
     * - percent-encoded unreserved characters (`A-Z a-z 0-9 - . _ ~`) are decoded, and any
     *   other percent-encoding keeps its meaning, with its hex digits upper-cased. `%2F`
     *   stays `%2F`: decoding it would change where the segments are;
     * - `;params` are dropped from each segment;
     * - repeated slashes are collapsed, and `.` segments removed.
     *
     * **`..` is not resolved.** Resolving it removes the segment before it, so it can make
     * the path the rules see *shorter* than the one the application routes:
     * `/wp-json/wp/v2/x/../../../../y` would be `/y` to the rules and still the REST API to
     * WordPress, which routes on the raw path. Every step above can only remove an empty or
     * `.` segment, so a path that began with a segment still begins with it, and a rule on
     * that prefix still matches.
     *
     * A trailing slash is kept, because `/wp-admin` and `/wp-admin/` are different rules.
     *
     * @param string $path
     *   A path starting with `/`.
     *
     * @return string
     *   The same path in its one spelling.
     */
    public static function normalise(string $path): string
    {
        $path = (string) preg_replace_callback(
            '/%([0-9A-Fa-f]{2})/',
            static function (array $match): string {
                $char = chr((int) hexdec($match[1]));

                return preg_match('/^[A-Za-z0-9\-._~]$/', $char) === 1 ? $char : '%' . strtoupper($match[1]);
            },
            $path
        );

        $segments = [];
        // Whether the path ends by naming a directory: a trailing slash, or a
        // last segment of `.` or `..`.
        $directory = false;

        foreach (explode('/', $path) as $segment) {
            $segment = explode(';', $segment, 2)[0];
            $directory = in_array($segment, ['', '.'], true);

            // `..` is kept as written, never resolved. Resolving it deletes the
            // segment before it, and the application routes on the raw path:
            // WordPress hands /wp-json/a/b/../../x to the REST API, while a
            // resolved /x would walk past every rule on /wp-json/. Every other
            // step here only drops an empty or `.` segment, so a path that
            // began with a segment still begins with it.
            if (!$directory) {
                $segments[] = $segment;
            }
        }

        if ($segments === []) {
            return '/';
        }

        return '/' . implode('/', $segments) . ($directory ? '/' : '');
    }

    /**
     * Whether a configured `path_source` is one this understands.
     *
     * @param mixed $source
     *   The configured value.
     *
     * @return bool
     *   TRUE for `pathinfo` or `script_name`.
     */
    public static function isValidSource(mixed $source): bool
    {
        return in_array($source, [self::PATHINFO, self::SCRIPT_NAME], true);
    }

    /**
     * Reduce a configured `base_path` to the form resolve() compares against.
     *
     * @param mixed $basePath
     *   The configured value.
     *
     * @return string|null
     *   `''` when there is nothing to strip (unset, empty, or `/`), the path with one
     *   leading slash and no trailing one otherwise, or NULL when the value is not a
     *   usable path at all.
     */
    public static function normaliseBasePath(mixed $basePath): ?string
    {
        if ($basePath === null) {
            return '';
        }

        if (!is_string($basePath) || str_contains($basePath, '?') || str_contains($basePath, '#')) {
            return null;
        }

        $trimmed = trim(trim($basePath), '/');

        return $trimmed === '' ? '' : '/' . $trimmed;
    }
}
