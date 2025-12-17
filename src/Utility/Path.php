<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Utility;

/**
 * Path utility class.
 */
final class Path
{
    /**
     * Determine whether a path is absolute (POSIX, Windows drive, UNC) or a URL.
     *
     * @param string $p
     *   The path string to test.
     *
     * @return bool
     *   True if the path is absolute (or a URL/stream); false if it's a relative filesystem path.
     */
    public static function isAbsolute(string $p): bool
    {
        return \str_starts_with($p, '/')
            || \preg_match('~^[A-Za-z]:[\\\\/]~', $p) === 1      // Windows C:\ or C:/
            || \str_starts_with($p, '\\\\')                       // UNC \\server\share
            || \preg_match('~^[a-z][a-z0-9+.-]*://~i', $p) === 1; // scheme://
    }

    /**
     * Heuristic to decide if a string looks like a URL or stream wrapper.
     *
     * @param string $s
     *   The string to check.
     *
     * @return bool
     *   True if it looks like "scheme://..."; false otherwise.
     */
    public static function looksLikeUrl(string $s): bool
    {
        return \preg_match('~^[a-z][a-z0-9+.-]*://~i', $s) === 1;
    }

    /**
     * Return a real path if available; otherwise ensure the path exists and return the original.
     *
     * Use this to gracefully handle paths where realpath() may fail (streams, zip, permissions) but the file exists.
     *
     * @param string $path
     *   The path to normalize.
     *
     * @return string
     *   Real path or the original if realpath() fails but the file exists.
     *
     * @throws \RuntimeException
     *   If the file does not exist.
     */
    public static function realOrGiven(string $path): string
    {
        $real = \realpath($path);
        if ($real !== false) {
            return $real;
        }

        if (!\file_exists($path)) {
            throw new \RuntimeException("Config not found: " . $path);
        }

        return $path; // exists but realpath failed (e.g., stream/zip/permission)
    }
}
