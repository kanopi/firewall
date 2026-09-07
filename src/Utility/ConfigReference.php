<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * Resolve `%config(dot.path)%` references against the merged configuration (#184).
 *
 * A deployment that keeps blocked clients in a database and also logs firewall
 * events to one declares the same connection twice, in `storage.config` and
 * again under `logger:`. Two places to change, and one of them can be
 * forgotten -- which produces a firewall whose log handler quietly writes
 * nowhere.
 *
 * ```yaml
 * storage:
 *   type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
 *   config:
 *     connection:
 *       driver: pdo_mysql
 *       host: "%env(DB_HOST)%"
 *       dbname: "%env(DB_NAME)%"
 *       user: "%env(DB_USER)%"
 *       password: "%env(DB_PASSWORD)%"
 *
 * logger:
 *   - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
 *     args:
 *       - table: firewall_log
 *         connection: "%config(storage.config.connection)%"
 * ```
 *
 * WHY THIS IS NOT A YAML ANCHOR:
 *
 * An anchor (`&db` / `*db`) already does this and needs no library support at
 * all, so it is the right answer whenever both blocks live in one file -- and
 * it stays documented as such. What it cannot do is cross a file boundary, and
 * `configs:` includes are a normal way to organise this project's
 * configuration: `storage:` in one included file and `logger:` in another
 * cannot share an anchor, because each file is parsed on its own.
 *
 * WHY IT IS RESOLVED HERE RATHER THAN WITH THE OTHER TOKENS:
 *
 * `%env()%` and `%file()%` are resolved per file by `TokenSubstitute`, during
 * the parse, because a variable and a path mean the same thing wherever they
 * appear. A reference to another part of the configuration does not: until
 * every file has been merged there is no "the configuration" to point into.
 * So this runs once, in `Config::load()`, after the merge and after overrides
 * -- which is exactly what gives it the reach an anchor lacks.
 *
 * WHY IT IS GENERIC RATHER THAN A CONNECTION FEATURE:
 *
 * The duplication that prompted it is a database connection, and two earlier
 * attempts to solve just that put a specific log handler's name into
 * `Firewall::create()`. Nothing here knows what a connection is. The same
 * token deduplicates a shared header list, a repeated `metadata.sources` block
 * or a rate-limit backend's own connection, and the firewall's startup path is
 * not involved at all.
 *
 * Behaviour mirrors `TokenSubstitute` so the two read alike:
 *
 *  - A value that is *exactly* one token is replaced by whatever is at that
 *    path, with its type intact -- which is what makes it usable for an array
 *    like a connection block.
 *  - A token *inside* a larger string is interpolated, so the target has to be
 *    a scalar. Referencing an array there is a mistake rather than something
 *    to guess at, and is reported.
 *
 * A path is matched literally, segment by segment. `DotPath` is deliberately
 * not used: its `*`, `a|b` and `{a,b}` are what a *pattern* means, and a
 * reference naming one thing should not quietly resolve to the first of
 * several.
 */
final class ConfigReference
{
    /**
     * Pattern for a value that is nothing but one reference.
     */
    private const WHOLE = '/^%config\(([^)]*)\)%$/';

    /**
     * Pattern for references appearing inside a larger string.
     */
    private const INLINE = '/%config\(([^)]*)\)%/';

    /**
     * Resolve every `%config(...)%` reference in a merged configuration.
     *
     * @param array<array-key, mixed> $config
     *   The merged configuration.
     * @param array<int, string>|null $problems
     *   Filled with a message per reference that could not be resolved. Each
     *   is reported by `Config::load()` as a load warning, so an operator sees
     *   it rather than only seeing the effect. Nullable so a caller can pass a
     *   variable that does not exist yet, which a by-ref parameter typed
     *   `array` would reject.
     *
     * @param-out array<int, string> $problems
     *
     * @return array<array-key, mixed>
     *   The configuration with references resolved. A reference that cannot be
     *   resolved is left in place as its literal token: the value is visibly
     *   wrong in whatever reads it, which beats substituting NULL and letting
     *   it look like something that was never configured.
     */
    public static function resolve(array $config, ?array &$problems = null): array
    {
        $problems ??= [];

        // Nothing to do for the overwhelmingly common config that uses no
        // references. Checked before walking because `load()` runs per request.
        if (!self::containsReference($config)) {
            return $config;
        }

        return self::resolveNode($config, $config, [], $problems);
    }

    /**
     * Whether a structure contains a reference token anywhere.
     *
     * @param mixed $node
     *   The node to scan.
     *
     * @return bool
     *   TRUE when at least one `%config(` appears in a string value or key.
     */
    private static function containsReference(mixed $node): bool
    {
        if (is_string($node)) {
            return str_contains($node, '%config(');
        }

        if (!is_array($node)) {
            return false;
        }

        foreach ($node as $value) {
            if (self::containsReference($value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve references within one node.
     *
     * @param mixed $node
     *   The node being resolved.
     * @param array<array-key, mixed> $root
     *   The whole configuration, which paths are read against.
     * @param array<int, string> $resolving
     *   Paths currently being resolved further up the stack, for cycle
     *   detection.
     * @param array<int, string> $problems
     *   Collected messages, by reference.
     *
     * @return mixed
     *   The node with its references resolved.
     */
    private static function resolveNode(mixed $node, array $root, array $resolving, array &$problems): mixed
    {
        if (is_array($node)) {
            foreach ($node as $key => $value) {
                $node[$key] = self::resolveNode($value, $root, $resolving, $problems);
            }

            return $node;
        }

        if (!is_string($node) || !str_contains($node, '%config(')) {
            return $node;
        }

        if (preg_match(self::WHOLE, $node, $matches) === 1) {
            return self::lookup($matches[1], $root, $resolving, $problems, $node);
        }

        return preg_replace_callback(
            self::INLINE,
            static function (array $matches) use ($root, $resolving, &$problems, $node): string {
                $value = self::lookup($matches[1], $root, $resolving, $problems, $matches[0]);

                if (is_scalar($value) || $value === null) {
                    return (string) $value;
                }

                // An array cannot be spliced into the middle of a string, and
                // guessing at a representation -- JSON? a comma list? -- would
                // be inventing a meaning the author did not write. Reported
                // and left alone, so the literal token shows where it was.
                $problems[] = sprintf(
                    'Reference "%s" in "%s" points at a value of type %s, which cannot be interpolated into a string. Make the whole value the reference instead.',
                    $matches[1],
                    $node,
                    get_debug_type($value)
                );

                return $matches[0];
            },
            $node
        ) ?? $node;
    }

    /**
     * Read the value a reference points at, resolving it in turn.
     *
     * @param string $path
     *   Dot-separated path, as written inside the token.
     * @param array<array-key, mixed> $root
     *   The whole configuration.
     * @param array<int, string> $resolving
     *   Paths currently being resolved further up the stack.
     * @param array<int, string> $problems
     *   Collected messages, by reference.
     * @param string $token
     *   The literal token, returned unchanged when it cannot be resolved.
     *
     * @return mixed
     *   The referenced value, or the literal token.
     */
    private static function lookup(string $path, array $root, array $resolving, array &$problems, string $token): mixed
    {
        $path = trim($path);

        if ($path === '') {
            $problems[] = sprintf('Reference "%s" names no path.', $token);

            return $token;
        }

        // A reference to a value that is itself a reference is resolved on the
        // way through, so `a -> b -> c` works. A cycle would recurse until the
        // stack gave out, which is a fatal rather than a message, so the chain
        // is carried down and checked.
        if (in_array($path, $resolving, true)) {
            $problems[] = sprintf(
                'Reference "%s" is circular: %s.',
                $path,
                implode(' -> ', [...$resolving, $path])
            );

            return $token;
        }

        $node = $root;

        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                $problems[] = sprintf('Reference "%s" points at nothing in the merged configuration.', $path);

                return $token;
            }

            $node = $node[$segment];
        }

        return self::resolveNode($node, $root, [...$resolving, $path], $problems);
    }
}
