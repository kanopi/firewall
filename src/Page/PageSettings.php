<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Page;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * The settings a page the firewall writes takes from configuration (#451, #452).
 *
 * `challenge.page`, `global.block_page` and `global.lockdown_page` are all maps of the
 * same kind: plain text, a language tag, CSS and a stylesheet. Each page names which keys
 * it accepts; the checks on a value are the same whichever page it is for, so that CSS
 * which could not close the challenge page's style block cannot close the block page's
 * either.
 *
 * Every value is checked twice. At startup, where a bad one is a `ConfigurationException`
 * naming every problem. And when the page is written, where a bad one is dropped instead:
 * a page can be rendered from values a host supplied and nothing validated.
 *
 * - `lang` is a language tag: `en`, `fr-CA`, `zh-Hant-TW`.
 * - `styles` is CSS. It is the operator's, so it is trusted -- except that it must not
 *   contain `</style`, which would close the block and let whatever follows be parsed as
 *   markup.
 * - `stylesheet` is a `<link>` target: a path on this site, or an `https:` URL.
 * - Every other key is plain text, escaped when the page is written.
 */
final class PageSettings
{
    /**
     * Keys every page takes that are not plain text.
     */
    public const SPECIAL_KEYS = ['lang', 'styles', 'stylesheet'];

    /**
     * Validate a page setting and reduce it to the keys that are set.
     *
     * @param string $label
     *   The setting's name, for the message: `challenge.page`, `global.block_page`.
     * @param array<int, string> $keys
     *   The keys this page accepts.
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<string, string>
     *   The keys that are set, trimmed. Empty when nothing is configured.
     *
     * @throws ConfigurationException
     *   When a key is unknown or its value cannot be used.
     */
    public static function fromConfig(string $label, array $keys, mixed $declared): array
    {
        $problems = self::problems($keys, $declared);

        if ($problems !== []) {
            throw new ConfigurationException($label . ': ' . implode('; ', $problems));
        }

        return is_array($declared) ? self::accepted($keys, $declared) : [];
    }

    /**
     * What is wrong with a page setting.
     *
     * The linter reports these, and fromConfig() refuses to start on them.
     *
     * @param array<int, string> $keys
     *   The keys this page accepts.
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<int, string>
     *   One line per problem; empty when the value can be used.
     */
    public static function problems(array $keys, mixed $declared): array
    {
        if ($declared === null || $declared === []) {
            return [];
        }

        if (!is_array($declared)) {
            return [sprintf('must be a map of %s, not %s', implode(', ', $keys), get_debug_type($declared))];
        }

        $problems = [];

        foreach ($declared as $key => $value) {
            if (!in_array($key, $keys, true)) {
                $problems[] = sprintf('unknown key "%s"; expected one of %s', $key, implode(', ', $keys));

                continue;
            }

            if ($value === null) {
                continue;
            }

            if (!is_string($value)) {
                $problems[] = sprintf('%s must be text, not %s', $key, get_debug_type($value));

                continue;
            }

            $problem = self::valueProblem($key, trim($value));

            if ($problem !== null) {
                $problems[] = $problem;
            }
        }

        return $problems;
    }

    /**
     * The keys of a page value that are known, set and usable.
     *
     * For a value nothing validated: anything that would fail validation is left out.
     *
     * @param array<int, string> $keys
     *   The keys this page accepts.
     * @param mixed $page
     *   A page value.
     *
     * @return array<string, string>
     *   The usable values, trimmed.
     */
    public static function accepted(array $keys, mixed $page): array
    {
        if (!is_array($page)) {
            return [];
        }

        $accepted = [];

        foreach ($keys as $key) {
            $value = $page[$key] ?? null;

            if (!is_string($value)) {
                continue;
            }

            $value = trim($value);

            if ($value !== '' && self::valueProblem($key, $value) === null) {
                $accepted[$key] = $value;
            }
        }

        return $accepted;
    }

    /**
     * What is wrong with one value, if anything.
     *
     * @param string $key
     *   A known key.
     * @param string $value
     *   Its value, trimmed.
     *
     * @return string|null
     *   The problem, or null when the value can be used. An empty value is always usable:
     *   it means the key is unset.
     */
    private static function valueProblem(string $key, string $value): ?string
    {
        if ($value === '') {
            return null;
        }

        // A language tag (BCP 47's shape, not its registry): `en`, `fr-CA`,
        // `zh-Hant-TW`. It is written into an attribute, where it is escaped
        // anyway; the shape check is so a typo is reported rather than shipped.
        if ($key === 'lang' && preg_match('/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/', $value) !== 1) {
            return sprintf('lang must be a language tag such as "en" or "fr-CA", not "%s"', $value);
        }

        // Inside <style>, the only thing that ends the block is `</style`, in
        // any case. Refused rather than escaped: CSS has no escaping that would
        // keep the operator's rule meaning what they wrote.
        if ($key === 'styles' && preg_match('#</style#i', $value) === 1) {
            return 'styles must not contain "</style"';
        }

        if ($key === 'stylesheet' && !self::isStylesheetTarget($value)) {
            return sprintf('stylesheet must be a path on this site ("/css/firewall.css") or an https: URL, not "%s"', $value);
        }

        return null;
    }

    /**
     * Whether a value can be a stylesheet `href`.
     *
     * A root-relative path, or an absolute `https:` URL. Not `//host/...`, which is another
     * site in disguise, not `http:`, which a page served over HTTPS will refuse anyway, and
     * not any other scheme -- `javascript:` and `data:` among them.
     */
    private static function isStylesheetTarget(string $value): bool
    {
        // Nothing an href needs, and everything that makes one ambiguous:
        // whitespace, control characters, quotes, angle brackets, backslashes.
        if (preg_match('/[\s\x00-\x1f\x7f"\'<>\\\\]/', $value) === 1) {
            return false;
        }

        if (str_starts_with($value, '/')) {
            return !str_starts_with($value, '//');
        }

        return filter_var($value, FILTER_VALIDATE_URL) !== false
            && strtolower((string) parse_url($value, PHP_URL_SCHEME)) === 'https';
    }
}
