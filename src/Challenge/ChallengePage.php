<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * `challenge.page`: the wording, language and styling of the interstitial (#451).
 *
 * In `mode: block` the challenge page is the library's, and until this its title, heading,
 * button, language and CSS were fixed. A site wanting the page in its own language and
 * colours had to write a provider -- wrapping a built-in one, since those are final -- even
 * though the page itself was fine.
 *
 * Every key is optional; an unset key keeps today's page. Text is plain text, escaped when
 * the page is written, as `challenge.notice` is. Two keys are not text:
 *
 * - `styles` is CSS, written into the page's `<style>` block after the built-in rules. It is
 *   the operator's, so it is trusted -- except that it must not contain `</style`, which
 *   would close the block and let whatever follows be parsed as markup.
 * - `stylesheet` is a `<link>` target: a path on this site, or an `https:` URL.
 *
 * Checked twice. At startup, where a bad value is a `ConfigurationException`, because a page
 * that silently ignored a typo -- or dropped the site's whole stylesheet -- would look like
 * the feature not working. And again when the page is written, where a bad value is dropped
 * instead: providers are also called by hosts, with a context nothing validated.
 */
final class ChallengePage
{
    /**
     * Keys taken as plain text.
     */
    public const TEXT_KEYS = ['title', 'heading', 'intro', 'button', 'error_message'];

    /**
     * Every key `challenge.page` accepts.
     */
    public const KEYS = ['lang', 'title', 'heading', 'intro', 'button', 'error_message', 'styles', 'stylesheet'];

    /**
     * Validate `challenge.page` and reduce it to the keys that are set.
     *
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<string, string>
     *   The keys that are set, trimmed. Empty when nothing is configured.
     *
     * @throws ConfigurationException
     *   When a key is unknown or its value cannot be used.
     */
    public static function fromConfig(mixed $declared): array
    {
        if ($declared === null || $declared === []) {
            return [];
        }

        $problems = self::problems($declared);

        if ($problems !== []) {
            throw new ConfigurationException('challenge.page: ' . implode('; ', $problems));
        }

        return self::accepted($declared);
    }

    /**
     * What is wrong with a `challenge.page` value.
     *
     * The linter reports these, and fromConfig() refuses to start on them.
     *
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<int, string>
     *   One line per problem; empty when the value can be used.
     */
    public static function problems(mixed $declared): array
    {
        if ($declared === null || $declared === []) {
            return [];
        }

        if (!is_array($declared)) {
            return [sprintf('must be a map of %s, not %s', implode(', ', self::KEYS), get_debug_type($declared))];
        }

        $problems = [];

        foreach ($declared as $key => $value) {
            if (!in_array($key, self::KEYS, true)) {
                $problems[] = sprintf('unknown key "%s"; expected one of %s', $key, implode(', ', self::KEYS));

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
     * The page values in a render context, keeping only those that are safe to write.
     *
     * Every built-in provider passes this to InterstitialRenderer::render(). A context
     * built by the Firewall has been validated already; one built by a host has not, so a
     * value that would fail validation is left out here rather than written.
     *
     * @param array<string, mixed> $context
     *   The render context.
     *
     * @return array<string, string>
     *   The usable page values.
     */
    public static function fromContext(array $context): array
    {
        $page = $context['page'] ?? [];

        return is_array($page) ? self::accepted($page) : [];
    }

    /**
     * The keys of a page value that are known, set and usable.
     *
     * @param array<mixed> $page
     *   A `challenge.page` value.
     *
     * @return array<string, string>
     *   The usable values, trimmed.
     */
    private static function accepted(array $page): array
    {
        $accepted = [];

        foreach (self::KEYS as $key) {
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
