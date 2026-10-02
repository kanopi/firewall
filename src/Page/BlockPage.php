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
use Symfony\Component\HttpFoundation\Request;

/**
 * The page a refused visitor sees: `global.block_page` and `global.lockdown_page` (#452).
 *
 * A block used to be one line of `text/plain`, and the docs suggested loading an HTML file
 * into `banning_message` -- which a browser then showed as source. This is the page that
 * suggestion wanted, built the way `challenge.page` is (#451): the operator sets text, a
 * language and styles, and the firewall writes the document, on the same card and
 * stylesheet as the challenge interstitial.
 *
 * Off unless configured, so a site upgrading sees the plain-text response it always had:
 *
 * ```yaml
 * global:
 *   block_page: true          # the built-in page, as it comes
 *   lockdown_page:
 *     heading: "Back soon"
 *     message: "We are upgrading the site until 18:00 UTC."
 * ```
 *
 * A rule can carry its own, merged over the global one: `metadata.block_page`.
 *
 * ## An operator's own document
 *
 * `template` replaces the built-in document with the operator's (#456), usually loaded with
 * `%file(...)%`. The page's other keys fill its placeholders -- `{{page.message}}`,
 * `{{page.heading}}`, `{{page.title}}`, `{{page.lang}}` -- alongside every `{{request.*}}`
 * and `{{block.*}}` one, so a rule's own message still lands in the operator's layout.
 * The template carries its own styling, so `styles` and `stylesheet` are refused beside it.
 */
final class BlockPage
{
    /**
     * Every key a block or lockdown page accepts.
     */
    public const KEYS = ['lang', 'title', 'heading', 'message', 'styles', 'stylesheet', 'template'];

    /**
     * The placeholders a template is given from the page, besides the request's.
     */
    public const TEMPLATE_PLACEHOLDERS = ['page.message', 'page.heading', 'page.title', 'page.lang'];

    /**
     * Keys taken as plain text, in which `{{…}}` placeholders are substituted.
     */
    public const TEXT_KEYS = ['title', 'heading', 'message'];

    /**
     * What the built-in pages say, by kind.
     */
    public const DEFAULTS = [
        'block' => [
            'title' => 'Request blocked',
            'heading' => 'Request blocked',
            'message' => "This request was blocked by the site's firewall.\n"
                . 'If you think this is a mistake, contact the site owner and quote reference {{request.id}}.',
        ],
        'lockdown' => [
            'title' => 'Temporarily closed',
            'heading' => 'Temporarily closed',
            'message' => 'This site is temporarily closed to visitors. Please try again shortly.',
        ],
    ];

    /**
     * The policy an HTML refusal is sent with.
     *
     * The page has no script and posts nothing, so neither is allowed. Styles, images and
     * fonts are, from this site and over `https:`, so `stylesheet` and a logo in it work.
     */
    public const CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'self' https: 'unsafe-inline'; "
        . "img-src 'self' https: data:; font-src 'self' https: data:; base-uri 'none'; form-action 'none'; "
        . "frame-ancestors 'none'";

    /**
     * Validate a page setting.
     *
     * @param string $label
     *   The setting's name, for the message: `global.block_page`.
     * @param mixed $declared
     *   `true` for the built-in page, a map to change it, or nothing.
     *
     * @return array<string, string>|null
     *   The keys that are set, or null when no page is configured -- the response is then
     *   the plain text it has always been.
     *
     * @throws ConfigurationException
     *   When the value is not one of those, or a key cannot be used.
     */
    public static function fromConfig(string $label, mixed $declared): ?array
    {
        $problems = self::problems($declared);

        if ($problems !== []) {
            throw new ConfigurationException($label . ': ' . implode('; ', $problems));
        }

        return self::settings($declared);
    }

    /**
     * What is wrong with a page setting.
     *
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<int, string>
     *   One line per problem; empty when the value can be used.
     */
    public static function problems(mixed $declared): array
    {
        if ($declared === null || is_bool($declared)) {
            return [];
        }

        if (!is_array($declared)) {
            return [sprintf('must be true, false or a map of %s, not %s', implode(', ', self::KEYS), get_debug_type($declared))];
        }

        $problems = PageSettings::problems(self::KEYS, $declared);

        $template = $declared['template'] ?? null;
        if (is_string($template) && trim($template) !== '' && !self::isDocument($template)) {
            $problems[] = 'template must be an HTML document, with an <html> element';
        }

        return array_merge($problems, self::conflicts($declared));
    }

    /**
     * What is wrong with a rule's page once it is merged over the global one.
     *
     * Each is checked on its own by problems(); this catches a pair that is fine apart
     * and not together -- a global `template` and a rule's `styles`, which the template
     * would silently ignore.
     *
     * @param mixed $global
     *   The global page setting.
     * @param mixed $rule
     *   The rule's.
     *
     * @return array<int, string>
     *   One line per problem.
     */
    public static function mergedProblems(mixed $global, mixed $rule): array
    {
        if (!is_array($global) || !is_array($rule)) {
            return [];
        }

        // Only what the merge adds: a conflict inside either one on its own is
        // already reported against that setting.
        if (self::conflicts($global) !== [] || self::conflicts($rule) !== []) {
            return [];
        }

        return array_map(
            static fn(string $problem): string => $problem . ', once merged over the global page',
            self::conflicts(array_merge($global, $rule))
        );
    }

    /**
     * Whether a page sets a template alongside keys the template replaces.
     *
     * @param array<mixed> $page
     *   A page setting.
     *
     * @return array<int, string>
     *   The problem, or nothing.
     */
    private static function conflicts(array $page): array
    {
        if (!self::isSet($page['template'] ?? null)) {
            return [];
        }

        $replaced = array_values(array_filter(
            ['styles', 'stylesheet'],
            static fn(string $key): bool => self::isSet($page[$key] ?? null)
        ));

        if ($replaced === []) {
            return [];
        }

        return [sprintf(
            '%s cannot be set with template, which carries its own styling; put %s in the template',
            implode(' and ', $replaced),
            count($replaced) === 1 ? 'it' : 'them'
        )];
    }

    /**
     * Whether a template has no `{{page.message}}`, so a rule's message would not show.
     *
     * A warning rather than an error: a page that says the same thing whatever the rule is
     * a reasonable choice. The linter reports it.
     */
    public static function templateLacksMessage(mixed $declared): bool
    {
        $template = is_array($declared) ? ($declared['template'] ?? null) : null;

        return self::isSet($template)
            && preg_match('/\{\{\s*page\.message\s*\}\}/i', (string) $template) !== 1;
    }

    /**
     * Whether a template is a whole document rather than a fragment.
     */
    private static function isDocument(string $template): bool
    {
        return preg_match('/<html[\s>]/i', $template) === 1;
    }

    /**
     * Whether a page value is set: text with something in it.
     */
    private static function isSet(mixed $value): bool
    {
        return is_string($value) && trim($value) !== '';
    }

    /**
     * A page setting's usable keys, without validating it.
     *
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<string, string>|null
     *   As fromConfig(), with anything unusable left out.
     */
    public static function settings(mixed $declared): ?array
    {
        if ($declared === true) {
            return [];
        }

        if (!is_array($declared)) {
            return null;
        }

        return PageSettings::accepted(self::KEYS, $declared);
    }

    /**
     * Whether a client would rather read JSON than a page.
     *
     * Its first preference, not merely something it accepts: a browser sends `*\/*`
     * after `text/html`, and must still get the page.
     */
    public static function prefersJson(Request $request): bool
    {
        $preferred = strtolower($request->getAcceptableContentTypes()[0] ?? '');

        return $preferred === 'application/json' || str_ends_with($preferred, '+json');
    }

    /**
     * Build the HTML page.
     *
     * @param string $kind
     *   `block` or `lockdown`.
     * @param array<string, string> $text
     *   The page's text, placeholders already substituted: `title`, `heading`, `message`.
     *   Plain text; escaped here.
     * @param array<string, string> $settings
     *   The rest of the page's settings: `lang`, `styles`, `stylesheet`.
     *
     * @return string
     *   A complete HTML document.
     */
    public static function html(string $kind, array $text, array $settings): string
    {
        $defaults = self::DEFAULTS[$kind] ?? self::DEFAULTS['block'];

        $paragraphs = self::paragraphs($text['message'] ?? '');
        $paragraphs = $paragraphs === '' ? '' : '    ' . $paragraphs;

        return PageRenderer::document([
            'settings' => array_intersect_key($settings, array_flip(PageSettings::SPECIAL_KEYS)) + array_filter([
                'title' => $text['title'] ?? '',
                'heading' => $text['heading'] ?? '',
            ], static fn(string $value): bool => trim($value) !== ''),
            'title' => $defaults['title'],
            'heading' => $defaults['heading'],
            'body' => $paragraphs,
        ]);
    }

    /**
     * The message as escaped paragraphs, one per non-empty line.
     *
     * What the built-in page shows under its heading, and what a template's
     * `{{page.message}}` is replaced with.
     *
     * @param string $message
     *   The message, placeholders already substituted. Plain text.
     * @param string $indent
     *   Put before every paragraph after the first. The built-in page indents
     *   them to its own markup; a template's placeholder sits wherever the
     *   operator put it, so it gets none.
     *
     * @return string
     *   `<p>` elements, one per line.
     */
    public static function paragraphs(string $message, string $indent = '    '): string
    {
        $paragraphs = [];

        foreach (preg_split('/\R/', $message) ?: [] as $line) {
            $line = trim($line);

            if ($line !== '') {
                $paragraphs[] = '<p>' . PageRenderer::escapeHtml($line) . '</p>';
            }
        }

        return implode("\n" . $indent, $paragraphs);
    }

    /**
     * Build the JSON body.
     *
     * @param string $kind
     *   `block` or `lockdown`.
     * @param int $status
     *   The response status.
     * @param string $reference
     *   The request ID.
     * @param int $retryAfter
     *   Seconds until a lockdown may lift; 0 omits it.
     *
     * @return string
     *   `{"error":"blocked","status":403,"request_id":"…"}`.
     */
    public static function json(string $kind, int $status, string $reference, int $retryAfter = 0): string
    {
        $body = [
            'error' => $kind === 'lockdown' ? 'lockdown' : 'blocked',
            'status' => $status,
            'request_id' => $reference,
        ];

        if ($retryAfter > 0) {
            $body['retry_after'] = $retryAfter;
        }

        return (string) json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
