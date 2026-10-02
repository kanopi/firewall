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
 */
final class BlockPage
{
    /**
     * Every key a block or lockdown page accepts.
     */
    public const KEYS = ['lang', 'title', 'heading', 'message', 'styles', 'stylesheet'];

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

        return PageSettings::problems(self::KEYS, $declared);
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

        $paragraphs = '';
        foreach (preg_split('/\R/', $text['message'] ?? '') ?: [] as $line) {
            $line = trim($line);

            if ($line !== '') {
                $paragraphs .= "\n    <p>" . PageRenderer::escapeHtml($line) . '</p>';
            }
        }

        return PageRenderer::document([
            'settings' => array_intersect_key($settings, array_flip(PageSettings::SPECIAL_KEYS)) + array_filter([
                'title' => $text['title'] ?? '',
                'heading' => $text['heading'] ?? '',
            ], static fn(string $value): bool => trim($value) !== ''),
            'title' => $defaults['title'],
            'heading' => $defaults['heading'],
            'body' => ltrim($paragraphs, "\n"),
        ]);
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
