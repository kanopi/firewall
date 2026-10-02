<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Page;

/**
 * The document every page the firewall writes is built on (#452).
 *
 * The challenge interstitial and the block and lockdown pages share it: one card, one
 * heading, one stylesheet. So `styles` and `stylesheet` written for one page style the
 * others the same way, and a site's colours are set once.
 *
 * The caller supplies what is its own -- the rules only its page needs, and what goes in
 * the card under the heading -- and the settings from `PageSettings`, which this writes:
 * `lang`, `title` and `heading` escaped, `styles` after every built-in rule, `stylesheet`
 * as a `<link>` after the style block.
 */
final class PageRenderer
{
    /**
     * The rules every page has: the page, the card, the heading, a paragraph.
     */
    public const BASE_STYLES = <<<'CSS'
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f5f6f8; color: #1a1a1a; margin: 0; display: flex; min-height: 100vh; align-items: center; justify-content: center; }
    .card { background: #fff; padding: 2rem 2.5rem; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); max-width: 28rem; width: 90%; }
    h1 { font-size: 1.25rem; margin: 0 0 0.75rem; }
    p { margin: 0 0 1.25rem; color: #555; }
CSS;

    /**
     * Escape a value for interpolation into HTML text or an attribute.
     */
    public static function escapeHtml(string|int $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Build the document.
     *
     * `page_styles`, `extra_styles`, `extra_head`, `body` and `after_main` are written
     * verbatim -- the caller owns escaping anything it interpolates into them. The
     * settings are filtered through PageSettings::accepted() again here, so values
     * nothing validated cannot reach the page.
     *
     * @param array{
     *   settings: array<string, string>,
     *   title: string,
     *   heading: string,
     *   page_styles?: string,
     *   extra_styles?: string,
     *   extra_head?: string,
     *   body: string,
     *   after_main?: string
     * } $parts
     *   `title` and `heading` are the defaults the settings may replace, as plain text.
     *
     * @return string
     *   A complete HTML document.
     */
    public static function document(array $parts): string
    {
        $settings = PageSettings::accepted(['lang', 'title', 'heading', 'styles', 'stylesheet'], $parts['settings']);

        $lang = self::escapeHtml($settings['lang'] ?? 'en');
        $title = self::escapeHtml($settings['title'] ?? $parts['title']);
        $heading = self::escapeHtml($settings['heading'] ?? $parts['heading']);

        $styles = self::BASE_STYLES;

        foreach ([$parts['page_styles'] ?? '', $parts['extra_styles'] ?? ''] as $rules) {
            if ($rules !== '') {
                $styles .= "\n" . $rules;
            }
        }

        // Last, so the operator's rules win over the built-in ones and the
        // page's at equal specificity. Not escaped: CSS is not HTML, and
        // PageSettings has already refused the one thing that could close
        // the block.
        if (isset($settings['styles'])) {
            $styles .= "\n" . $settings['styles'];
        }

        $stylesheet = isset($settings['stylesheet'])
            ? "\n  <link rel=\"stylesheet\" href=\"" . self::escapeHtml($settings['stylesheet']) . '">'
            : '';

        $extraHead = $parts['extra_head'] ?? '';
        $extraHead = $extraHead === '' ? '' : "\n" . $extraHead;

        $body = $parts['body'];
        $afterMain = $parts['after_main'] ?? '';
        $afterMain = $afterMain === '' ? '' : "\n" . $afterMain;

        return <<<HTML
<!DOCTYPE html>
<html lang="{$lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>{$title}</title>
  <style>
{$styles}
  </style>{$stylesheet}{$extraHead}
</head>
<body>
  <main class="card">
    <h1>{$heading}</h1>
{$body}
  </main>{$afterMain}
</body>
</html>
HTML;
    }
}
