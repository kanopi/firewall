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
use Kanopi\Firewall\Page\PageSettings;

/**
 * `challenge.page`: the wording, language and styling of the interstitial (#451).
 *
 * In `mode: block` the challenge page is the library's, and until this its title, heading,
 * button, language and CSS were fixed. A site wanting the page in its own language and
 * colours had to write a provider -- wrapping a built-in one, since those are final -- even
 * though the page itself was fine.
 *
 * Every key is optional; an unset key keeps today's page. The checks on each value are
 * PageSettings', shared with the block and lockdown pages.
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
        return PageSettings::fromConfig('challenge.page', self::KEYS, $declared);
    }

    /**
     * What is wrong with a `challenge.page` value.
     *
     * @param mixed $declared
     *   The configured value.
     *
     * @return array<int, string>
     *   One line per problem; empty when the value can be used.
     */
    public static function problems(mixed $declared): array
    {
        return PageSettings::problems(self::KEYS, $declared);
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
        return PageSettings::accepted(self::KEYS, $context['page'] ?? []);
    }
}
