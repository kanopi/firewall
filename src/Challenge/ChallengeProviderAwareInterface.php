<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

/**
 * Opt-in contract for plugins that pick their own challenge provider.
 *
 * Without this, every `response: challenge` plugin serves whatever
 * `challenge.provider` names, so choosing reCAPTCHA for one high-confidence
 * rule imposes a third-party round trip on every broad heuristic too. A
 * plugin implementing this interface names the provider it wants; anything
 * returning NULL falls back to `challenge.provider` exactly as before.
 *
 * `AbstractPluginBase` implements it by reading
 * `metadata.challenge_provider`, so every first-party plugin can be pointed
 * at a provider from YAML with no PHP:
 *
 * ```yaml
 * plugins:
 *   - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
 *     response: challenge
 *     metadata:
 *       challenge_provider: recaptcha
 * ```
 *
 * Plugins that do not extend the base class can implement this directly and
 * return a hardcoded name. One difference is worth knowing: names coming
 * from `metadata` are resolved and validated when the firewall is built, so
 * a typo fails at startup, while a name returned only from PHP cannot be
 * seen until the plugin matches and is therefore validated then.
 *
 * The name is a `challenge.provider` string — a built-in short name
 * (`math`, `altcha`, `turnstile`, `recaptcha`) or a FQCN implementing
 * `ChallengeProviderInterface` — and doubles as the scope of the pass token
 * the challenge mints. See `ChallengeProviderRegistry`.
 */
interface ChallengeProviderAwareInterface
{
    /**
     * Name of the challenge provider this plugin's matches should serve.
     *
     * @return string|null
     *   A `challenge.provider` name, or NULL to use the globally configured
     *   provider.
     */
    public function getChallengeProviderName(): ?string;
}
