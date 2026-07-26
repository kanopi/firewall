<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Symfony\Component\HttpFoundation\Request;

/**
 * Built-in arithmetic challenge.
 *
 * Renders "What is A + B?" where A and B are small random integers. The
 * expected answer is signed into a hidden form field (`challenge_state`)
 * with a short embedded expiry, so the server stays stateless between
 * the render and verify steps — there is no per-challenge record to
 * store or look up.
 *
 * Wire format of the signed state: `answer|exp.signature`
 *   answer    = the expected integer answer (server-side truth)
 *   exp       = unix timestamp after which the challenge is stale
 *   signature = HMAC over "answer|exp" via TokenManager::sign()
 *
 * The challenge_state lifetime is short (5 minutes) — long enough that a
 * legitimate visitor can read and type, short enough that a precomputed
 * answer harvested from a bot farm goes stale before it can be replayed
 * at scale.
 *
 * This is deliberately a low-friction proof-of-effort, not a CAPTCHA.
 * Operators who need stronger bot resistance can implement
 * ChallengeProviderInterface against Turnstile/hCaptcha/etc.
 */
final class MathChallengeProvider implements ChallengeProviderInterface
{
    /**
     * Form field that carries the signed `answer|exp.signature` payload
     * from render → verify.
     */
    public const STATE_FIELD = 'challenge_state';

    /**
     * Form field that carries the visitor's typed answer.
     */
    public const ANSWER_FIELD = 'challenge_answer';

    private const STATE_LIFETIME = 300;

    /**
     * Constructs a new MathChallengeProvider object.
     *
     * @param TokenManager $tokenManager
     *   Shared HMAC manager. Used to sign the `answer|exp` state embedded in
     *   the interstitial, which is what keeps this provider stateless — the
     *   expected answer never has to be stored server-side.
     */
    public function __construct(private readonly TokenManager $tokenManager)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'math';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        $a = random_int(1, 9);
        $b = random_int(1, 9);
        $expected = (string) ($a + $b);
        $exp = time() + self::STATE_LIFETIME;

        $stateData = $expected . '|' . $exp;
        $signedState = $stateData . '.' . $this->tokenManager->sign($stateData);

        $question = InterstitialRenderer::escapeHtml(sprintf('What is %d + %d?', $a, $b));
        $answerField = InterstitialRenderer::escapeHtml(self::ANSWER_FIELD);
        $stateField = InterstitialRenderer::escapeHtml(self::STATE_FIELD);
        $state = InterstitialRenderer::escapeHtml($signedState);

        return InterstitialRenderer::render([
            'intro' => 'Please answer the question below to continue.',
            'extra_styles' => '    label { display: block; font-weight: 600; margin-bottom: 0.5rem; }'
                . "\n" . '    input[type="text"] { width: 100%; padding: 0.6rem 0.75rem; font-size: 1rem; '
                . 'border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }'
                . "\n" . '    button { margin-top: 1rem; }',
            'extra_head' => '',
            'form_fields' => <<<FIELDS
      <label for="answer">{$question}</label>
      <input type="text" id="answer" name="{$answerField}" inputmode="numeric" autocomplete="off" autofocus required>
      <input type="hidden" name="{$stateField}" value="{$state}">
FIELDS,
            'submit_disabled' => false,
            'error_message' => 'Incorrect answer. Please try again.',
            'submit_guard' => '',
            'extra_script' => '',
            'submit_url' => $context['submit_url'] ?? '',
            'redirect_to' => $context['redirect_to'] ?? '/',
            'ttl' => $context['ttl'] ?? '3600',
            'header_name' => $context['header_name'] ?? '',
            'redirect_field' => self::REDIRECT_FIELD,
            'ttl_field' => self::TTL_FIELD,
        ]);
    }

    /**
     * {@inheritdoc}
     *
     * Rejects the solution unless all four checks pass: the signed state is
     * intact (HMAC), the state has not gone stale (`exp`), the state is
     * well-formed, and the typed answer matches the signed expected answer.
     * The answer comparison uses `hash_equals` so a near-miss reveals nothing
     * through timing.
     */
    public function verifySolution(Request $request): bool
    {
        $state = (string) $request->request->get(self::STATE_FIELD, '');
        $answer = trim((string) $request->request->get(self::ANSWER_FIELD, ''));

        if ($state === '' || $answer === '' || substr_count($state, '.') !== 1) {
            return false;
        }

        [$data, $signature] = explode('.', $state, 2);
        if (!$this->tokenManager->verifySignature($data, $signature)) {
            return false;
        }

        if (substr_count($data, '|') !== 1) {
            return false;
        }

        [$expected, $exp] = explode('|', $data, 2);

        if (!ctype_digit($exp) || (int) $exp <= time()) {
            return false;
        }

        return hash_equals($expected, $answer);
    }
}
