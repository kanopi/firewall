<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Reputation\ReputationProviderFactory;
use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationSubject;
use Kanopi\Firewall\Reputation\ReputationVerdict;
use Kanopi\Firewall\Reputation\SubjectAwareReputationProviderInterface;
use Kanopi\Firewall\Utility\RuleDiagnostics;
use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Traits\RequestValueTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Match when a reputation service scores the client badly enough (#204).
 *
 * ```yaml
 * - plugin: "Kanopi\\Firewall\\Plugins\\Reputation"
 *   response: block
 *   metadata:
 *     name: internal-reputation
 *   config:
 *     provider: http
 *     url: "https://reputation.example.com/v1/score?ip={ip}"
 *     score_path: data.score
 *     threshold: 75
 * ```
 *
 * Everything that is true of every reputation lookup lives here, and everything
 * that is true of one service lives in its
 * `Reputation\ReputationProviderInterface`. `AbuseIpdb` is this plugin with the
 * provider fixed, which is why its configuration did not change when this was
 * extracted out from under it.
 *
 * ## It fails open
 *
 * A lookup that times out, is refused, runs into a spent quota or returns
 * something that is not a verdict reports no match, logs at warning level, and
 * lets evaluation continue. Reputation is corroborating evidence, not the last
 * line of defence -- a third party's outage must not become an outage here.
 *
 * `on_error: last_known_good` is the one alternative, and it does not weaken
 * that: it reuses a verdict this firewall already fetched for that same address
 * and would otherwise have thrown away for being old. Nothing is ever refused
 * on an answer the provider did not give.
 *
 * ## It is cached, because the quota usually is not generous
 *
 * Verdicts are cached per address and per provider for `cache_ttl`, so cost is
 * one call per unique visitor per period; repeat visitors and crawlers are
 * free. Failures are cached too, for a much shorter `error_cache_ttl` --
 * without that, an outage would make every request pay the full timeout, which
 * is a site slowdown dressed up as failing open.
 *
 * The cache is per provider *slug*, so two services scoring the same address
 * never read each other's answers. Their scales mean different things.
 *
 * ## Trusted beats the score
 *
 * A provider that vouches for an address -- AbuseIPDB's whitelist, a service
 * that knows its customer's monitoring -- never matches, whatever the score.
 */
class Reputation extends AbstractPluginBase
{
    use EvaluateTrait;
    use RequestValueTrait;

    /**
     * Constructs a new reputation rule.
     *
     * @param array<int|string, mixed> $metadata
     *   Metadata for the rule.
     * @param array<int|string, mixed> $config
     *   The rule's own settings, including the provider's.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);

        // Eagerly, so that a provider that refuses to build is a rule that did
        // not start -- reported by getFailedRules(), firewall-doctor and
        // firewall-check -- rather than an exception out of evaluate() on every
        // request.
        $this->provider();
    }

    /**
     * Score at or above which the plugin matches.
     *
     * AbuseIPDB's own guidance treats 75 as the point where a report set is
     * strong enough to act on, and providers scoring 0-100 are the common case.
     */
    protected const DEFAULT_THRESHOLD = 75.0;

    /**
     * What to do when the provider cannot answer.
     *
     * Reusing two of the three values a rule source's `on_error` takes (#161),
     * with the same meanings. `abort` is deliberately not among them: a source
     * aborts during bootstrap, where a loud failure is a deploy that stops, but
     * this runs in the request path, where it would be a 500 for a visitor
     * because somebody else's API is slow.
     */
    protected const ERROR_POLICIES = ['fail_open', 'last_known_good'];

    /**
     * The provider, built once per rule instance.
     */
    protected ?ReputationProviderInterface $provider = null;

    /**
     * The subject of the request being evaluated.
     *
     * Held for the duration of one evaluation so the cache path and the log
     * context agree with what was actually looked up.
     */
    protected ?ReputationSubject $subject = null;

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'Reputation';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Check the client IP address against a reputation service and match when its score reaches the configured threshold';
    }

    /**
     * The provider this rule asks, when its `config.provider` names none.
     *
     * @return string
     *   A built-in short name.
     */
    protected function defaultProvider(): string
    {
        return 'http';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        if (!$this->applies($request)) {
            return false;
        }

        $provider = $this->provider();
        $problem = $provider->getConfigurationProblem();

        if ($problem !== null) {
            // Not configured -- the rule is inert. Matching here would block
            // every request for somebody who added the rule before
            // provisioning a credential.
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - %s', $provider->getName(), $problem),
                $this->getContext($request)
            );

            return false;
        }

        $subject = $this->resolveSubject($request);

        if (!$subject instanceof ReputationSubject) {
            // Nothing to ask about. For an address that is a request with no
            // client IP; for `subject: post.email` it is every request that
            // does not carry one, which is most of them -- a signup form is
            // one path out of thousands.
            //
            // Sending an empty subject would be worse than skipping: a scoring
            // service asked about "" answers something, and that answer is
            // about nothing.
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - the request carries no %s', $provider->getName(), $this->subjectKind()),
                $this->getContext($request)
            );

            return false;
        }

        if (!$this->providerKnowsAbout($provider, $subject)) {
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - it could have no answer for this subject', $provider->getName()),
                $this->getContext($request, ['subject' => $subject->describe()])
            );

            return false;
        }

        $verdict = $this->lookup($subject, $request);

        if (!$verdict instanceof ReputationVerdict) {
            // Already logged at warning level by the lookup. Fail open.
            return false;
        }

        if ($verdict->trusted) {
            $this->getLogger()->debug(
                sprintf('%s reports the subject as trusted - not matching', $provider->getName()),
                $this->getContext($request, ['subject' => $subject->describe()] + $verdict->attributes)
            );

            return false;
        }

        $threshold = $this->threshold();

        // TRUE means "this rule matched", not "allow the request" -- the
        // PluginManager applies the entry's `response:` when we return TRUE.
        // See PluginInterface::evaluate().
        if ($verdict->score >= $threshold) {
            $this->getLogger()->info(
                sprintf('%s matched', $provider->getName()),
                $this->getContext($request, [
                    'subject' => $subject->describe(),
                    'score' => $verdict->score,
                    'threshold' => $threshold,
                ] + $verdict->attributes)
            );

            return true;
        }

        $this->getLogger()->debug(
            sprintf('%s score is under the threshold', $provider->getName()),
            $this->getContext($request, [
                'subject' => $subject->describe(),
                'score' => $verdict->score,
                'threshold' => $threshold,
            ] + $verdict->attributes)
        );

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return (int) ($this->config['block_status'] ?? 403);
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return (int) ($this->config['block_duration'] ?? 3600);
    }

    /**
     * Whether this request is one worth asking about.
     *
     * A reputation lookup is the most expensive thing in an evaluation -- a
     * network round trip, a slice of somebody's quota, and latency in front of
     * a visitor -- and for most sites only a handful of paths are worth
     * spending it on. `when:` is the gate:
     *
     * ```yaml
     * config:
     *   when:
     *     - "path@starts_with:/login"
     *     - "path:/checkout"
     * ```
     *
     * The conditions are the ones documented for every other rule, so `method`,
     * `header.*`, `post.*`, `query` and the rest all work here without this
     * inventing a `paths:` or a `methods:` key that would have meant learning a
     * second vocabulary for the same idea. Like a plugin's `config:` list, the
     * entries are first-match-wins: any one of them matching is enough.
     *
     * No `when:` means every request, which is what every rule written before
     * this did.
     *
     * @param Request $request
     *   The request under evaluation.
     *
     * @return bool
     *   TRUE when the lookup should happen.
     */
    protected function applies(Request $request): bool
    {
        $when = $this->config['when'] ?? null;

        if (!is_array($when) || $when === []) {
            return true;
        }

        if ($this->evaluateRequest($request, $when)) {
            return true;
        }

        $this->getLogger()->debug('Reputation lookup skipped - the request is outside `when`', $this->getContext($request, [
            'plugin' => $this->getName(),
        ]));

        return false;
    }

    /**
     * Resolve a `when:` variable against the request.
     *
     * `EvaluateTrait` leaves this as a hook returning NULL so that a class can
     * use rule evaluation without exposing a request vocabulary. Every
     * condition here is about the request, so it delegates to the shared
     * resolver -- the same one `Url` rules and rate-limit keys use, so `path`,
     * `method`, `header.*`, `post.*`, `query` and `cookie.*` mean here exactly
     * what they mean there.
     *
     * @param Request $request
     *   The request under evaluation.
     * @param string $variable
     *   The variable named in a condition.
     *
     * @return mixed
     *   Its value, or NULL when this rule cannot resolve it.
     */
    protected function getValue(Request $request, string $variable): mixed
    {
        return $this->resolveRequestValue($request, $variable);
    }

    /**
     * {@inheritdoc}
     *
     * The vocabulary `when:` accepts. Used by `reportUnusableRules()` below
     * rather than by the base implementation, which inspects `config:` as a
     * rule list and returns early here because this rule's `config:` is a map.
     */
    protected function knownRuleVariables(): array
    {
        return ['method', 'host', 'path', 'query', 'scheme', 'port', 'post', 'header', 'cookie'];
    }

    /**
     * {@inheritdoc}
     *
     * Points the rule checker at `when:`, which is the only rule list this
     * plugin has.
     *
     * A misspelled condition matters more here than in most places. A rule
     * whose condition cannot match simply never fires; a **gate** whose
     * condition cannot match turns the rule off for every request, while the
     * configuration still reads as though reputation is being checked on
     * `/login` (#165).
     */
    protected function reportUnusableRules(): void
    {
        parent::reportUnusableRules();

        $when = $this->config['when'] ?? null;

        if (!is_array($when) || $when === []) {
            return;
        }

        $result = RuleDiagnostics::inspect($when, $this->knownRuleVariables());
        $this->config['when'] = $result['rules'];

        foreach ($result['issues'] as $issue) {
            $this->getLogger()->warning('Reputation `when` condition will not match anything - the rule is gated off every request', [
                'plugin' => $this->getName(),
                'rule' => $issue['rule'],
                'reason' => $issue['reason'],
            ]);
        }
    }

    /**
     * What this rule looks up, out of the request.
     *
     * @param Request $request
     *   The request under evaluation.
     *
     * @return ReputationSubject|null
     *   The subject, or NULL when the request carries nothing to ask about.
     */
    protected function resolveSubject(Request $request): ?ReputationSubject
    {
        $kind = $this->subjectKind();

        $value = $kind === ReputationSubject::CLIENT_IP
            ? $request->getClientIp()
            : $this->resolveRequestValue($request, $kind);

        // A list -- repeated form fields, a multi-value header -- is not one
        // subject, and picking an element would be this rule deciding which of
        // somebody's values to send to a third party.
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            return null;
        }

        $value = trim((string) $value);

        if ($value === '') {
            return null;
        }

        $algorithm = $this->subjectHash();

        if ($algorithm === null) {
            return new ReputationSubject($value, $kind);
        }

        // Some services take a digest rather than the value, which is the only
        // way to ask about an email address without sending one. Case-folded
        // first, because a digest of "Alice@Example.com" and one of
        // "alice@example.com" are different digests of the same mailbox and
        // every service that takes one normalises before hashing.
        return new ReputationSubject(hash($algorithm, strtolower($value)), $kind, true);
    }

    /**
     * Whether the provider could have an answer for this subject.
     *
     * @param ReputationProviderInterface $reputationProvider
     *   The provider.
     * @param ReputationSubject $reputationSubject
     *   The subject.
     *
     * @return bool
     *   TRUE when the lookup is worth making.
     */
    protected function providerKnowsAbout(ReputationProviderInterface $reputationProvider, ReputationSubject $reputationSubject): bool
    {
        // The address-only contract takes a string, and for an address that is
        // exactly what it wants. A subject-aware provider is asked through the
        // interface that can express the rest.
        return $reputationSubject->isAddress()
            ? $reputationProvider->knowsAbout($reputationSubject->value)
            : true;
    }

    /**
     * What this rule is configured to look up.
     *
     * @return string
     *   A field name in the vocabulary rules already use, defaulting to the
     *   client address -- which is what every reputation rule written before
     *   2.28.0 asks about.
     */
    protected function subjectKind(): string
    {
        $configured = $this->config['subject'] ?? null;

        return is_string($configured) && trim($configured) !== ''
            ? strtolower(trim($configured))
            : ReputationSubject::CLIENT_IP;
    }

    /**
     * The digest a subject is sent as, if it is sent as one.
     *
     * @return string|null
     *   A hash algorithm, or NULL to send the value itself.
     *
     * @throws ConfigurationException
     *   When the algorithm is not one this system has. Checked at startup
     *   rather than per request: a rule that cannot hash cannot ask, and a
     *   rule that quietly stopped hashing would be sending plaintext email
     *   addresses to a third party.
     */
    protected function subjectHash(): ?string
    {
        $configured = $this->config['subject_hash'] ?? null;

        if (!is_string($configured) || trim($configured) === '') {
            return null;
        }

        $algorithm = strtolower(trim($configured));

        if (!in_array($algorithm, hash_algos(), true)) {
            throw new ConfigurationException(sprintf(
                'The reputation `subject_hash` is not a hash algorithm this system has: %s. Common '
                . 'choices are sha256 and sha1.',
                $algorithm
            ));
        }

        return $algorithm;
    }

    /**
     * The provider this rule asks.
     *
     * Built in the constructor, not on first use. `LazyObjectRegistry` catches
     * a rule whose construction throws and reports it through
     * `Firewall::getFailedRules()`, `firewall-doctor` and `firewall-check` --
     * and that only happens for work done *in* the constructor. Building it
     * lazily meant a `provider:` naming no class threw
     * `ConfigurationException` out of `evaluate()` instead, which for a host is
     * an exception on every request rather than one broken rule in a report
     * (a defect in 2.27.0, whose own docblock claimed the opposite).
     *
     * Nothing here does I/O -- a provider's constructor validates its
     * configuration and stops -- so the cost is the same either way.
     *
     * @return ReputationProviderInterface
     *   The provider.
     */
    protected function provider(): ReputationProviderInterface
    {
        return $this->provider ??= $this->buildProvider();
    }

    /**
     * Construct the configured provider.
     *
     * @return ReputationProviderInterface
     *   The provider.
     *
     * @throws \Kanopi\Firewall\Exception\ConfigurationException
     *   When the provider does not resolve, or cannot answer about the subject
     *   this rule is configured to ask about.
     */
    protected function buildProvider(): ReputationProviderInterface
    {
        $configured = $this->config['provider'] ?? null;
        $name = is_string($configured) && trim($configured) !== ''
            ? trim($configured)
            : $this->defaultProvider();

        $reputationProvider = ReputationProviderFactory::create($name, $this->config);

        // Reads the key for its side effect: an unusable algorithm throws, and
        // throwing here is what makes it a failed rule rather than a surprise
        // on the first signup.
        $this->subjectHash();

        $kind = $this->subjectKind();

        if ($kind === ReputationSubject::CLIENT_IP) {
            return $reputationProvider;
        }

        // A rule asking about an email address, pointed at a provider that
        // scores addresses. Refusing to start is the only honest answer:
        // sending a username to a service that scores IPs gets an answer, and
        // the answer is about something else.
        $aware = $reputationProvider instanceof SubjectAwareReputationProviderInterface;

        if (!$aware || !$reputationProvider->handles(new ReputationSubject('', $kind))) {
            throw new ConfigurationException(sprintf(
                'The reputation rule is configured with `subject: %s`, but %s %s. Point it at a provider '
                . 'that scores that, or remove `subject:`.',
                $kind,
                $reputationProvider->getName(),
                $aware ? 'does not score that kind of subject' : 'only scores client addresses'
            ));
        }

        return $reputationProvider;
    }

    /**
     * Resolve an address to a verdict, cache first.
     *
     * @param ReputationSubject $reputationSubject
     *   What to look up.
     * @param Request $request
     *   The request under evaluation, for log context.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL when no answer could be obtained -- in which case
     *   a warning has already been logged and the caller must fail open.
     */
    protected function lookup(ReputationSubject $reputationSubject, Request $request): ?ReputationVerdict
    {
        $provider = $this->provider();
        $error = $this->readError($reputationSubject);

        if ($error !== null) {
            // A recent failure, still inside error_cache_ttl. Reported at
            // debug rather than warning -- the warning was written when the
            // lookup actually failed, and repeating it once per request for
            // the whole window would bury everything else.
            $this->getLogger()->debug(
                sprintf('%s lookup skipped - a recent lookup failed and is still cached', $provider->getName()),
                $this->getContext($request, ['subject' => $reputationSubject->describe(), 'error' => $error])
            );

            return $this->onError($reputationSubject, $request);
        }

        $cached = $this->readCache($reputationSubject);

        if ($cached instanceof ReputationVerdict) {
            return $cached;
        }

        try {
            $verdict = $provider instanceof SubjectAwareReputationProviderInterface
                ? $provider->checkSubject($reputationSubject)
                : $provider->check($reputationSubject->value);
        } catch (ReputationUnavailableException $reputationUnavailableException) {
            $this->getLogger()->warning(
                sprintf('%s lookup failed - allowing the request through', $provider->getName()),
                $this->getContext($request, [
                    'subject' => $reputationSubject->describe(),
                    'error' => $reputationUnavailableException->getMessage(),
                    'http_status' => $reputationUnavailableException->httpStatus,
                    'hint' => 'Reputation is advisory here: the request proceeds to the next rule. '
                        . 'Check the credential and the service.',
                ])
            );

            $this->writeError($reputationSubject, $reputationUnavailableException);

            return $this->onError($reputationSubject, $request);
        }

        $this->writeCache($reputationSubject, ['verdict' => $verdict->toArray()]);

        return $verdict;
    }

    /**
     * What a failed lookup falls back to.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject that could not be looked up.
     * @param Request $request
     *   The request under evaluation, for log context.
     *
     * @return ReputationVerdict|null
     *   An expired verdict under `on_error: last_known_good`, or NULL to fail
     *   open.
     */
    protected function onError(ReputationSubject $reputationSubject, Request $request): ?ReputationVerdict
    {
        if ($this->errorPolicy() !== 'last_known_good') {
            return null;
        }

        $stale = $this->readCache($reputationSubject, true);

        if (!$stale instanceof ReputationVerdict) {
            return null;
        }

        // Warning, not debug: the answer being acted on is older than the
        // operator asked for, and that is something they may want to know
        // before reading the block that came out of it.
        $this->getLogger()->warning(
            sprintf('%s is unreachable - using the last known verdict for this address', $this->provider()->getName()),
            $this->getContext($request, [
                'subject' => $reputationSubject->describe(),
                'score' => $stale->score,
                'age_seconds' => time() - (int) @filemtime((string) $this->cachePath($reputationSubject)),
            ])
        );

        return $stale;
    }

    /**
     * Read the cached verdict for an address, if there is a usable one.
     *
     * Verdicts and failures are kept in **separate files**, which is not an
     * implementation detail: a failure written over the verdict it replaced
     * would destroy the only thing `on_error: last_known_good` has to fall back
     * on, at exactly the moment it is needed. Separate files also mean each
     * keeps its own mtime, so the two lifetimes are read from the filesystem
     * rather than from a timestamp this had to remember to write.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject to read.
     * @param bool $ignoreTtl
     *   Return a verdict however old it is, for `on_error: last_known_good`.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL on a miss, an expired entry, or an unreadable one.
     */
    protected function readCache(ReputationSubject $reputationSubject, bool $ignoreTtl = false): ?ReputationVerdict
    {
        $path = $this->cachePath($reputationSubject);
        $entry = $this->readEntry($path);

        if ($entry === null) {
            return null;
        }

        if (!$ignoreTtl && (time() - (int) @filemtime((string) $path)) >= $this->cacheTtl()) {
            return null;
        }

        return ReputationVerdict::fromArray($entry['verdict'] ?? null) ?? $this->legacyVerdict($entry);
    }

    /**
     * Read the cached failure for an address, if one is still recent.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject to read.
     *
     * @return string|null
     *   What went wrong, or NULL when there is no failure inside
     *   `error_cache_ttl`.
     */
    protected function readError(ReputationSubject $reputationSubject): ?string
    {
        $path = $this->errorPath($reputationSubject);
        $entry = $this->readEntry($path);

        if ($entry === null || !isset($entry['error'])) {
            return null;
        }

        if ((time() - (int) @filemtime((string) $path)) >= $this->errorCacheTtl()) {
            return null;
        }

        return (string) $entry['error'];
    }

    /**
     * Decode a cache file, if it is there and says anything.
     *
     * @param string|null $path
     *   The file, or NULL when there is no usable cache directory.
     *
     * @return array<array-key, mixed>|null
     *   The decoded entry, or NULL on a miss or anything unreadable. Forgiving
     *   on purpose: a truncated or hand-edited file counts as a miss, which
     *   costs one lookup, where trusting it costs a wrong verdict.
     */
    protected function readEntry(?string $path): ?array
    {
        if ($path === null || !is_file($path)) {
            return null;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            return null;
        }

        $entry = json_decode($contents, true);

        return is_array($entry) ? $entry : null;
    }

    /**
     * A verdict out of a cache entry an older release wrote.
     *
     * Nothing by default: a shape this version does not recognise is a miss,
     * which costs one lookup. A provider whose entries predate the shared cache
     * overrides this so an upgrade does not spend a day's quota re-asking about
     * addresses it already had answers for.
     *
     * @param array<array-key, mixed> $entry
     *   The decoded cache entry.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL when the entry is not one this rule can read.
     */
    protected function legacyVerdict(array $entry): ?ReputationVerdict
    {
        return null;
    }

    /**
     * Remember that a lookup failed, without forgetting what it said last time.
     *
     * Its own file, next to the verdict rather than over it. Without that, the
     * first failure would delete the last known good answer, and the policy
     * that exists to use one would have nothing to use.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject that could not be looked up.
     * @param ReputationUnavailableException $reputationUnavailableException
     *   What went wrong.
     */
    protected function writeError(ReputationSubject $reputationSubject, ReputationUnavailableException $reputationUnavailableException): void
    {
        $this->write($this->errorPath($reputationSubject), [
            'error' => $reputationUnavailableException->getMessage(),
            'http_status' => $reputationUnavailableException->httpStatus,
        ]);
    }

    /**
     * Store a verdict for an address.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject the entry describes.
     * @param array<string, mixed> $entry
     *   `['verdict' => [...]]`.
     */
    protected function writeCache(ReputationSubject $reputationSubject, array $entry): void
    {
        $this->write($this->cachePath($reputationSubject), $entry);
    }

    /**
     * Write one cache file.
     *
     * A cache that cannot be written is not fatal -- it costs quota, not
     * correctness -- so this reports the problem and returns.
     *
     * @param string|null $path
     *   The file, or NULL when there is no usable cache directory.
     * @param array<string, mixed> $entry
     *   What to store.
     */
    protected function write(?string $path, array $entry): void
    {
        if ($path === null) {
            return;
        }

        $encoded = json_encode($entry);

        if ($encoded === false) {
            return;
        }

        if (@file_put_contents($path, $encoded, LOCK_EX) === false) {
            $this->getLogger()->warning(
                sprintf('%s could not write its cache - every request will spend quota', $this->provider()->getName()),
                [
                    'plugin' => $this->getName(),
                    'path' => $path,
                    'hint' => 'Point cache_dir at a writable directory.',
                ]
            );
        }
    }

    /**
     * Absolute path of the cache entry for an address.
     *
     * The address is hashed rather than used directly: it keeps client IPs out
     * of directory listings, and guarantees a filesystem-safe name for IPv6.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject to derive a path for.
     *
     * @return string|null
     *   The path, or NULL when the cache directory could not be created.
     */
    protected function cachePath(ReputationSubject $reputationSubject): ?string
    {
        $directory = rtrim($this->cacheDir(), '/');

        if (!is_dir($directory) && !@mkdir($directory, 0775, true) && !is_dir($directory)) {
            $this->getLogger()->warning(
                sprintf('%s cache directory could not be created - every request will spend quota', $this->provider()->getName()),
                [
                    'plugin' => $this->getName(),
                    'path' => $directory,
                ]
            );

            return null;
        }

        // An address keeps the 2.27.0 filename exactly. Anything else gets its
        // kind in the name, so a score for `post.email` and one for an address
        // are never the same entry -- different questions, and on some services
        // different scales.
        $kind = $reputationSubject->isAddress() ? '' : $reputationSubject->slug() . '-';

        return $directory . '/' . $this->provider()->getSlug() . '-' . $kind . sha1($reputationSubject->value) . '.json';
    }

    /**
     * Absolute path of the cached failure for an address.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject to derive a path for.
     *
     * @return string|null
     *   The path, or NULL when the cache directory could not be created.
     */
    protected function errorPath(ReputationSubject $reputationSubject): ?string
    {
        $path = $this->cachePath($reputationSubject);

        return $path === null ? null : substr($path, 0, -5) . '.error.json';
    }

    /**
     * Directory holding cached verdicts.
     *
     * Follows `Config`'s convention so a deployment that already sets
     * KANOPI_FIREWALL_CACHE_DIR does not have to say it twice, with an
     * explicit `cache_dir` winning when present. The per-provider default
     * keeps an upgrade from orphaning the verdicts an earlier version cached.
     *
     * @return string
     *   The directory.
     */
    protected function cacheDir(): string
    {
        $configured = $this->config['cache_dir'] ?? null;

        if (is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        if (defined('KANOPI_FIREWALL_CACHE_DIR')) {
            return (string) constant('KANOPI_FIREWALL_CACHE_DIR');
        }

        return sys_get_temp_dir() . '/kanopi-firewall-' . $this->provider()->getSlug();
    }

    /**
     * Score at or above which the rule matches.
     *
     * @return float
     *   The threshold, on the provider's own scale.
     */
    protected function threshold(): float
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::float(
            $this->config,
            'threshold',
            self::DEFAULT_THRESHOLD,
            $this->provider()->getName()
        );
    }

    /**
     * Lifetime of a cached verdict, in seconds.
     *
     * @return int
     *   Seconds.
     */
    protected function cacheTtl(): int
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::int(
            $this->config,
            'cache_ttl',
            $this->provider()->getDefaultCacheTtl(),
            $this->provider()->getName()
        );
    }

    /**
     * Lifetime of a cached failure, in seconds.
     *
     * @return int
     *   Seconds.
     */
    protected function errorCacheTtl(): int
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::int(
            $this->config,
            'error_cache_ttl',
            $this->provider()->getDefaultErrorCacheTtl(),
            $this->provider()->getName()
        );
    }

    /**
     * What to do when the provider cannot answer.
     *
     * @return string
     *   One of self::ERROR_POLICIES.
     */
    protected function errorPolicy(): string
    {
        $configured = $this->config['on_error'] ?? null;
        $policy = is_string($configured) ? strtolower(trim($configured)) : '';

        if ($policy === '') {
            return 'fail_open';
        }

        if (!in_array($policy, self::ERROR_POLICIES, true)) {
            $this->getLogger()->warning('Reputation on_error is not a policy this rule has - failing open', [
                'plugin' => $this->getName(),
                'given' => $configured,
                'expected' => self::ERROR_POLICIES,
            ]);

            return 'fail_open';
        }

        return $policy;
    }
}
