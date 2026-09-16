<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Metrics;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Event\RequestRecorded;
use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\Firewall\Metrics\DecisionMetricsListener;
use Kanopi\Firewall\Metrics\Metric;
use Kanopi\Firewall\Metrics\MetricsRecorderInterface;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Turning decisions into counters (#222).
 *
 * The interesting part of an exporter is not the socket, it is deciding what
 * the series are — so that two installations produce the same ones. These are
 * about that decision.
 */
class DecisionMetricsListenerTest extends AbstractTestCase
{
    private RecordingRecorder $recorder;

    protected function setUp(): void
    {
        parent::setUp();
        $this->recorder = new RecordingRecorder();
    }

    public function testEveryTerminalDecisionIsCountedByWhatItWas(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new RequestAllowed($this->request()));
        $listener(new RequestBlocked($this->request(), $this->rule('bad-ips'), 403));
        $listener(new RequestChallenged($this->request(), $this->rule('gate'), 'math'));
        $listener(new RequestRecorded($this->request(), $this->rule('honeypot'), true));
        $listener(new RequestRedirected($this->request(), $this->rule('legacy'), '/new', 302));
        $listener(new RequestMarked($this->request(), $this->rule('suspect'), 'maybe-bot', 'fw'));

        $this->assertSame([
            ['decision' => 'allowed', 'rule' => Metric::NO_RULE, 'enforced' => 'true'],
            ['decision' => 'blocked', 'rule' => 'bad-ips', 'enforced' => 'true'],
            ['decision' => 'challenged', 'rule' => 'gate', 'enforced' => 'true'],
            // `recorded` and `marked` always read false, and deliberately:
            // both let the request through — one writes to the block list, the
            // other annotates — so neither enforced anything, and their events
            // say so. Filtering `enforced="true"` gives what the firewall *did
            // to* traffic, and these are not among those things.
            ['decision' => 'recorded', 'rule' => 'honeypot', 'enforced' => 'false'],
            ['decision' => 'redirected', 'rule' => 'legacy', 'enforced' => 'true'],
            ['decision' => 'marked', 'rule' => 'suspect', 'enforced' => 'false'],
        ], $this->recorder->labelsFor(Metric::REQUESTS));
    }

    /**
     * `mode: log` decides without acting, and a dashboard that cannot tell the
     * two apart reports a dry run as a wall of blocks.
     */
    public function testAnObservedDecisionIsCountedSeparatelyFromAnEnforcedOne(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new RequestBlocked($this->request(), $this->rule('bad-ips'), 403, false));

        $this->assertSame(
            [['decision' => 'blocked', 'rule' => 'bad-ips', 'enforced' => 'false']],
            $this->recorder->labelsFor(Metric::REQUESTS)
        );
    }

    /**
     * The solve rate the issue asks for needs both halves, and they come from
     * different events: `ChallengeSolved` only ever fires for the visitors who
     * came back.
     */
    public function testAChallengeIsCountedWhenItIsIssuedAndAgainWhenItIsSolved(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new RequestChallenged($this->request(), $this->rule('gate'), 'math'));
        $listener(new RequestChallenged($this->request(), $this->rule('gate'), 'math'));
        $listener(new ChallengeSolved($this->request(), 'math', 900));

        $this->assertSame([
            ['provider' => 'math', 'outcome' => 'issued'],
            ['provider' => 'math', 'outcome' => 'issued'],
            ['provider' => 'math', 'outcome' => 'solved'],
        ], $this->recorder->labelsFor(Metric::CHALLENGES));
    }

    public function testAFailedChallengeIsCountedWithItsReason(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new ChallengeFailed($this->request(), 'recaptcha', 'invalid_solution'));

        $this->assertSame(
            [['provider' => 'recaptcha', 'outcome' => 'failed']],
            $this->recorder->labelsFor(Metric::CHALLENGES)
        );
        $this->assertSame(
            [['provider' => 'recaptcha', 'reason' => 'invalid_solution']],
            $this->recorder->labelsFor(Metric::CHALLENGE_FAILURES)
        );
    }

    /**
     * A request allowed by default had no rule. An empty label would be
     * indistinguishable from a rule whose name is missing, which is a
     * different problem.
     */
    public function testADecisionWithNoRuleSaysSoRatherThanLeavingTheLabelEmpty(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new RequestAllowed($this->request()));
        $listener(new RequestBlocked($this->request(), null, 403));

        foreach ($this->recorder->labelsFor(Metric::REQUESTS) as $labels) {
            $this->assertSame(Metric::NO_RULE, $labels['rule']);
        }
    }

    /**
     * The mistake that takes a Prometheus server down is unbounded labels. The
     * cap is not a substitute for choosing bounded ones — it is what makes the
     * mistake cost a vague dashboard rather than the scrape target.
     */
    public function testRuleLabelsAreCappedAndTheRestBucketed(): void
    {
        $listener = new DecisionMetricsListener($this->recorder, 3);

        foreach (range(1, 10) as $i) {
            $listener(new RequestBlocked($this->request(), $this->rule('rule-' . $i), 403));
        }

        $rules = array_column($this->recorder->labelsFor(Metric::REQUESTS), 'rule');

        $this->assertSame(['rule-1', 'rule-2', 'rule-3'], array_slice($rules, 0, 3));
        $this->assertSame(array_fill(0, 7, Metric::OVERFLOW), array_slice($rules, 3));
    }

    /**
     * A rule already admitted keeps its own name however often it fires, so the
     * cap bounds distinct values rather than throttling a busy rule.
     */
    public function testARuleAlreadyAdmittedIsNeverBucketed(): void
    {
        $listener = new DecisionMetricsListener($this->recorder, 1);

        $listener(new RequestBlocked($this->request(), $this->rule('first'), 403));
        $listener(new RequestBlocked($this->request(), $this->rule('second'), 403));
        $listener(new RequestBlocked($this->request(), $this->rule('first'), 403));

        $this->assertSame(
            ['first', Metric::OVERFLOW, 'first'],
            array_column($this->recorder->labelsFor(Metric::REQUESTS), 'rule')
        );
    }

    public function testTheCapCanBeTurnedOff(): void
    {
        $listener = new DecisionMetricsListener($this->recorder, 0);

        foreach (range(1, 5) as $i) {
            $listener(new RequestBlocked($this->request(), $this->rule('rule-' . $i), 403));
        }

        $this->assertSame(
            ['rule-1', 'rule-2', 'rule-3', 'rule-4', 'rule-5'],
            array_column($this->recorder->labelsFor(Metric::REQUESTS), 'rule')
        );
    }

    /**
     * Every shipped plugin falls back to its own class name, so this needs a
     * plugin that genuinely answers with nothing — which a custom one can.
     */
    public function testABlankRuleNameBecomesNameable(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);
        $nameless = $this->createMock(PluginInterface::class);
        $nameless->method('getName')->willReturn('   ');

        $listener(new RequestBlocked($this->request(), $nameless, 403));

        $this->assertSame(Metric::NO_RULE, $this->recorder->labelsFor(Metric::REQUESTS)[0]['rule']);
    }

    /**
     * A listener that silently ignores an event type it does not know is a
     * dashboard that quietly stops adding up.
     */
    public function testAnUnknownDecisionIsCountedRatherThanDropped(): void
    {
        $listener = new DecisionMetricsListener($this->recorder);

        $listener(new class ($this->request()) extends DecisionEvent {});

        $this->assertSame(
            [['decision' => Metric::OVERFLOW, 'rule' => Metric::NO_RULE, 'enforced' => 'true']],
            $this->recorder->labelsFor(Metric::REQUESTS)
        );
    }

    /**
     * PSR-14 dispatchers match on the concrete class, so registering for
     * `DecisionEvent` catches nothing. This list is how a host wires it up, and
     * a missing entry is a metric that silently never appears.
     */
    public function testEveryDecisionEventIsListedForWiring(): void
    {
        $shipped = array_map(
            static fn(string $file): string => 'Kanopi\\Firewall\\Event\\' . basename($file, '.php'),
            (array) glob(dirname(__DIR__, 3) . '/src/Event/*.php')
        );

        $concrete = array_values(array_filter(
            $shipped,
            static fn(string $class): bool => is_subclass_of($class, DecisionEvent::class)
        ));

        sort($concrete);
        $listed = DecisionMetricsListener::eventClasses();
        sort($listed);

        $this->assertSame($concrete, $listed);
    }

    private function rule(string $name): PluginInterface
    {
        return new IpAddress(['name' => $name], ['10.0.0.1']);
    }

    private function request(): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
    }
}

/**
 * A recorder that remembers what it was told, in order.
 */
final class RecordingRecorder implements MetricsRecorderInterface
{
    /**
     * @var array<int, array{metric: string, labels: array<string, string>, by: int}>
     */
    public array $counters = [];

    /**
     * @var array<int, array{metric: string, labels: array<string, string>, value: float}>
     */
    public array $gauges = [];

    public function increment(string $metric, array $labels = [], int $by = 1): void
    {
        $this->counters[] = ['metric' => $metric, 'labels' => $labels, 'by' => $by];
    }

    public function gauge(string $metric, array $labels = [], float $value = 0.0): void
    {
        $this->gauges[] = ['metric' => $metric, 'labels' => $labels, 'value' => $value];
    }

    /**
     * @return array<int, array<string, string>>
     */
    public function labelsFor(string $metric): array
    {
        return array_values(array_map(
            static fn(array $entry): array => $entry['labels'],
            array_filter($this->counters, static fn(array $entry): bool => $entry['metric'] === $metric)
        ));
    }
}
