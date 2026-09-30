<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\InterstitialRenderer;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A host's own line on the challenge page (#421).
 *
 * In `mode: block` the page is the library's, so a host had no way to tell a visitor
 * anything. The case that asked for it: a visitor solves, the pass cookie never comes
 * back (Pantheon strips cookies it does not recognise by name), and they are challenged
 * again, forever, with nothing on the page to say why.
 */
final class InterstitialNoticesTest extends AbstractTestCase
{
    private const SECRET = 'interstitial-notices-test-secret';

    private const CONTEXT = [
        'submit_url' => '/_firewall/challenge',
        'redirect_to' => '/gated',
        'ttl' => '60',
        'header_name' => '',
    ];

    // -----------------------------------------------------------------------
    // The page
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{\Closure(): ChallengeProviderInterface}>
     */
    public static function providers(): array
    {
        return [
            'math' => [static fn(): ChallengeProviderInterface => new MathChallengeProvider(new TokenManager(self::SECRET))],
            'altcha' => [static fn(): ChallengeProviderInterface => new AltchaChallengeProvider(new TokenManager(self::SECRET))],
            'turnstile' => [static fn(): ChallengeProviderInterface => new TurnstileChallengeProvider([
                'site_key' => '1x00000000000000000000AA',
                'secret_key' => '1x0000000000000000000000000000000AA',
            ])],
            'recaptcha v2' => [static fn(): ChallengeProviderInterface => new RecaptchaChallengeProvider([
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ])],
            'recaptcha v3' => [static fn(): ChallengeProviderInterface => new RecaptchaChallengeProvider([
                'version' => 'v3',
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ])],
        ];
    }

    private function render(ChallengeProviderInterface $provider, array $context): string
    {
        return $provider->renderInterstitial(Request::create('/gated', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.5']), $context);
    }

    /**
     * Every built-in page shows the notices, in order, above the form.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testEveryBuiltInPageShowsTheNotices(\Closure $provider): void
    {
        $html = $this->render($provider(), self::CONTEXT + ['notices' => ['First line.', 'Second line.']]);

        $this->assertStringContainsString('<div class="notices" role="status">', $html);
        $first = strpos($html, '<p class="notice">First line.</p>');
        $second = strpos($html, '<p class="notice">Second line.</p>');
        $form = strpos($html, '<form id="challenge-form"');

        $this->assertNotFalse($first);
        $this->assertNotFalse($second);
        $this->assertLessThan($second, $first, 'In the order given.');
        $this->assertLessThan($form, $second, 'Above the form.');
    }

    /**
     * No notices, no markup: the page is exactly what it was.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testNoNoticesAddNoMarkup(\Closure $provider): void
    {
        $this->assertStringNotContainsString('class="notices"', $this->render($provider(), self::CONTEXT));
        $this->assertStringNotContainsString('class="notices"', $this->render($provider(), self::CONTEXT + ['notices' => []]));
    }

    /**
     * Plain text, escaped: a notice can carry a visitor-facing string built from anything,
     * and it must never become markup.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testANoticeIsEscaped(\Closure $provider): void
    {
        $html = $this->render($provider(), self::CONTEXT + ['notices' => ['<script>alert(1)</script> & "quotes"']]);

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;', $html);
    }

    /**
     * What notices() accepts: non-empty text, trimmed. Anything else is dropped.
     */
    public function testOnlyNonEmptyTextIsANotice(): void
    {
        $this->assertSame(
            ['one', 'two'],
            InterstitialRenderer::notices(['notices' => ['  one ', '', '   ', 7, null, ['x'], 'two']])
        );
        $this->assertSame([], InterstitialRenderer::notices(['notices' => 'not a list']));
        $this->assertSame([], InterstitialRenderer::notices([]));
    }

    // -----------------------------------------------------------------------
    // Where they come from
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $challenge
     */
    private function firewall(array $challenge = [], ?EventDispatcherInterface $dispatcher = null, ?TestHandler $handler = null): Firewall
    {
        $inputs = [[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'challenge' => $challenge + ['provider' => 'math', 'secret' => self::SECRET, 'path' => '/_firewall/challenge'],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'enable' => true,
                'config' => ['path:/gated'],
            ]],
        ]];

        if ($handler instanceof TestHandler) {
            $inputs[] = ['logger' => [['class' => $handler]]];
        }

        return Firewall::create($inputs, [], $dispatcher);
    }

    private function challenge(Firewall $firewall): ChallengeRequiredException
    {
        try {
            $firewall->evaluate(Request::create('/gated', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
        } catch (ChallengeRequiredException $exception) {
            return $exception;
        }

        $this->fail('Expected a challenge.');
    }

    /**
     * A dispatcher that runs one listener for RequestChallenged.
     *
     * @param \Closure(RequestChallenged): void $listener
     */
    private function listening(\Closure $listener): EventDispatcherInterface
    {
        return new class($listener) implements EventDispatcherInterface {
            public function __construct(private readonly \Closure $listener)
            {
            }

            public function dispatch(object $event): object
            {
                if ($event instanceof RequestChallenged) {
                    ($this->listener)($event);
                }

                return $event;
            }
        };
    }

    public function testNoNoticeByDefault(): void
    {
        $this->assertSame([], $this->challenge($this->firewall())->getRenderContext()['notices']);
    }

    /**
     * `challenge.notice`, as text or as a list, reaches the page in `mode: exception` too:
     * the exception renders the same page a block-mode response writes.
     */
    public function testAConfiguredNoticeReachesThePage(): void
    {
        $exception = $this->challenge($this->firewall(['notice' => 'Trouble? Email help@example.com.']));

        $this->assertSame(['Trouble? Email help@example.com.'], $exception->getRenderContext()['notices']);
        $this->assertStringContainsString(
            '<p class="notice">Trouble? Email help@example.com.</p>',
            $exception->renderInterstitial(Request::create('/gated'))
        );

        $this->assertSame(
            ['One.', 'Two.'],
            $this->challenge($this->firewall(['notice' => ['One.', 'Two.']]))->getRenderContext()['notices']
        );
    }

    /**
     * A listener adds a line for this visitor -- the case the issue is about: a marker set
     * on the solve came back without the pass.
     */
    public function testAListenerCanAddANoticeForThisVisitor(): void
    {
        $dispatcher = $this->listening(static function (RequestChallenged $event): void {
            if ($event->getRequest()->cookies->has('marker') && !$event->getRequest()->cookies->has('pass')) {
                $event->addNotice('Your browser did not send back the verification cookie.');
            }
        });

        $firewall = $this->firewall(['notice' => 'Configured first.'], $dispatcher);

        try {
            $firewall->evaluate(Request::create('/gated', 'GET', [], ['marker' => '1'], [], ['REMOTE_ADDR' => '203.0.113.9']));
            $this->fail('Expected a challenge.');
        } catch (ChallengeRequiredException $exception) {
            $this->assertSame(
                ['Configured first.', 'Your browser did not send back the verification cookie.'],
                $exception->getRenderContext()['notices']
            );
        }

        $this->assertSame(['Configured first.'], $this->challenge($firewall)->getRenderContext()['notices'], 'Only for the visitor it applies to.');
    }

    /**
     * A refused submission is answered with a fresh challenge, and that page carries the
     * configured notice too. No RequestChallenged is dispatched for it, so listener notices
     * are not expected there.
     */
    public function testARefusedSubmissionCarriesTheConfiguredNotice(): void
    {
        $firewall = $this->firewall(['notice' => 'Configured.']);

        try {
            $firewall->evaluate(Request::create('/_firewall/challenge', 'POST', ['answer' => 'wrong'], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
            $this->fail('Expected the refused submission to be answered with a challenge.');
        } catch (ChallengeRequiredException $exception) {
            $this->assertSame(['Configured.'], $exception->getRenderContext()['notices']);
        }
    }

    /**
     * A notice that is not text is ignored with a warning, rather than taking the challenge
     * flow down.
     */
    public function testANoticeThatIsNotTextIsIgnored(): void
    {
        $handler = new TestHandler(Level::Debug);
        $exception = $this->challenge($this->firewall(['notice' => ['fine', 42]], null, $handler));

        $this->assertSame([], $exception->getRenderContext()['notices']);
        $this->assertTrue($handler->hasRecordThatContains('challenge.notice must be text', Level::Warning));
    }

    /**
     * The event's own API.
     */
    public function testTheEventCollectsNoticesInOrder(): void
    {
        $event = new RequestChallenged(Request::create('/'), $this->createMock(\Kanopi\Firewall\Plugins\PluginInterface::class), 'math');

        $this->assertSame([], $event->getNotices());

        $event->addNotice('a');
        $event->addNotice('b');

        $this->assertSame(['a', 'b'], $event->getNotices());
    }
}
