<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A request with no client address (#403).
 *
 * Not something PHP-FPM behind a web server produces. It happens where a host builds the
 * request itself -- a long-running runtime's bridge, a queue worker, a test -- and there
 * it is every request. `IpAddress` used to fatal on one, and every one shared the block-list
 * key `""`: one address-less client tripping a rule refused every other, on every path.
 */
final class NoClientAddressTest extends TestCase
{
    private string $file;

    protected function setUp(): void
    {
        parent::setUp();

        putenv('FIREWALL_BYPASS_CLI=1');
        $this->file = sys_get_temp_dir() . '/fw-no-address-' . uniqid() . '.json';
    }

    protected function tearDown(): void
    {
        foreach (glob($this->file . '*') ?: [] as $file) {
            @unlink($file);
        }

        @unlink(dirname($this->file) . '/storage_data_offenses.json');

        parent::tearDown();
    }

    private function addressless(string $path = '/', array $server = []): Request
    {
        $request = Request::create($path, 'GET', [], [], [], $server);
        $request->server->remove('REMOTE_ADDR');

        return $request;
    }

    /**
     * @param array<int, array<string, mixed>> $plugins
     */
    private function firewall(array $plugins, ?RecordingDispatcher $dispatcher = null): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception', 'behind_proxy' => false],
            'storage' => ['type' => FileStorage::class, 'config' => ['storage_file' => $this->file]],
            'logger' => [['class' => TestLogHandler::class]],
            'plugins' => $plugins,
        ]], [], $dispatcher);
    }

    private function isRefused(Firewall $firewall, Request $request): bool
    {
        try {
            $firewall->evaluate($request);

            return false;
        } catch (FirewallBlockedException) {
            return true;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function storedRecords(): array
    {
        return is_file($this->file) ? (array) json_decode((string) file_get_contents($this->file), true) : [];
    }

    /**
     * No address, no match -- for a block rule and an allow rule alike. It was a TypeError.
     */
    public function testAddressRulesDoNotMatchAndDoNotCrash(): void
    {
        $firewall = $this->firewall([
            ['plugin' => IpAddress::class, 'response' => 'allow', 'enable' => true, 'config' => ['203.0.113.9']],
            ['plugin' => IpAddress::class, 'response' => 'block', 'enable' => true, 'config' => ['0.0.0.0/0', '::/0']],
        ]);

        $this->assertTrue($firewall->evaluate($this->addressless()));
    }

    /**
     * Refused, and not banned: there is no client to attach a ban to.
     */
    public function testARuleStillRefusesButNothingIsWrittenToTheBlockList(): void
    {
        $firewall = $this->firewall([['plugin' => Url::class, 'response' => 'block', 'enable' => true, 'config' => ['path:/wp-login.php']]]);

        $this->assertTrue($this->isRefused($firewall, $this->addressless('/wp-login.php')));
        $this->assertSame([], $this->storedRecords());
    }

    /**
     * The whole bug: the next address-less visitor, on a different path, is not refused
     * for the first one's offence.
     */
    public function testOneAddresslessClientDoesNotGetTheNextOneRefused(): void
    {
        $this->isRefused(
            $this->firewall([['plugin' => Url::class, 'response' => 'block', 'enable' => true, 'config' => ['path:/wp-login.php']]]),
            $this->addressless('/wp-login.php')
        );

        $this->assertTrue($this->firewall([])->evaluate($this->addressless('/')));
    }

    /**
     * And a block already stored under the empty key -- written before this fix -- is not
     * read back against them either.
     */
    public function testABlockAlreadyUnderTheEmptyKeyIsNotApplied(): void
    {
        (new FileStorage(['storage_file' => $this->file]))->set('', ['reason' => 'written before #403'], 3600);

        $this->assertTrue($this->firewall([])->evaluate($this->addressless('/')));
    }

    /**
     * A `record` rule has nothing to record, and says so in its event.
     */
    public function testARecordRuleRecordsNothingAndSaysSo(): void
    {
        $dispatcher = new RecordingDispatcher();
        $firewall = $this->firewall([['plugin' => Url::class, 'response' => 'record', 'enable' => true, 'config' => ['path:/xmlrpc.php']]], $dispatcher);

        $this->assertTrue($firewall->evaluate($this->addressless('/xmlrpc.php')));
        $this->assertSame([], $this->storedRecords());

        $recorded = $dispatcher->ofType(\Kanopi\Firewall\Event\RequestRecorded::class);
        $this->assertCount(1, $recorded);
        $this->assertFalse($recorded[0]->wasStored());
    }

    /**
     * Counted by an address the request does not have, the requests are not pooled into
     * one bucket that any one of them could exhaust for the rest.
     */
    public function testARateLimitByAddressDoesNotPoolAddresslessRequests(): void
    {
        $firewall = $this->firewall([[
            'plugin' => RateLimit::class,
            'response' => 'block',
            'enable' => true,
            'metadata' => ['storage' => ['type' => 'Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage']],
            'config' => [['path' => '/', 'rate' => 1, 'sample' => 60]],
        ]]);

        for ($i = 0; $i < 3; $i++) {
            $this->assertFalse($this->isRefused($firewall, $this->addressless('/')), 'Request ' . ($i + 1));
        }
    }

    /**
     * A rate limit counting something else still counts.
     */
    public function testARateLimitByAnotherIdentityStillCounts(): void
    {
        $firewall = $this->firewall([[
            'plugin' => RateLimit::class,
            'response' => 'block',
            'enable' => true,
            'metadata' => ['storage' => ['type' => 'Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage']],
            'config' => [['path' => '/api', 'rate' => 1, 'sample' => 60, 'key' => ['header.x-api-key']]],
        ]]);

        $this->assertFalse($this->isRefused($firewall, $this->addressless('/api', ['HTTP_X_API_KEY' => 'k1'])));
        $this->assertTrue($this->isRefused($firewall, $this->addressless('/api', ['HTTP_X_API_KEY' => 'k1'])));
    }

    /**
     * Said once, since a runtime without the address lacks it on every request.
     */
    public function testItIsReportedOnce(): void
    {
        $firewall = $this->firewall([['plugin' => Url::class, 'response' => 'block', 'enable' => true, 'config' => ['path:/wp-login.php']]]);
        $handler = LoggingFactory::logger()->getHandlers()[0] ?? null;
        $this->assertInstanceOf(TestLogHandler::class, $handler);

        $this->isRefused($firewall, $this->addressless('/wp-login.php'));
        $this->isRefused($firewall, $this->addressless('/wp-login.php'));
        $firewall->evaluate($this->addressless('/'));

        $this->assertCount(1, array_filter(
            $handler->records,
            static fn ($record): bool => str_contains($record->message, 'has no client address - address rules cannot match')
        ));
    }

    /**
     * An ordinary request is untouched: blocked and written to the block list.
     */
    public function testARequestWithAnAddressIsStillBanned(): void
    {
        $firewall = $this->firewall([['plugin' => Url::class, 'response' => 'block', 'enable' => true, 'config' => ['path:/wp-login.php']]]);

        $this->assertTrue($this->isRefused($firewall, Request::create('/wp-login.php', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9'])));
        $this->assertArrayHasKey('203.0.113.9', $this->storedRecords());
    }
}
