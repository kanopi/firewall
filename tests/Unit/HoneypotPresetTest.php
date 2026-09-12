<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

/**
 * The shipped honeypot preset (#202).
 *
 * Two things have to hold, and neither is obvious from reading the YAML:
 *
 * 1. The request that springs the trap is **served**, so a scanner learns nothing about
 *    which URL is wired. A honeypot that refuses is a signpost.
 * 2. None of its paths is already blocked by another shipped preset. If one were, that rule
 *    would refuse the request and the stealth would be gone — silently, because the
 *    honeypot would still appear to be configured.
 */
class HoneypotPresetTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-honeypot-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    private static function presetPath(): string
    {
        return dirname(__DIR__, 2) . '/presets/honeypot.yml';
    }

    /**
     * @param array<int, string> $extraPresets
     */
    private function firewall(array $extraPresets = []): Firewall
    {
        $configs = array_map(
            static fn(string $name): string => dirname(__DIR__, 2) . '/presets/' . $name,
            $extraPresets
        );

        $configs[] = self::presetPath();
        $configs[] = [
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\\Firewall\\Storage\\FileStorage',
                'config' => ['storage_file' => $this->dir . '/blocked.data'],
            ],
        ];

        return Firewall::create($configs);
    }

    private function request(string $path, string $ip = '203.0.113.9'): Request
    {
        $request = Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'honeypot-test');

        return $request;
    }

    /**
     * Springing the trap is served; the next request is not.
     */
    public function testTheTrapServesThenBlocks(): void
    {
        $firewall = $this->firewall();

        $this->assertTrue(
            $firewall->evaluate($this->request('/.ssh/id_rsa')),
            'The request that sprang the trap must be served, or the scanner learns what it found.'
        );

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($this->request('/'));
    }

    /**
     * Everybody else is untouched.
     */
    public function testAnOrdinaryVisitorIsUnaffected(): void
    {
        $firewall = $this->firewall();

        $firewall->evaluate($this->request('/.ssh/id_rsa'));

        $this->assertTrue($firewall->evaluate($this->request('/', '198.51.100.7')));
    }

    /**
     * Every path in the preset really is a honeypot, not a block.
     *
     * The check that matters, and the one that would rot: another preset growing a rule
     * that covers one of these would refuse the request instead of recording it, and
     * nothing else would notice — the honeypot would still be configured, still appear to
     * work, and quietly tell every scanner exactly which path was wired.
     *
     * @param string $path
     *   A path the preset claims to trap.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('honeypotPaths')]
    public function testNoOtherShippedPresetBlocksThePath(string $path): void
    {
        // Every rule set that a site is likely to load alongside this one.
        $firewall = $this->firewall([
            'drupal.yml',
            'wordpress.yml',
            'malicious-urls.yml',
        ]);

        $this->assertTrue(
            $firewall->evaluate($this->request($path)),
            sprintf(
                '%s is refused by another shipped preset, so it is not a honeypot — the '
                . 'scanner is told exactly which path it found. Remove it from honeypot.yml '
                . 'or from the preset that blocks it.',
                $path
            )
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function honeypotPaths(): array
    {
        preg_match_all('/^\s+- "path:([^"]+)"/m', (string) file_get_contents(self::presetPath()), $matches);

        $cases = [];

        foreach ($matches[1] as $path) {
            $cases[$path] = [$path];
        }

        return $cases;
    }

    /**
     * The scrape found the paths, rather than passing by testing none of them.
     */
    public function testThePresetWasRead(): void
    {
        $this->assertGreaterThanOrEqual(15, count(self::honeypotPaths()));
    }
}
