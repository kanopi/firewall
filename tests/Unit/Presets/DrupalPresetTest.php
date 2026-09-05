<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Presets;

use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the shipped Drupal presets against real request paths.
 *
 * The negative cases matter more than the positive ones. A preset that fails
 * to block something leaves a gap; a preset that blocks a core asset or a
 * public user profile takes the site down, and does it on every install that
 * included the file.
 */
class DrupalPresetTest extends AbstractTestCase
{
    /**
     * Build the Url plugin from a shipped preset.
     */
    private function plugin(string $preset): Url
    {
        $config = Config::loadFile(dirname(__DIR__, 3) . '/presets/' . $preset);

        $this->assertSame([], Config::getLoadErrors(), 'The preset itself must load cleanly.');
        $this->assertArrayHasKey('plugins', $config);

        return new Url(
            $config['plugins'][0]['metadata'] ?? [],
            $config['plugins'][0]['config'] ?? []
        );
    }

    /**
     * A request for a path.
     */
    private function request(string $path): Request
    {
        // The query has to travel in the URI. Passing QUERY_STRING in the
        // server array leaves Request::getQueryString() null, which silently
        // makes every query-based assertion pass whatever the rules say.
        return Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
    }

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        Config::clearLoadErrors();
    }

    /**
     * Paths drupal.yml must block.
     *
     * @param string $path
     *   The request path.
     */
    #[DataProvider('drupalBlockedProvider')]
    public function testDrupalPresetBlocks(string $path): void
    {
        $this->assertTrue(
            $this->plugin('drupal.yml')->evaluate($this->request($path)),
            sprintf('Expected %s to be blocked by drupal.yml', $path)
        );
    }

    /**
     * What the safe preset exists to stop.
     */
    public static function drupalBlockedProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            // Version disclosure
            '/CHANGELOG.txt',
            '/core/CHANGELOG.txt',
            '/core/INSTALL.mysql.txt',
            '/core/MAINTAINERS.txt',
            '/README.txt',
            '/web.config',
            // Installer and recovery
            '/core/install.php',
            '/core/update.php',
            '/core/authorize.php',
            '/core/rebuild.php',
            '/install.php',
            '/update.php',
            '/core/scripts/password-hash.sh',
            // Settings served as text
            '/sites/default/settings.php',
            '/sites/default/settings.local.php',
            '/sites/example.com/settings.php',
            '/sites/default/services.yml',
            '/sites/default/default.settings.php',
            // PHP under the files directory
            '/sites/default/files/evil.php',
            '/sites/default/files/nested/deep/evil.php',
            '/sites/default/files/evil.phtml',
            '/sites/default/files/evil.phar',
            '/sites/default/files/evil.PHP',
            '/sites/example.com/files/evil.php5',
            '/sites/default/files/private/evil.php',
            // Private files
            '/sites/default/files/private/salary.pdf',
            '/sites/default/private/salary.pdf',
            // Configuration export
            '/config/sync/core.extension.yml',
            // Build artefacts
            '/composer.json',
            '/composer.lock',
            '/package.json',
            '/yarn.lock',
            '/vendor/autoload.php',
            '/.git/config',
            '/.env',
            '/.ddev/config.yaml',
            // Drupal 7 leftovers
            '/xmlrpc.php',
            '/cron.php',
            // Development routes
            '/devel/php',
            '/admin/config/development/devel',
            '/core/modules/system/tests/http.php',
            '/phpunit.xml.dist',
        ]);
    }

    /**
     * Paths drupal.yml must leave alone.
     *
     * These are the ones that break a site if the preset is too greedy: core
     * assets, uploaded media, public profiles, and the ACME challenge path an
     * SSL renewal depends on.
     *
     * @param string $path
     *   The request path.
     */
    #[DataProvider('drupalAllowedProvider')]
    public function testDrupalPresetLeavesLegitimateTrafficAlone(string $path): void
    {
        $this->assertFalse(
            $this->plugin('drupal.yml')->evaluate($this->request($path)),
            sprintf('Expected %s NOT to be blocked by drupal.yml', $path)
        );
    }

    /**
     * Traffic a working Drupal site depends on.
     */
    public static function drupalAllowedProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            '/',
            '/node/1',
            '/about-us',
            // Core and contrib assets are served straight out of /core and
            // /modules — blocking those prefixes would unstyle the site.
            '/core/misc/drupal.js',
            '/core/themes/olivero/css/base/base.css',
            '/core/assets/vendor/jquery/jquery.min.js',
            '/modules/contrib/webform/css/webform.css',
            '/themes/custom/site/dist/css/style.css',
            '/libraries/slick/slick.min.js',
            // Uploaded media is the whole point of the files directory.
            '/sites/default/files/2026-09/photo.jpg',
            '/sites/default/files/styles/large/public/photo.jpg.webp',
            '/sites/default/files/document.pdf',
            // A public user profile. Blocking /user wholesale would take these.
            '/user/42',
            '/user/42/edit',
            // Certificate renewal.
            '/.well-known/acme-challenge/token123',
            '/robots.txt',
            '/sitemap.xml',
            // The admin surface belongs to the other preset.
            '/admin/content',
            '/user/login',
        ]);
    }

    /**
     * Paths drupal-admin.yml must block.
     *
     * @param string $path
     *   The request path.
     */
    #[DataProvider('adminBlockedProvider')]
    public function testAdminPresetBlocks(string $path): void
    {
        $this->assertTrue(
            $this->plugin('drupal-admin.yml')->evaluate($this->request($path)),
            sprintf('Expected %s to be blocked by drupal-admin.yml', $path)
        );
    }

    /**
     * The administrative and authentication surface.
     */
    public static function adminBlockedProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            '/admin',
            '/admin/content',
            '/admin/reports/status',
            '/user/login',
            '/user/register',
            '/user/password',
            '/user/reset/1/123/abc',
            '/user',
            '/node/add',
            '/node/add/article',
            '/node/12/edit',
            '/node/12/delete',
            // Language-prefixed login, which a multilingual site serves too.
            '/es/user/login',
            '/pt-br/user/register',
        ]);
    }

    /**
     * Paths drupal-admin.yml must leave alone.
     *
     * @param string $path
     *   The request path.
     */
    #[DataProvider('adminAllowedProvider')]
    public function testAdminPresetLeavesPublicTrafficAlone(string $path): void
    {
        $this->assertFalse(
            $this->plugin('drupal-admin.yml')->evaluate($this->request($path)),
            sprintf('Expected %s NOT to be blocked by drupal-admin.yml', $path)
        );
    }

    /**
     * Public traffic that superficially resembles the admin surface.
     */
    public static function adminAllowedProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            '/',
            '/node/1',
            // A public profile, and a path that merely starts with the same
            // letters as /admin.
            '/user/42',
            '/administrative-services',
            '/news/admin-appointed-to-board',
            // `q` is the search parameter on a great many themes, so a
            // visitor searching for "admin" must not be blocked. This is why
            // the preset does not carry Drupal 7's query-routing rules.
            '/search?q=admin',
            '/search?q=administrator',
            '/search?q=user/login',
        ]);
    }

    /**
     * The two presets compose without one undoing the other.
     */
    public function testPresetsCompose(): void
    {
        $safe = Config::loadFile(dirname(__DIR__, 3) . '/presets/drupal.yml');
        $admin = Config::loadFile(dirname(__DIR__, 3) . '/presets/drupal-admin.yml');

        $combined = new Url([], array_merge(
            $safe['plugins'][0]['config'],
            $admin['plugins'][0]['config']
        ));

        $this->assertTrue($combined->evaluate($this->request('/core/install.php')));
        $this->assertTrue($combined->evaluate($this->request('/user/login')));
        $this->assertFalse($combined->evaluate($this->request('/sites/default/files/photo.jpg')));
    }
}
