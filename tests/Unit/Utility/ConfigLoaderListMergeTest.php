<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Utility\ConfigLoader;
use PHPUnit\Framework\TestCase;

/**
 * An included file replaces a list, the empty list included (#474).
 *
 * Lists are documented as "replaced as a whole by later files". `[]` was the exception: an
 * empty array failed the list check (`range(0, -1)` is `[0, -1]`, not `[]`), so it was merged
 * as an empty map and changed nothing. An override meant to empty `lockdown_allow` -- so that
 * nobody gets past a lockdown -- left every earlier address in place, without a word.
 */
class ConfigLoaderListMergeTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmp = sys_get_temp_dir() . '/cfg_lists_' . bin2hex(random_bytes(4));
        mkdir($this->tmp, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmp . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->tmp);
        parent::tearDown();
    }

    /**
     * Write each file, and load the first.
     *
     * @param array<string, string> $files
     *   YAML by file name; the first is loaded.
     *
     * @return array<string, mixed>
     */
    private function load(array $files): array
    {
        foreach ($files as $name => $yaml) {
            file_put_contents($this->tmp . '/' . $name, $yaml);
        }

        return ConfigLoader::load($this->tmp . '/' . array_key_first($files));
    }

    public function testALaterIncludesEmptyListClearsAnEarlierOnes(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [a.yml, b.yml]\n",
            'a.yml' => "global:\n  trusted_proxies: [10.0.0.0/8]\n  lockdown_allow: [203.0.113.5]\n",
            'b.yml' => "global:\n  trusted_proxies: []\n  lockdown_allow: [198.51.100.7]\n",
        ]);

        $this->assertSame([], $config['global']['trusted_proxies']);
        $this->assertSame(['198.51.100.7'], $config['global']['lockdown_allow']);
    }

    public function testAnIncludesEmptyListClearsTheIncludingFilesList(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [incident.yml]\nglobal:\n  lockdown_allow: [203.0.113.5, 198.51.100.0/24]\n",
            'incident.yml' => "global:\n  lockdown_allow: []\n",
        ]);

        $this->assertSame([], $config['global']['lockdown_allow']);
    }

    public function testAnEmptyListOverAMapLeavesTheMap(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [b.yml]\nglobal:\n  block_page:\n    title: Blocked\n",
            'b.yml' => "global:\n  block_page: []\n",
        ]);

        // `[]` is also YAML's empty map, and an empty map adds no keys -- as before.
        $this->assertSame(['title' => 'Blocked'], $config['global']['block_page']);
    }

    public function testAMapOverAnEmptyListIsTheMap(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [b.yml]\nglobal:\n  block_page: []\n",
            'b.yml' => "global:\n  block_page:\n    title: Blocked\n",
        ]);

        $this->assertSame(['title' => 'Blocked'], $config['global']['block_page']);
    }

    public function testAListOverAnEmptyListIsTheList(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [b.yml]\nglobal:\n  trusted_proxies: []\n",
            'b.yml' => "global:\n  trusted_proxies: [10.0.0.0/8]\n",
        ]);

        $this->assertSame(['10.0.0.0/8'], $config['global']['trusted_proxies']);
    }

    public function testAListInsideALegacyPluginIsReplacedWhole(): void
    {
        $plugin = 'Kanopi\\Firewall\\Plugins\\Url';
        $config = $this->load([
            'main.yml' => "configs: [a.yml, b.yml, c.yml]\n",
            'a.yml' => "block:\n  {$plugin}:\n    tags: [a, c]\n    config: ['path:/admin']\n",
            'b.yml' => "block:\n  {$plugin}:\n    tags: [b]\n    config: ['path:/login']\n",
            'c.yml' => "block:\n  {$plugin}:\n    notes: []\n",
        ]);

        // Merged position by position before: [b] over [a, c] was [b, c].
        $this->assertSame(['b'], $config['block'][$plugin]['tags']);
        // `config` is the one list a legacy plugin appends, and still does.
        $this->assertSame(['path:/admin', 'path:/login'], $config['block'][$plugin]['config']);
    }

    public function testAnEmptyListInsideALegacyPluginClearsIt(): void
    {
        $plugin = 'Kanopi\\Firewall\\Plugins\\Url';
        $config = $this->load([
            'main.yml' => "configs: [a.yml, b.yml]\n",
            'a.yml' => "block:\n  {$plugin}:\n    tags: [a, c]\n    config: ['path:/admin']\n",
            'b.yml' => "block:\n  {$plugin}:\n    tags: []\n    config: []\n",
        ]);

        $this->assertSame([], $config['block'][$plugin]['tags']);
        // Appending nothing leaves the rules as they were.
        $this->assertSame(['path:/admin'], $config['block'][$plugin]['config']);
    }

    public function testAMapInsideALegacyPluginStillMerges(): void
    {
        $plugin = 'Kanopi\\Firewall\\Plugins\\Url';
        $config = $this->load([
            'main.yml' => "configs: [a.yml, b.yml]\n",
            'a.yml' => "block:\n  {$plugin}:\n    metadata: { name: urls, mode: log }\n",
            'b.yml' => "block:\n  {$plugin}:\n    metadata: { mode: block }\n",
        ]);

        $this->assertSame(['name' => 'urls', 'mode' => 'block'], $config['block'][$plugin]['metadata']);
    }

    public function testRootPluginsStillAppend(): void
    {
        $config = $this->load([
            'main.yml' => "configs: [a.yml, b.yml]\nplugins: [{ plugin: A }]\n",
            'a.yml' => "plugins: [{ plugin: B }]\n",
            'b.yml' => "plugins: []\n",
        ]);

        $this->assertSame([['plugin' => 'A'], ['plugin' => 'B']], $config['plugins']);
    }
}
