<?php

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\ConfigLoader;
use Kanopi\Firewall\Utility\TokenSubstitute;

final class ConfigLoaderTest extends AbstractTestCase
{
    private string $tmp;
    private string $sub;
    private string $more;
    private string $secretsFile;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->tmp = sys_get_temp_dir() . '/cfg_' . bin2hex(random_bytes(4));
        $this->sub = $this->tmp . '/config';
        $this->more = $this->tmp . '/more';
        mkdir($this->tmp);
        mkdir($this->sub);
        mkdir($this->more);

        // File content used by file: processor
        $this->secretsFile = $this->tmp . '/secret.txt';
        file_put_contents($this->secretsFile, "s3cr3t\n");

        // Env vars used in tests
        putenv('APP_ENV=dev');
        putenv('APP_PORT=8080');
        putenv('APP_PI=3.14');
        putenv('APP_BOOL_TRUE=on');
        putenv('APP_BOOL_FALSE=no');
        putenv('APP_JSON={"a":1,"b":[2,3]}');
        putenv('APP_BASE64=' . base64_encode('hello world'));
        putenv('APP_FILE=' . $this->secretsFile);
        putenv('APP_TRIM=  TrimMe  ');
        putenv('APP_CSV= alpha, beta , gamma ');
        putenv('APP_QS=foo=1&bar=2&bar=3');
        putenv('APP_URL=https://example.com:8443/path?x=1#frag');
        putenv('EXTRA_CFG=' . $this->sub . '/inc_from_env.yml');

        // Include chain for depth/circular tests created in individual tests.
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        TokenSubstitute::resetUnsafeProcessors();
        // Best-effort cleanup
        $this->rrmdir($this->tmp);
        parent::tearDown();
    }

    private function rrmdir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : @unlink($file->getPathname());
        }
        @rmdir($dir);
    }

    private function write(string $path, string $content): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        file_put_contents($path, $content);
    }

    public function testLoadParsesEnvTypedInterpolationIncludesAndRelativePaths(): void
    {
        // Test uses %env(file:APP_FILE)% which is disabled by default
        // (see security fix #55). Opt in explicitly for the duration.
        TokenSubstitute::enableUnsafeProcessors(['file']);

        // Sub-includes (glob + {config_dir} + explicit)
        $this->write($this->more . '/a.one.yml', "from_glob: one\n");
        $this->write($this->more . '/b.two.yml', "from_glob: two\n");
        $this->write($this->sub . '/inc_from_env.yml', "from_env_include: yes\n");

        // Base config with everything
        $base = $this->tmp . '/config.yml';
        $this->write($base, <<<YML
app:
  env_full: "%env(string:APP_ENV)%"
  env_inline: "port=%env(int:APP_PORT)% env=%env(APP_ENV)%"
  port: '%env(int:APP_PORT)%'
  pi: '%env(float:APP_PI)%'
  truthy: '%env(bool:APP_BOOL_TRUE)%'
  falsy: '%env(bool:APP_BOOL_FALSE)%'
  json: '%env(json:APP_JSON)%'
  b64: '%env(base64:APP_BASE64)%'
  file: '%env(file:APP_FILE)%'
  trimmed: '%env(trim:APP_TRIM)%'
  lower: '%env(lower:APP_ENV)%'
  upper: '%env(upper:APP_ENV)%'
  csv: '%env(csv:APP_CSV)%'
  qs: '%env(query_string:APP_QS)%'
  url: '%env(url:APP_URL)%'

# relative path targets (these files exist relative to config.yml dir)
logger:
  main:
    handler: stream
    args: ["logs/app.log"]

block:
  \\Kanopi\\Firewall\\Plugins\\GeoLocation:
    metadata:
      reader:
        db: "geo/GeoLiteCity.mmdb"

allow:
  \\Kanopi\\Firewall\\Plugins\\Asn:
    metadata:
      reader:
        db: "geo/ASN.mmdb"

allow2:
  \\Kanopi\\Firewall\\Plugins\\RateLimit:
    metadata:
      storage:
        config:
          file: "limits/rate.yml"

configs:
  - "{config_dir}/more/*.yml"
  - "%env(string:EXTRA_CFG)%"
  - "config/extra.yml"
YML
        );

        // Files referenced by relative path patterns
        $this->write($this->tmp . '/logs/app.log', '');
        $this->write($this->tmp . '/geo/GeoLiteCity.mmdb', '');
        $this->write($this->tmp . '/geo/ASN.mmdb', '');
        $this->write($this->tmp . '/limits/rate.yml', "limits:\n  x: 1\n");
        $this->write($this->sub . '/extra.yml', "from_explicit: ok\n");

        // Load with patterns including alternation and wildcard
        $cfg = ConfigLoader::load($base, [
            'logger.*.args.0',
            'block|allow.\\Kanopi\\Firewall\\Plugins\\GeoLocation.metadata.reader.db',
            '{block,allow}.\\Kanopi\\Firewall\\Plugins\\Asn.metadata.reader.db',
            '(block|allow|allow2).\\Kanopi\\Firewall\\Plugins\\RateLimit.metadata.storage.config.file',
        ]);

        // %env full-scalar typing
        self::assertSame('dev', $cfg['app']['env_full']);
        self::assertSame(8080, $cfg['app']['port']);
        self::assertSame(3.14, $cfg['app']['pi']);
        self::assertTrue($cfg['app']['truthy']);
        self::assertFalse($cfg['app']['falsy']);
        self::assertSame(['a' => 1, 'b' => [2, 3]], $cfg['app']['json']);
        self::assertSame("hello world", $cfg['app']['b64']);
        self::assertSame("s3cr3t\n", $cfg['app']['file']);
        self::assertSame('TrimMe', $cfg['app']['trimmed']);
        self::assertSame('dev', $cfg['app']['lower']);
        self::assertSame('DEV', $cfg['app']['upper']);
        self::assertSame(['alpha', 'beta', 'gamma'], $cfg['app']['csv']);
        self::assertSame(['foo' => '1', 'bar' => ['2', '3']], $cfg['app']['qs']);
        self::assertIsArray($cfg['app']['url']);
        self::assertSame('example.com', $cfg['app']['url']['host']);

        // Interpolation inside strings → remains string
        self::assertSame('port=8080 env=dev', $cfg['app']['env_inline']);

        // Relative path rewrites became absolute
        self::assertFileExists($cfg['logger']['main']['args'][0]);
        $tmpBase = realpath($this->tmp) ?: $this->tmp;
        self::assertStringStartsWith($tmpBase, realpath($cfg['logger']['main']['args'][0]) ?: $cfg['logger']['main']['args'][0]);

        self::assertFileExists($cfg['block']['\\Kanopi\\Firewall\\Plugins\\GeoLocation']['metadata']['reader']['db']);
        self::assertFileExists($cfg['allow']['\\Kanopi\\Firewall\\Plugins\\Asn']['metadata']['reader']['db']);
        self::assertFileExists($cfg['allow2']['\\Kanopi\\Firewall\\Plugins\\RateLimit']['metadata']['storage']['config']['file']);

        // Includes: glob + env + explicit were merged
        self::assertSame('two', $cfg['from_glob']);
        self::assertSame('yes', $cfg['from_env_include']);
        self::assertSame('ok', $cfg['from_explicit']);
    }

    public function testParseUsesBaseDirOfProvidedOrigin(): void
    {
        $origin = $this->tmp . '/root.yml';
        $this->write($origin, "x: 1\n");
        $yaml = <<<YML
configs:
  - "rel/child.yml"
YML;
        $this->write($this->tmp . '/rel/child.yml', "y: 2\n");

        $cfg = ConfigLoader::parse($yaml, $origin, []);
        self::assertSame(2, $cfg['y']);
    }

    public function testCircularIncludeThrows(): void
    {
        $a = $this->tmp . '/a.yml';
        $b = $this->tmp . '/b.yml';
        $this->write($a, "configs: [\"b.yml\"]\n");
        $this->write($b, "configs: [\"a.yml\"]\n");

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Circular include detected');
        ConfigLoader::load($a);
    }

    public function testMaxDepthExceededThrows(): void
    {
        // Build linear chain longer than MAX_DEPTH (20)
        $prev = null;
        for ($i = 0; $i < 22; $i++) {
            $f = $this->tmp . "/d{$i}.yml";
            if ($prev === null) {
                $this->write($f, "value: 0\nconfigs: [\"d1.yml\"]\n");
            } elseif ($i < 21) {
                $next = "d" . ($i + 1) . ".yml";
                $this->write($f, "value: $i\nconfigs: [\"$next\"]\n");
            } else {
                $this->write($f, "value: $i\n");
            }
            $prev = $f;
        }

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Include depth exceeded');
        ConfigLoader::load($this->tmp . '/d0.yml');
    }

    public function testNormalizeIncludeSupportsEnvAndConfigDirAndRelative(): void
    {
        // env include path
        $this->write($this->sub . '/env.yml', "env_included: ok\n");
        putenv('EXTRA_ONE=' . $this->sub . '/env.yml');

        // {config_dir} + relative
        $this->write($this->tmp . '/rel/thing.yml', "from_rel: ok\n");

        $main = $this->tmp . '/main.yml';
        $this->write($main, <<<YML
configs:
  - "%env(string:EXTRA_ONE)%"
  - "{config_dir}/rel/thing.yml"
YML
        );

        $cfg = ConfigLoader::load($main);
        self::assertSame('ok', $cfg['env_included']);
        self::assertSame('ok', $cfg['from_rel']);
    }

    public function testRelativePathResolverSkipsUrlsAndAbsolutes(): void
    {
        $main = $this->tmp . '/main.yml';
        $this->write($main, <<<YML
logger:
  main:
    args: ["http://example.com/logs/app.log", "/abs/path.log", "rel/app2.log"]
YML
        );
        $this->write($this->tmp . '/rel/app2.log', '');

        $cfg = ConfigLoader::load($main, ['logger.*.args.0', 'logger.*.args.1', 'logger.*.args.2']);

        self::assertSame('http://example.com/logs/app.log', $cfg['logger']['main']['args'][0]);
        self::assertSame('/abs/path.log', $cfg['logger']['main']['args'][1]);
        $tmpBase = realpath($this->tmp) ?: $this->tmp;
        self::assertStringStartsWith($tmpBase, $cfg['logger']['main']['args'][2]); // rewritten
    }

    public function testMergeConfigsReplacesLists(): void
    {
        $a = $this->tmp . '/a.yml';
        $b = $this->tmp . '/b.yml';

        $this->write($a, <<<YML
arr: [1,2,3]
obj:
  x: 1
  y: 2
YML
        );

        $this->write($b, <<<YML
arr: [4,5]      # should REPLACE not append
obj:
  y: 20         # should override only y
  z: 3
YML
        );

        // Build a main file that includes both, so ConfigLoader's merge (replace-lists) is used
        $main = $this->tmp . '/main.yml';
        $this->write($main, "configs: [\"a.yml\", \"b.yml\"]\n");

        $cfg = ConfigLoader::load($main);

        // list replaced entirely
        self::assertSame([4, 5], $cfg['arr']);
        // object deep-merged
        self::assertSame(['x' => 1, 'y' => 20, 'z' => 3], $cfg['obj']);
    }

    public function testRootScalarYamlReturnsEmptyArray(): void
    {
        $f = $this->tmp . '/root_scalar.yml';
        $this->write($f, "--- justastring\n");
        $cfg = ConfigLoader::load($f);
        self::assertSame([], $cfg);
    }

    public function testExpandMatchesEarlyExitOnMissingSegment(): void
    {
        $f = $this->tmp . '/early_exit.yml';
        $this->write($f, "a:\n  b:\n    c: 1\n");
        $cfg = ConfigLoader::load($f, ['a.nope.c']); // pattern won't match; ensures branch is exercised
        self::assertSame(1, $cfg['a']['b']['c']);
    }

    public function testRelativePathResolverSkipsWindowsAndUncAbsolutes(): void
    {
        $main = $this->tmp . '/main_win.yml';
        $this->write($main, <<<YML
logger:
  main:
    args: ['C:\\\\abs\\\\path.log', '\\\\server\\share\\file.log', 'rel/app3.log']
YML
        );
        $this->write($this->tmp . '/rel/app3.log', '');
        $cfg = ConfigLoader::load($main, ['logger.*.args.0', 'logger.*.args.1', 'logger.*.args.2']);
        self::assertSame('C:\\\\abs\\\\path.log', $cfg['logger']['main']['args'][0]);  // untouched
        self::assertSame('\\\\server\\share\\file.log', $cfg['logger']['main']['args'][1]); // untouched        $tmpBase = realpath($this->tmp) ?: $this->tmp;
        $tmpBase = realpath($this->tmp) ?: $this->tmp;
        $rhs = realpath($cfg['logger']['main']['args'][2]) ?: $cfg['logger']['main']['args'][2];
        self::assertStringStartsWith($tmpBase, $rhs); // rewritten
    }

    public function testParseWithFileSchemeOriginCoversRealOrGivenBranch(): void
    {
        // Create a child config and a main YAML as strings, but pass origin with file:// scheme.
        $child = $this->tmp . '/rel/child2.yml';
        $this->write($child, "k: v\n");
        $yaml = "configs: ['rel/child2.yml']\n";
        $origin = $this->tmp . '/root2.yml';
        $this->write($origin, "root: ok\n");
        $cfg = ConfigLoader::parse($yaml, $origin, []);
        self::assertSame('v', $cfg['k']);
    }

    public function testInvalidIncludeEntryTypeThrows(): void
    {
        $f = $this->tmp . '/invalid_inc.yml';
        $this->write($f, "configs:\n  - { bad: type }\n");
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Invalid include entry');
        ConfigLoader::load($f);
    }

    /**
     * Tests ConfigLoader::setByPath() sets a simple value.
     */
    public function testSetByPathSimple(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        $data = [];
        $path = ['foo'];
        $value = 'bar';
        $result = $method->invokeArgs(null, [$data, $path, $value]);

        $this->assertEquals(['foo' => 'bar'], $result);
    }

    /**
     * Tests ConfigLoader::setByPath() creates nested structure.
     */
    public function testSetByPathNested(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        $data = [];
        $path = ['a', 'b', 'c'];
        $value = 'test';
        $result = $method->invokeArgs(null, [$data, $path, $value]);

        $this->assertEquals(['a' => ['b' => ['c' => 'test']]], $result);
    }

    /**
     * Tests ConfigLoader::setByPath() overwrites scalar with nested structure.
     */
    public function testSetByPathOverwritesScalar(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        // When the path needs to traverse through a scalar value,
        // it should convert that scalar to an array
        $data = ['a' => 'x'];
        $path = ['a', 'b'];
        $value = 'new-value';
        $result = $method->invokeArgs(null, [$data, $path, $value]);

        // The scalar 'x' at $data['a'] should be replaced with an array
        $this->assertEquals(['a' => ['b' => 'new-value']], $result);
        $this->assertIsArray($result['a']);
        $this->assertEquals('new-value', $result['a']['b']);
    }

    /**
     * Tests ConfigLoader::setByPath() updates existing nested value.
     */
    public function testSetByPathUpdatesExisting(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        $data = ['a' => ['b' => 'old', 'c' => 'keep']];
        $path = ['a', 'b'];
        $value = 'new';
        $result = $method->invokeArgs(null, [$data, $path, $value]);

        $this->assertEquals('new', $result['a']['b']);
        $this->assertEquals('keep', $result['a']['c']);
    }

    /**
     * Tests ConfigLoader::setByPath() with numeric keys (array indexes).
     */
    public function testSetByPathWithNumericKeys(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        $data = ['items' => ['first', 'second']];
        $path = ['items', 0];
        $value = 'updated';
        $result = $method->invokeArgs(null, [$data, $path, $value]);

        $this->assertEquals('updated', $result['items'][0]);
        $this->assertEquals('second', $result['items'][1]);
    }

    /**
     * Tests ConfigLoader::setByPath() for path resolution use case.
     * This simulates the actual use case in resolveRelativePathsForKeys().
     */
    public function testSetByPathForPathResolution(): void
    {
        $reflection = new \ReflectionClass(ConfigLoader::class);
        $method = $reflection->getMethod('setByPath');
        $method->setAccessible(true);

        // Simulate a config structure with relative paths
        $data = [
            'storage' => [
                'config' => [
                    'file' => 'data/storage.db'
                ]
            ],
            'block' => [
                'plugin1' => [
                    'metadata' => [
                        'storage' => [
                            'config' => [
                                'file' => 'plugins/db.sqlite'
                            ]
                        ]
                    ]
                ]
            ]
        ];

        // Replace the first relative path
        $path1 = ['storage', 'config', 'file'];
        $value1 = '/absolute/path/to/data/storage.db';
        $data = $method->invokeArgs(null, [$data, $path1, $value1]);

        $this->assertEquals('/absolute/path/to/data/storage.db', $data['storage']['config']['file']);

        // Replace the second relative path
        $path2 = ['block', 'plugin1', 'metadata', 'storage', 'config', 'file'];
        $value2 = '/absolute/path/to/plugins/db.sqlite';
        $data = $method->invokeArgs(null, [$data, $path2, $value2]);

        $this->assertEquals('/absolute/path/to/plugins/db.sqlite', $data['block']['plugin1']['metadata']['storage']['config']['file']);
        // First replacement should still be there
        $this->assertEquals('/absolute/path/to/data/storage.db', $data['storage']['config']['file']);
    }

    public function testPluginConfigMergePreservesPriorityAndAppendsConfig(): void
    {
        $file1 = $this->tmp . '/plugin1.yml';
        $file2 = $this->tmp . '/plugin2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -100
    enable: true
    config:
      - path:/admin
      - path:/login
YAML
        );

        file_put_contents($file2, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -50
    enable: true
    config:
      - path:/custom
      - path:/api/dangerous
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugin1.yml
  - plugin2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Priority should be preserved from first config
        $this->assertEquals(-100, $result['block']['Kanopi\Firewall\Plugins\Url']['priority']);

        // Config arrays should be merged (appended)
        $this->assertCount(4, $result['block']['Kanopi\Firewall\Plugins\Url']['config']);
        $this->assertEquals('path:/admin', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][0]);
        $this->assertEquals('path:/login', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][1]);
        $this->assertEquals('path:/custom', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][2]);
        $this->assertEquals('path:/api/dangerous', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][3]);
    }

    public function testPluginConfigWithEnableFalseIsSkipped(): void
    {
        $file1 = $this->tmp . '/plugin1.yml';
        $file2 = $this->tmp . '/plugin2_disabled.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -100
    enable: true
    config:
      - path:/admin
      - path:/login
YAML
        );

        file_put_contents($file2, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -50
    enable: false
    config:
      - path:/custom
      - path:/api/dangerous
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugin1.yml
  - plugin2_disabled.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Should only have config from file1 since file2 has enable:false
        $this->assertEquals(-100, $result['block']['Kanopi\Firewall\Plugins\Url']['priority']);
        $this->assertTrue($result['block']['Kanopi\Firewall\Plugins\Url']['enable']);
        $this->assertCount(2, $result['block']['Kanopi\Firewall\Plugins\Url']['config']);
        $this->assertEquals('path:/admin', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][0]);
        $this->assertEquals('path:/login', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][1]);
    }

    public function testPluginConfigMergeWorksForBypassSection(): void
    {
        $file1 = $this->tmp . '/bypass1.yml';
        $file2 = $this->tmp . '/bypass2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -200
    enable: true
    config:
      - 192.168.1.0/24
YAML
        );

        file_put_contents($file2, <<<YAML
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -150
    enable: true
    config:
      - 10.0.0.0/8
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - bypass1.yml
  - bypass2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Priority should be preserved from first config
        $this->assertEquals(-200, $result['bypass']['Kanopi\Firewall\Plugins\IpAddress']['priority']);

        // Config arrays should be merged
        $this->assertCount(2, $result['bypass']['Kanopi\Firewall\Plugins\IpAddress']['config']);
        $this->assertEquals('192.168.1.0/24', $result['bypass']['Kanopi\Firewall\Plugins\IpAddress']['config'][0]);
        $this->assertEquals('10.0.0.0/8', $result['bypass']['Kanopi\Firewall\Plugins\IpAddress']['config'][1]);
    }

    public function testPluginConfigBothDisabledRemovesPlugin(): void
    {
        $file1 = $this->tmp . '/plugin1.yml';
        $file2 = $this->tmp . '/plugin2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -100
    enable: false
    config:
      - path:/admin
YAML
        );

        file_put_contents($file2, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -50
    enable: false
    config:
      - path:/custom
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugin1.yml
  - plugin2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Plugin should not exist in config when both are disabled
        $this->assertArrayNotHasKey('Kanopi\Firewall\Plugins\Url', $result['block'] ?? []);
    }

    public function testPluginConfigDisabledBaseEnabledOverrideReplacesBase(): void
    {
        $file1 = $this->tmp . '/plugin1.yml';
        $file2 = $this->tmp . '/plugin2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -100
    enable: false
    config:
      - path:/admin
      - path:/login
YAML
        );

        file_put_contents($file2, <<<YAML
block:
  Kanopi\Firewall\Plugins\Url:
    priority: -50
    enable: true
    config:
      - path:/custom
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugin1.yml
  - plugin2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Base should be completely replaced by override
        $this->assertEquals(-50, $result['block']['Kanopi\Firewall\Plugins\Url']['priority']);
        $this->assertTrue($result['block']['Kanopi\Firewall\Plugins\Url']['enable']);
        $this->assertCount(1, $result['block']['Kanopi\Firewall\Plugins\Url']['config']);
        $this->assertEquals('path:/custom', $result['block']['Kanopi\Firewall\Plugins\Url']['config'][0]);
    }

    public function testPluginsArrayMergingAppendsEntries(): void
    {
        $file1 = $this->tmp . '/plugins1.yml';
        $file2 = $this->tmp . '/plugins2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\IpAddress
    response: allow
    weight: -200
    enable: true
    config:
      - 127.0.0.1
YAML
        );

        file_put_contents($file2, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\Url
    response: block
    weight: -100
    enable: true
    config:
      - path:/admin
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugins1.yml
  - plugins2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Both plugins should be present (appended, not replaced)
        $this->assertArrayHasKey('plugins', $result);
        $this->assertCount(2, $result['plugins']);

        // First plugin from file1
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][0]['plugin']);
        $this->assertEquals('allow', $result['plugins'][0]['response']);
        $this->assertEquals(-200, $result['plugins'][0]['weight']);

        // Second plugin from file2
        $this->assertEquals('Kanopi\Firewall\Plugins\Url', $result['plugins'][1]['plugin']);
        $this->assertEquals('block', $result['plugins'][1]['response']);
        $this->assertEquals(-100, $result['plugins'][1]['weight']);
    }

    public function testPluginsArrayMergingWithExistingPlugins(): void
    {
        $file1 = $this->tmp . '/plugins1.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\RateLimit
    response: block
    weight: 100
YAML
        );

        file_put_contents($main, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\IpAddress
    response: allow
    weight: -200

configs:
  - plugins1.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Both plugins should be present (main + included)
        $this->assertCount(2, $result['plugins']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][0]['plugin']);
        $this->assertEquals('Kanopi\Firewall\Plugins\RateLimit', $result['plugins'][1]['plugin']);
    }

    public function testPluginsArrayMergingWithMultipleInstances(): void
    {
        $file1 = $this->tmp . '/plugins1.yml';
        $file2 = $this->tmp . '/plugins2.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\IpAddress
    response: allow
    weight: -200
    config:
      - 127.0.0.1
YAML
        );

        file_put_contents($file2, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\IpAddress
    response: block
    weight: -100
    config:
      - 192.168.1.100
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - plugins1.yml
  - plugins2.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Both instances of IpAddress should be present
        $this->assertCount(2, $result['plugins']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][0]['plugin']);
        $this->assertEquals('allow', $result['plugins'][0]['response']);
        $this->assertEquals('Kanopi\Firewall\Plugins\IpAddress', $result['plugins'][1]['plugin']);
        $this->assertEquals('block', $result['plugins'][1]['response']);
    }

    public function testMixedOldAndNewFormatMerging(): void
    {
        $file1 = $this->tmp . '/old_format.yml';
        $file2 = $this->tmp . '/new_format.yml';
        $main = $this->tmp . '/main.yml';

        file_put_contents($file1, <<<YAML
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -200
    enable: true
    config:
      - 127.0.0.1
YAML
        );

        file_put_contents($file2, <<<YAML
plugins:
  - plugin: Kanopi\Firewall\Plugins\Url
    response: block
    weight: -100
    enable: true
    config:
      - path:/admin
YAML
        );

        file_put_contents($main, <<<YAML
configs:
  - old_format.yml
  - new_format.yml
YAML
        );

        $result = ConfigLoader::load($main);

        // Both formats should be present
        $this->assertArrayHasKey('bypass', $result);
        $this->assertArrayHasKey('plugins', $result);
        $this->assertArrayHasKey('Kanopi\Firewall\Plugins\IpAddress', $result['bypass']);
        $this->assertCount(1, $result['plugins']);
    }

}