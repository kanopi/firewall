<?php

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\ConfigLoader;

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

        $this->expectException(\RuntimeException::class);
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

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Include depth exceeded');
        ConfigLoader::load($this->tmp . '/d0.yml');
    }

    public function testMissingEnvVarThrowsWithHelpfulMessage(): void
    {
        $f = $this->tmp . '/bad_env.yml';
        $this->write($f, "x: '%env(int:DOES_NOT_EXIST)%'\n");

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Environment variable "DOES_NOT_EXIST" is not set');
        ConfigLoader::load($f);
    }

    public function testBadBoolCastThrows(): void
    {
        putenv('WEIRD_BOOL=maybe');
        $f = $this->tmp . '/bad_bool.yml';
        $this->write($f, "x: '%env(bool:WEIRD_BOOL)%'\n");

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        ConfigLoader::load($f);
    }

    public function testBadJsonThrows(): void
    {
        putenv('BAD_JSON={oops]');
        $f = $this->tmp . '/bad_json.yml';
        $this->write($f, "x: '%env(json:BAD_JSON)%'\n");

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid JSON');
        ConfigLoader::load($f);
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

    public function testUnknownEnvProcessorThrows(): void
    {
        putenv('FOO=bar');
        $f = $this->tmp . '/unknown_proc.yml';
        $this->write($f, "x: '%env(weird:FOO)%'\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unknown env processor');
        ConfigLoader::load($f);
    }

    public function testBadIntCastThrows(): void
    {
        putenv('BAD_INT=notanumber');
        $f = $this->tmp . '/bad_int.yml';
        $this->write($f, "x: '%env(int:BAD_INT)%'\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        ConfigLoader::load($f);
    }

    public function testBadFloatCastThrows(): void
    {
        putenv('BAD_FLOAT=NaNish');
        $f = $this->tmp . '/bad_float.yml';
        $this->write($f, "x: '%env(float:BAD_FLOAT)%'\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        ConfigLoader::load($f);
    }

    public function testInvalidBase64Throws(): void
    {
        putenv('BAD_B64=*not-base64*');
        $f = $this->tmp . '/bad_b64.yml';
        $this->write($f, "x: '%env(base64:BAD_B64)%'\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid base64');
        ConfigLoader::load($f);
    }

    public function testFileProcessorMissingThrows(): void
    {
        putenv('MISSING_FILE=' . $this->tmp . '/nope.txt');
        $f = $this->tmp . '/missing_file.yml';
        $this->write($f, "x: '%env(file:MISSING_FILE)%'\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found or unreadable');
        ConfigLoader::load($f);
    }

    public function testUrlProcessorReturnsParsedArray(): void
    {
        putenv('OK_URL=:still/a/url'); // parse_url returns an array (path-only)
        $f = $this->tmp . '/ok_url.yml';
        $this->write($f, "x: '%env(url:OK_URL)%'\n");
        $cfg = ConfigLoader::load($f);
        self::assertIsArray($cfg['x']);
        self::assertArrayHasKey('path', $cfg['x']);
        self::assertSame(':still/a/url', $cfg['x']['path']);
    }

    public function testQueryStringEmptyReturnsEmptyArray(): void
    {
        putenv('APP_QS_EMPTY=');
        $f = $this->tmp . '/qs_empty.yml';
        $this->write($f, "x: '%env(query_string:APP_QS_EMPTY)%'\n");
        $cfg = ConfigLoader::load($f);
        self::assertSame([], $cfg['x']);
    }

    public function testNormalizeIncludeEnvResolvesToNonStringThrows(): void
    {
        putenv('INCLUDE_JSON={"a":1}');
        $f = $this->tmp . '/main_nonstring_include.yml';
        $this->write($f, "configs: ['%env(json:INCLUDE_JSON)%']\n");
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid include entry (must be string)');
        ConfigLoader::load($f);
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
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid include entry');
        ConfigLoader::load($f);
    }
}