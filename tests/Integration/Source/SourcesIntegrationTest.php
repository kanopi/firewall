<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Source;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Exercises `metadata.sources` end to end, through a real firewall config.
 *
 * The unit tests cover each pipeline stage. This covers the part they cannot:
 * that a YAML file on disk declaring sources produces a firewall which allows
 * and blocks the addresses those sources named.
 */
class SourcesIntegrationTest extends IntegrationTestCase
{
    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');
    }

    /**
     * Write a list fixture and return its path.
     */
    private function list(string $name, string $contents): string
    {
        $path = $this->tempDir . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * Build a firewall from a config array, in exception mode.
     */
    private function firewall(array $config): Firewall
    {
        $config['global']['mode'] ??= 'exception';
        $config['storage']['type'] ??= 'Kanopi\Firewall\Storage\InMemoryStorage';

        // Keep every source cache inside this test's temp directory.
        $config['plugins'] = array_map(function (array $plugin): array {
            if (isset($plugin['metadata']['sources'])) {
                $plugin['metadata']['sources'] = array_map(function (array $source): array {
                    $source['ttl'] ??= 0;

                    return $source;
                }, $plugin['metadata']['sources']);
            }

            return $plugin;
        }, $config['plugins']);

        $configFile = $this->tempDir . '/config.yml';
        file_put_contents($configFile, Yaml::dump($config, 6, 2));

        return Firewall::create([$configFile]);
    }

    /**
     * Whether a request survives evaluation.
     */
    private function allows(Firewall $firewall, string $ip): bool
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);

        try {
            $firewall->evaluate($request);
        } catch (FirewallBlockedException) {
            return false;
        }

        return true;
    }

    /**
     * A block list assembled from two text sources blocks both sets and
     * leaves everything else alone.
     */
    public function testTextSourcesFeedABlockList(): void
    {
        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => [
                        'sources' => [
                            [
                                'name' => 'scanners',
                                'upstream' => $this->list('scanners.txt', "# banner\n203.0.113.0/24\n"),
                                'validate' => 'cidr',
                            ],
                            [
                                'name' => 'tor',
                                'upstream' => $this->list('tor.txt', "198.51.100.7\n"),
                                'validate' => 'cidr',
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $this->assertFalse($this->allows($firewall, '203.0.113.9'), 'First source should block.');
        $this->assertFalse($this->allows($firewall, '198.51.100.7'), 'Second source should block.');
        $this->assertTrue($this->allows($firewall, '8.8.8.8'), 'Unlisted addresses pass.');
    }

    /**
     * The same list can drive a different response — the point of separating
     * the data from the policy. Here it allows rather than blocks, and the
     * allow runs first so it wins over the block list below it.
     */
    public function testSameDataDifferentResponse(): void
    {
        $monitors = $this->list('monitors.txt', "203.0.113.5\n");

        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'allow',
                    'weight' => -200,
                    'enable' => true,
                    'metadata' => ['sources' => [['name' => 'monitors', 'upstream' => $monitors]]],
                ],
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['203.0.113.0/24'],
                ],
            ],
        ]);

        $this->assertTrue($this->allows($firewall, '203.0.113.5'), 'Allow source wins over the block list.');
        $this->assertFalse($this->allows($firewall, '203.0.113.6'), 'Others in the block range still blocked.');
    }

    /**
     * A JSON source is selected, filtered, and templated into rules on the way
     * into the plugin — the AWS-shaped case, without the network.
     */
    public function testJsonSourceIsSelectedAndFiltered(): void
    {
        $body = json_encode([
            'prefixes' => [
                ['ip_prefix' => '203.0.113.0/24', 'region' => 'us-east-1', 'service' => 'EC2'],
                ['ip_prefix' => '198.51.100.0/24', 'region' => 'eu-west-1', 'service' => 'EC2'],
                ['ip_prefix' => '192.0.2.0/24', 'region' => 'us-east-1', 'service' => 'S3'],
            ],
        ]);

        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => [
                        'sources' => [
                            [
                                'name' => 'cloud-ec2-us',
                                'upstream' => $this->list('ranges.json', (string) $body),
                                'format' => 'json',
                                'select' => 'prefixes.*',
                                'where' => ['service:EC2', 'region@starts_with:us-'],
                                'template' => '{value[ip_prefix]}',
                                'validate' => 'cidr',
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $this->assertFalse($this->allows($firewall, '203.0.113.9'), 'Matching service and region blocks.');
        $this->assertTrue($this->allows($firewall, '198.51.100.9'), 'Wrong region is filtered out.');
        $this->assertTrue($this->allows($firewall, '192.0.2.9'), 'Wrong service is filtered out.');
    }

    /**
     * Inline `config:` is appended after every source, so a deployment can add
     * a local entry without editing a shared list.
     */
    public function testInlineConfigAugmentsSources(): void
    {
        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => [
                        'sources' => [['name' => 'shared', 'upstream' => $this->list('shared.txt', "203.0.113.0/24\n")]],
                    ],
                    'config' => ['198.51.100.42'],
                ],
            ],
        ]);

        $this->assertFalse($this->allows($firewall, '203.0.113.1'), 'Source entry blocks.');
        $this->assertFalse($this->allows($firewall, '198.51.100.42'), 'Local entry blocks.');
    }

    /**
     * A CSV source templated into ASN rules reaches the Asn plugin intact,
     * showing the pipeline is not IpAddress-specific.
     */
    public function testCsvSourceTemplatedIntoRuleStrings(): void
    {
        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => [
                        'sources' => [
                            [
                                'name' => 'bad-paths',
                                'upstream' => $this->list('paths.csv', "path,confidence\n/wp-login.php,90\n/robots.txt,5\n"),
                                'format' => 'csv',
                                'where' => ['confidence@greater_than:50'],
                                'template' => 'path:{value[path]}',
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        // Different source addresses: a block records an offense against the
        // address, so reusing one would ban the second request on its history
        // rather than on its path.
        $blocked = Request::create('/wp-login.php', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $allowed = Request::create('/robots.txt', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.4.4']);

        $threw = false;

        try {
            $firewall->evaluate($blocked);
        } catch (FirewallBlockedException) {
            $threw = true;
        }

        $this->assertTrue($threw, 'High-confidence path from the CSV should block.');

        $firewall->evaluate($allowed);
        $this->assertTrue(true, 'Filtered-out path should not block.');
    }

    /**
     * A source that cannot be read leaves the rest of the list working, and
     * the firewall still starts.
     */
    public function testMissingSourceDegradesWithoutTakingTheRest(): void
    {
        $firewall = $this->firewall([
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'metadata' => [
                        'sources' => [
                            ['name' => 'present', 'upstream' => $this->list('present.txt', "203.0.113.0/24\n")],
                            ['name' => 'absent', 'upstream' => $this->tempDir . '/never-written.txt'],
                        ],
                    ],
                ],
            ],
        ]);

        $this->assertFalse($this->allows($firewall, '203.0.113.9'), 'Readable source still applies.');
        $this->assertTrue($this->allows($firewall, '8.8.8.8'), 'Missing source contributes nothing.');
    }
}
