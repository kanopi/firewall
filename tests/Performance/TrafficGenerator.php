<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Performance;

use GuzzleHttp\Client;
use GuzzleHttp\Promise;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;

/**
 * Traffic Generator for performance testing
 */
class TrafficGenerator
{
    private array $config;
    private MetricsCollector $metrics;
    private Client $httpClient;
    private string $targetUrl;
    private array $ipPool = [];
    private array $urlPatterns = [];
    private array $userAgents = [];
    
    public function __construct(array $config, MetricsCollector $metrics)
    {
        $this->config = $config;
        $this->metrics = $metrics;
        $this->targetUrl = getenv('FIREWALL_TEST_URL') ?: 'http://localhost:8080';
        
        $this->httpClient = new Client([
            'timeout' => 30,
            'verify' => false,
            'http_errors' => false,
            'allow_redirects' => false,
        ]);
        
        $this->initialize();
    }
    
    /**
     * Initialize test data
     */
    private function initialize(): void
    {
        $this->generateIpPool();
        $this->prepareUrlPatterns();
        $this->prepareUserAgents();
    }
    
    /**
     * Run the traffic generation
     */
    public function run(): array
    {
        $duration = $this->config['test']['duration_minutes'] * 60;
        $endTime = time() + $duration;
        $concurrency = $this->config['test']['concurrent_connections'];
        
        // Ramp up if configured
        if ($this->config['test']['ramp_up_seconds'] > 0) {
            $this->rampUp($concurrency);
        }
        
        // Main test loop
        $printInterval = time();
        while (time() < $endTime) {
            $requests = $this->generateRequestBatch($concurrency);
            $this->executeRequests($requests);
            
            // Print stats every second
            if (time() > $printInterval) {
                $this->metrics->printStats();
                $printInterval = time();
            }
            
            // Small sleep to prevent overwhelming the system
            usleep(10000); // 10ms
        }
        
        echo "\n"; // New line after stats
        
        return $this->metrics->getResults();
    }
    
    /**
     * Generate pool of IPs based on geographic distribution
     */
    private function generateIpPool(): void
    {
        $distribution = $this->config['geographic']['distribution'];
        $totalIps = $this->config['test']['concurrent_connections'] * 10;
        
        foreach ($distribution as $country => $percentage) {
            $count = (int) ($totalIps * $percentage / 100);
            for ($i = 0; $i < $count; $i++) {
                $this->ipPool[] = [
                    'ip' => $this->generateIpForCountry($country),
                    'country' => $country,
                    'asn' => $this->generateAsnPattern(),
                    'type' => $this->determineTrafficType(),
                ];
            }
        }
        
        shuffle($this->ipPool);
    }
    
    /**
     * Generate IP address for specific country
     */
    private function generateIpForCountry(string $country): string
    {
        // Simplified IP ranges for testing
        $countryRanges = [
            'US' => ['4.0.0.0', '4.255.255.255'],
            'CN' => ['1.0.0.0', '1.255.255.255'],
            'RU' => ['2.0.0.0', '2.255.255.255'],
            'BR' => ['177.0.0.0', '177.255.255.255'],
            'IN' => ['14.0.0.0', '14.255.255.255'],
            'GB' => ['5.0.0.0', '5.255.255.255'],
            'DE' => ['46.0.0.0', '46.255.255.255'],
            'FR' => ['90.0.0.0', '90.255.255.255'],
            'JP' => ['126.0.0.0', '126.255.255.255'],
            'KR' => ['175.0.0.0', '175.255.255.255'],
            'VN' => ['203.0.0.0', '203.255.255.255'],
            'NG' => ['41.0.0.0', '41.255.255.255'],
        ];
        
        if (isset($countryRanges[$country])) {
            $range = $countryRanges[$country];
            $startIp = ip2long($range[0]);
            $endIp = ip2long($range[1]);
            return long2ip(mt_rand($startIp, $endIp));
        }
        
        // Default random IP
        return mt_rand(1, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(1, 254);
    }
    
    /**
     * Generate ASN pattern
     */
    private function generateAsnPattern(): array
    {
        $patterns = $this->config['geographic']['asn_patterns'];
        $rand = mt_rand(1, 100);
        $cumulative = 0;
        
        foreach ($patterns as $type => $percentage) {
            $cumulative += $percentage;
            if ($rand <= $cumulative) {
                return $this->getAsnForType($type);
            }
        }
        
        return ['number' => mt_rand(1000, 65000), 'org' => 'Unknown'];
    }
    
    /**
     * Get ASN details for type
     */
    private function getAsnForType(string $type): array
    {
        $asnMap = [
            'residential' => [
                ['number' => 7922, 'org' => 'Comcast'],
                ['number' => 7018, 'org' => 'AT&T'],
                ['number' => 20001, 'org' => 'Charter'],
            ],
            'datacenter' => [
                ['number' => 16276, 'org' => 'OVH'],
                ['number' => 24940, 'org' => 'Hetzner'],
                ['number' => 63949, 'org' => 'Linode'],
            ],
            'cloud' => [
                ['number' => 16509, 'org' => 'Amazon AWS'],
                ['number' => 15169, 'org' => 'Google Cloud'],
                ['number' => 8075, 'org' => 'Microsoft Azure'],
            ],
            'vpn' => [
                ['number' => 60068, 'org' => 'Datacamp'],
                ['number' => 9009, 'org' => 'M247'],
                ['number' => 46562, 'org' => 'Total Server'],
            ],
        ];
        
        $options = $asnMap[$type] ?? $asnMap['residential'];
        return $options[array_rand($options)];
    }
    
    /**
     * Determine if traffic should be normal or malicious
     */
    private function determineTrafficType(): string
    {
        $maliciousThreshold = $this->config['traffic']['distribution']['malicious'];
        return mt_rand(1, 100) <= $maliciousThreshold ? 'malicious' : 'normal';
    }
    
    /**
     * Prepare URL patterns
     */
    private function prepareUrlPatterns(): void
    {
        $this->urlPatterns = [
            'valid' => $this->config['traffic']['urls']['valid'],
            'invalid' => $this->config['traffic']['urls']['invalid'],
            'malicious' => $this->config['traffic']['urls']['malicious'],
        ];
    }
    
    /**
     * Prepare user agents
     */
    private function prepareUserAgents(): void
    {
        foreach ($this->config['user_agents']['patterns'] as $type => $agents) {
            $this->userAgents[$type] = $agents;
        }
    }
    
    /**
     * Generate a batch of requests
     */
    private function generateRequestBatch(int $count): array
    {
        $requests = [];
        
        for ($i = 0; $i < $count; $i++) {
            $ipData = $this->ipPool[array_rand($this->ipPool)];
            $method = $this->getRandomMethod();
            $url = $this->getRandomUrl($ipData['type']);
            $userAgent = $this->getRandomUserAgent($ipData['type']);
            
            $headers = [
                'User-Agent' => $userAgent,
                'X-Forwarded-For' => $ipData['ip'],
                'X-Real-IP' => $ipData['ip'],
                'X-Country' => $ipData['country'],
                'X-ASN' => (string) $ipData['asn']['number'],
                'X-ASN-Org' => $ipData['asn']['org'],
            ];
            
            // Add sleep pattern
            $sleep = $this->getSleepDuration($ipData['type']);
            
            $requests[] = [
                'method' => $method,
                'uri' => $this->targetUrl . $url,
                'headers' => $headers,
                'ip_data' => $ipData,
                'sleep' => $sleep,
            ];
        }
        
        return $requests;
    }
    
    /**
     * Execute requests concurrently
     */
    private function executeRequests(array $requests): void
    {
        $promises = [];
        
        foreach ($requests as $requestData) {
            // Apply sleep if needed
            if ($requestData['sleep'] > 0) {
                usleep($requestData['sleep'] * 1000);
            }
            
            $startTime = microtime(true);
            
            $promise = $this->httpClient->requestAsync(
                $requestData['method'],
                $requestData['uri'],
                ['headers' => $requestData['headers']]
            )->then(
                function ($response) use ($requestData, $startTime) {
                    $responseTime = (microtime(true) - $startTime) * 1000; // Convert to ms
                    $headers = $response->getHeaders();
                    $headers['X-Response-Time'] = [$responseTime];
                    
                    $this->metrics->recordRequest(
                        $requestData,
                        $response->getStatusCode(),
                        $headers
                    );
                },
                function ($exception) use ($requestData, $startTime) {
                    $statusCode = 0;
                    $headers = [];
                    
                    if ($exception instanceof RequestException && $exception->hasResponse()) {
                        $response = $exception->getResponse();
                        $statusCode = $response->getStatusCode();
                        $headers = $response->getHeaders();
                    }
                    
                    $responseTime = (microtime(true) - $startTime) * 1000;
                    $headers['X-Response-Time'] = [$responseTime];
                    
                    $this->metrics->recordRequest($requestData, $statusCode, $headers);
                }
            );
            
            $promises[] = $promise;
        }
        
        // Wait for all requests to complete
        Promise\Utils::settle($promises)->wait();
    }
    
    /**
     * Get random HTTP method
     */
    private function getRandomMethod(): string
    {
        $methods = $this->config['traffic']['methods'];
        $rand = mt_rand(1, 100);
        $cumulative = 0;
        
        foreach ($methods as $method => $percentage) {
            $cumulative += $percentage;
            if ($rand <= $cumulative) {
                return $method;
            }
        }
        
        return 'GET';
    }
    
    /**
     * Get random URL based on traffic type
     */
    private function getRandomUrl(string $trafficType): string
    {
        if ($trafficType === 'malicious') {
            $urlType = mt_rand(1, 100) <= 70 ? 'malicious' : 'invalid';
        } else {
            $urlType = mt_rand(1, 100) <= 90 ? 'valid' : 'invalid';
        }
        
        $urls = $this->urlPatterns[$urlType];
        $url = $urls[array_rand($urls)];
        
        // Replace placeholders
        $url = str_replace('[id]', (string) mt_rand(1, 10000), $url);
        
        return $url;
    }
    
    /**
     * Get random user agent based on traffic type
     */
    private function getRandomUserAgent(string $trafficType): string
    {
        $distribution = $this->config['user_agents']['distribution'];
        
        if ($trafficType === 'malicious') {
            $types = ['malicious', 'scrapers', 'bots'];
        } else {
            $types = array_keys($distribution);
        }
        
        $type = $types[array_rand($types)];
        $agents = $this->userAgents[$type] ?? $this->userAgents['normal_browsers'];
        
        return $agents[array_rand($agents)];
    }
    
    /**
     * Get sleep duration based on traffic type
     */
    private function getSleepDuration(string $trafficType): int
    {
        $patterns = $this->config['traffic']['sleep_patterns'][$trafficType];
        
        if (mt_rand(1, 100) <= $patterns['percentage']) {
            return mt_rand($patterns['min'], $patterns['max']);
        }
        
        return 0;
    }
    
    /**
     * Gradual ramp up
     */
    private function rampUp(int $targetConcurrency): void
    {
        $rampUpSeconds = $this->config['test']['ramp_up_seconds'];
        $steps = 10;
        $stepDuration = $rampUpSeconds / $steps;
        
        echo "Ramping up over {$rampUpSeconds} seconds...\n";
        
        for ($i = 1; $i <= $steps; $i++) {
            $currentConcurrency = (int) ($targetConcurrency * $i / $steps);
            $requests = $this->generateRequestBatch($currentConcurrency);
            $this->executeRequests($requests);
            
            if ($i < $steps) {
                sleep((int) $stepDuration);
            }
        }
        
        echo "Ramp up complete. Running at full capacity.\n\n";
    }
}