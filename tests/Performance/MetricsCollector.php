<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Performance;

/**
 * Collects and aggregates performance metrics during benchmark tests
 */
class MetricsCollector
{
    private array $config;
    private array $metrics = [];
    private array $responseTimes = [];
    private array $requestsByCountry = [];
    private array $requestsByMethod = [];
    private array $requestsByUrl = [];
    private array $requestsByPlugin = [];
    private array $memorySnapshots = [];
    private float $startTime;
    
    // Counters
    private int $totalRequests = 0;
    private int $blockedRequests = 0;
    private int $allowedRequests = 0;
    private int $rateLimitHits = 0;
    private int $falsePositives = 0;
    private int $truePositives = 0;
    private int $trueNegatives = 0;
    private int $falseNegatives = 0;
    
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->startTime = microtime(true);
        $this->initializeMetrics();
        
        // Start memory monitoring in background
        $this->startMemoryMonitoring();
    }
    
    /**
     * Initialize metrics structure
     */
    private function initializeMetrics(): void
    {
        $this->metrics = [
            'start_time' => date('Y-m-d H:i:s'),
            'config' => $this->config,
            'environment' => [
                'php_version' => PHP_VERSION,
                'memory_limit' => ini_get('memory_limit'),
                'max_execution_time' => ini_get('max_execution_time'),
            ],
        ];
    }
    
    /**
     * Record a request and its response
     */
    public function recordRequest(array $requestData, int $statusCode, array $responseHeaders): void
    {
        $this->totalRequests++;
        
        // Determine if blocked
        $isBlocked = $statusCode === 400 || $statusCode === 403 || $statusCode === 429;
        
        if ($isBlocked) {
            $this->blockedRequests++;
            
            // Determine blocking reason from headers
            $blockingPlugin = $responseHeaders['X-Blocked-By'][0] ?? 'unknown';
            $this->recordPluginBlock($blockingPlugin);
            
            // Check if rate limited
            if ($statusCode === 429) {
                $this->rateLimitHits++;
            }
            
            // Determine if true/false positive
            if ($requestData['ip_data']['type'] === 'malicious') {
                $this->truePositives++; // Correctly blocked malicious traffic
            } else {
                $this->falsePositives++; // Incorrectly blocked legitimate traffic
            }
        } else {
            $this->allowedRequests++;
            
            // Determine if true/false negative
            if ($requestData['ip_data']['type'] === 'malicious') {
                $this->falseNegatives++; // Failed to block malicious traffic
            } else {
                $this->trueNegatives++; // Correctly allowed legitimate traffic
            }
        }
        
        // Record response time
        $responseTime = $responseHeaders['X-Response-Time'][0] ?? null;
        if ($responseTime) {
            $this->responseTimes[] = (float) $responseTime;
        }
        
        // Record by country
        $country = $requestData['ip_data']['country'];
        $this->requestsByCountry[$country] = ($this->requestsByCountry[$country] ?? 0) + 1;
        
        // Record by method
        $method = $requestData['method'];
        $this->requestsByMethod[$method] = ($this->requestsByMethod[$method] ?? 0) + 1;
        
        // Record by URL
        $path = parse_url($requestData['uri'], PHP_URL_PATH);
        $this->requestsByUrl[$path] = ($this->requestsByUrl[$path] ?? 0) + 1;
    }
    
    /**
     * Record which plugin blocked a request
     */
    private function recordPluginBlock(string $plugin): void
    {
        $this->requestsByPlugin[$plugin] = ($this->requestsByPlugin[$plugin] ?? 0) + 1;
    }
    
    /**
     * Start memory monitoring
     */
    private function startMemoryMonitoring(): void
    {
        // Record initial memory usage
        $this->recordMemorySnapshot();
        
        // Note: In a real implementation, you'd use a separate process or thread
        // For this example, we'll record memory at key points
    }
    
    /**
     * Record current memory usage
     */
    public function recordMemorySnapshot(): void
    {
        $this->memorySnapshots[] = [
            'timestamp' => microtime(true) - $this->startTime,
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
        ];
    }
    
    /**
     * Calculate latency percentiles
     */
    private function calculateLatencyPercentiles(): array
    {
        if (empty($this->responseTimes)) {
            return ['p50' => 0, 'p95' => 0, 'p99' => 0];
        }
        
        sort($this->responseTimes);
        $count = count($this->responseTimes);
        
        return [
            'p50' => $this->responseTimes[(int)($count * 0.5)],
            'p95' => $this->responseTimes[(int)($count * 0.95)],
            'p99' => $this->responseTimes[(int)($count * 0.99)],
            'min' => min($this->responseTimes),
            'max' => max($this->responseTimes),
            'avg' => array_sum($this->responseTimes) / $count,
        ];
    }
    
    /**
     * Get CPU usage (Linux only)
     */
    private function getCpuUsage(): float
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            return 0.0;
        }
        
        $stat1 = file('/proc/stat');
        usleep(100000); // 0.1 second
        $stat2 = file('/proc/stat');
        
        $info1 = explode(" ", preg_replace("!cpu +!", "", $stat1[0]));
        $info2 = explode(" ", preg_replace("!cpu +!", "", $stat2[0]));
        
        $diff_idle = $info2[3] - $info1[3];
        $diff_total = array_sum($info2) - array_sum($info1);
        
        return round(100 * ($diff_total - $diff_idle) / $diff_total, 2);
    }
    
    /**
     * Get final results
     */
    public function getResults(): array
    {
        $duration = microtime(true) - $this->startTime;
        
        // Record final memory snapshot
        $this->recordMemorySnapshot();
        
        // Calculate rates
        $maliciousRequests = $this->truePositives + $this->falseNegatives;
        $legitimateRequests = $this->trueNegatives + $this->falsePositives;
        
        $maliciousBlockRate = $maliciousRequests > 0 
            ? round(($this->truePositives / $maliciousRequests) * 100, 2)
            : 0;
            
        $falsePositiveRate = $legitimateRequests > 0
            ? round(($this->falsePositives / $legitimateRequests) * 100, 2)
            : 0;
        
        return array_merge($this->metrics, [
            'end_time' => date('Y-m-d H:i:s'),
            'duration_seconds' => $duration,
            'total_requests' => $this->totalRequests,
            'blocked_requests' => $this->blockedRequests,
            'allowed_requests' => $this->allowedRequests,
            'requests_per_second' => $this->totalRequests / $duration,
            
            // Accuracy metrics
            'true_positives' => $this->truePositives,
            'false_positives' => $this->falsePositives,
            'true_negatives' => $this->trueNegatives,
            'false_negatives' => $this->falseNegatives,
            'malicious_block_rate' => $maliciousBlockRate,
            'false_positive_rate' => $falsePositiveRate,
            
            // Performance metrics
            'latency_percentiles' => $this->calculateLatencyPercentiles(),
            'rate_limit_hits' => $this->rateLimitHits,
            
            // Distribution metrics
            'requests_by_country' => $this->requestsByCountry,
            'requests_by_method' => $this->requestsByMethod,
            'requests_by_url' => array_slice($this->requestsByUrl, 0, 20), // Top 20
            'requests_by_plugin' => $this->requestsByPlugin,
            
            // System metrics
            'memory_snapshots' => $this->memorySnapshots,
            'peak_memory_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'cpu_usage' => $this->getCpuUsage(),
        ]);
    }
    
    /**
     * Print real-time statistics
     */
    public function printStats(): void
    {
        $elapsed = microtime(true) - $this->startTime;
        $rps = $this->totalRequests / $elapsed;
        
        echo sprintf(
            "\r[%s] Requests: %d | Blocked: %d (%.1f%%) | RPS: %.1f | Memory: %.1fMB",
            gmdate('H:i:s', (int)$elapsed),
            $this->totalRequests,
            $this->blockedRequests,
            $this->totalRequests > 0 ? ($this->blockedRequests / $this->totalRequests) * 100 : 0,
            $rps,
            memory_get_usage(true) / 1024 / 1024
        );
    }
}