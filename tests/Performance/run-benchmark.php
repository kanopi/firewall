#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Firewall Performance Benchmark Runner
 * 
 * Usage: php run-benchmark.php [--config=path/to/config.yml]
 */

require_once __DIR__ . '/../../vendor/autoload.php';

use Kanopi\Firewall\Tests\Performance\TrafficGenerator;
use Kanopi\Firewall\Tests\Performance\MetricsCollector;
use Kanopi\Firewall\Tests\Performance\ReportGenerator;
use Symfony\Component\Yaml\Yaml;

// Parse command line arguments
$options = getopt('', ['config::', 'help']);

if (isset($options['help'])) {
    echo "Firewall Performance Benchmark Tool\n";
    echo "Usage: php run-benchmark.php [--config=path/to/config.yml]\n";
    echo "Options:\n";
    echo "  --config     Path to configuration file (default: benchmark-config.yml)\n";
    echo "  --help       Show this help message\n";
    exit(0);
}

$configFile = $options['config'] ?? __DIR__ . '/benchmark-config.yml';

if (!file_exists($configFile)) {
    echo "Error: Configuration file not found: $configFile\n";
    exit(1);
}

try {
    // Load configuration
    $config = Yaml::parseFile($configFile);
    
    // Initialize components
    $metricsCollector = new MetricsCollector($config);
    $trafficGenerator = new TrafficGenerator($config, $metricsCollector);
    $reportGenerator = new ReportGenerator($config);
    
    // Display test information
    echo "\n=== Firewall Performance Benchmark ===\n";
    echo "Configuration: $configFile\n";
    echo "Duration: {$config['test']['duration_minutes']} minutes\n";
    echo "Concurrent connections: {$config['test']['concurrent_connections']}\n";
    echo "Target URL: " . (getenv('FIREWALL_TEST_URL') ?: 'http://localhost:8080') . "\n";
    echo "Traffic distribution: {$config['traffic']['distribution']['normal']}% normal, ";
    echo "{$config['traffic']['distribution']['malicious']}% malicious\n";
    echo "\nStarting test...\n\n";
    
    // Run the benchmark
    $startTime = microtime(true);
    $metrics = $trafficGenerator->run();
    $duration = microtime(true) - $startTime;
    
    // Add final metrics
    $metrics['test_duration_seconds'] = $duration;
    $metrics['requests_per_second'] = $metrics['total_requests'] / $duration;
    
    // Generate reports
    echo "\nGenerating reports...\n";
    $reportGenerator->generate($metrics);
    
    // Display summary
    echo "\n=== Test Summary ===\n";
    echo "Total duration: " . round($duration, 2) . " seconds\n";
    echo "Total requests: {$metrics['total_requests']}\n";
    echo "Blocked requests: {$metrics['blocked_requests']} ";
    echo "(" . round($metrics['blocked_requests'] / $metrics['total_requests'] * 100, 2) . "%)\n";
    echo "Allowed requests: {$metrics['allowed_requests']} ";
    echo "(" . round($metrics['allowed_requests'] / $metrics['total_requests'] * 100, 2) . "%)\n";
    echo "Average RPS: " . round($metrics['requests_per_second'], 2) . "\n";
    
    if (isset($metrics['latency_percentiles'])) {
        echo "\nLatency percentiles:\n";
        echo "  P50: " . round($metrics['latency_percentiles']['p50'], 2) . "ms\n";
        echo "  P95: " . round($metrics['latency_percentiles']['p95'], 2) . "ms\n";
        echo "  P99: " . round($metrics['latency_percentiles']['p99'], 2) . "ms\n";
    }
    
    echo "\nReports saved to: {$config['reporting']['output_dir']}\n";
    
    // Check success criteria
    $criteria = $config['success_criteria'];
    $passed = true;
    
    if ($metrics['malicious_block_rate'] < $criteria['malicious_block_rate']) {
        echo "\n❌ FAILED: Malicious block rate ({$metrics['malicious_block_rate']}%) ";
        echo "below threshold ({$criteria['malicious_block_rate']}%)\n";
        $passed = false;
    }
    
    if ($metrics['false_positive_rate'] > $criteria['max_false_positive_rate']) {
        echo "❌ FAILED: False positive rate ({$metrics['false_positive_rate']}%) ";
        echo "above threshold ({$criteria['max_false_positive_rate']}%)\n";
        $passed = false;
    }
    
    if ($passed) {
        echo "\n✅ All success criteria met!\n";
    }
    
    exit($passed ? 0 : 1);
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}