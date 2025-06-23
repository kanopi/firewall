#!/usr/bin/env php
<?php

/**
 * Check if performance test results meet success criteria
 * Used in CI/CD pipelines to gate deployments
 */

if ($argc < 2) {
    echo "Usage: php check-criteria.php <results.json>\n";
    exit(1);
}

$resultsFile = $argv[1];

if (!file_exists($resultsFile)) {
    echo "Error: Results file not found: $resultsFile\n";
    exit(1);
}

$results = json_decode(file_get_contents($resultsFile), true);

if (!$results) {
    echo "Error: Invalid JSON in results file\n";
    exit(1);
}

// Get success criteria from results (included in the report)
$criteria = $results['config']['success_criteria'] ?? [];

if (empty($criteria)) {
    echo "Warning: No success criteria defined\n";
    exit(0);
}

$failed = false;

echo "\n=== Checking Success Criteria ===\n\n";

// Check malicious block rate
if (isset($criteria['malicious_block_rate'])) {
    $actual = $results['malicious_block_rate'] ?? 0;
    $target = $criteria['malicious_block_rate'];
    
    if ($actual >= $target) {
        echo "✅ Malicious block rate: {$actual}% (target: ≥{$target}%)\n";
    } else {
        echo "❌ Malicious block rate: {$actual}% (target: ≥{$target}%)\n";
        $failed = true;
    }
}

// Check false positive rate
if (isset($criteria['max_false_positive_rate'])) {
    $actual = $results['false_positive_rate'] ?? 0;
    $target = $criteria['max_false_positive_rate'];
    
    if ($actual <= $target) {
        echo "✅ False positive rate: {$actual}% (target: ≤{$target}%)\n";
    } else {
        echo "❌ False positive rate: {$actual}% (target: ≤{$target}%)\n";
        $failed = true;
    }
}

// Check latency
if (isset($criteria['max_added_latency_ms'])) {
    $actual = $results['latency_percentiles']['p95'] ?? 0;
    $target = $criteria['max_added_latency_ms'];
    
    if ($actual <= $target) {
        echo "✅ P95 latency: {$actual}ms (target: ≤{$target}ms)\n";
    } else {
        echo "❌ P95 latency: {$actual}ms (target: ≤{$target}ms)\n";
        $failed = true;
    }
}

// Check memory usage
if (isset($criteria['max_memory_usage_mb'])) {
    $actual = $results['peak_memory_mb'] ?? 0;
    $target = $criteria['max_memory_usage_mb'];
    
    if ($actual <= $target) {
        echo "✅ Peak memory: {$actual}MB (target: ≤{$target}MB)\n";
    } else {
        echo "❌ Peak memory: {$actual}MB (target: ≤{$target}MB)\n";
        $failed = true;
    }
}

// Check requests per second
if (isset($criteria['min_requests_per_second'])) {
    $actual = round($results['requests_per_second'] ?? 0, 2);
    $target = $criteria['min_requests_per_second'];
    
    if ($actual >= $target) {
        echo "✅ Requests per second: {$actual} (target: ≥{$target})\n";
    } else {
        echo "❌ Requests per second: {$actual} (target: ≥{$target})\n";
        $failed = true;
    }
}

echo "\n";

if ($failed) {
    echo "❌ Some criteria failed. Performance test FAILED.\n";
    exit(1);
} else {
    echo "✅ All criteria passed. Performance test PASSED.\n";
    exit(0);
}