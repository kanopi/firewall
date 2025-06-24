<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Performance;

/**
 * Generates performance test reports in various formats
 */
class ReportGenerator
{
    private array $config;
    private string $outputDir;
    
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->outputDir = $config['reporting']['output_dir'] ?? './reports/performance';
        
        // Create output directory if it doesn't exist
        if (!is_dir($this->outputDir)) {
            mkdir($this->outputDir, 0755, true);
        }
    }
    
    /**
     * Generate all configured reports
     */
    public function generate(array $metrics): void
    {
        $formats = $this->config['reporting']['formats'] ?? ['html', 'json'];
        
        foreach ($formats as $format) {
            switch ($format) {
                case 'html':
                    $this->generateHtmlReport($metrics);
                    break;
                case 'json':
                    $this->generateJsonReport($metrics);
                    break;
            }
        }
    }
    
    /**
     * Generate JSON report
     */
    private function generateJsonReport(array $metrics): void
    {
        $filename = $this->outputDir . '/results.json';
        file_put_contents($filename, json_encode($metrics, JSON_PRETTY_PRINT));
        echo "JSON report saved to: $filename\n";
    }
    
    /**
     * Generate HTML report
     */
    private function generateHtmlReport(array $metrics): void
    {
        $html = $this->buildHtmlReport($metrics);
        $filename = $this->outputDir . '/report.html';
        file_put_contents($filename, $html);
        echo "HTML report saved to: $filename\n";
    }
    
    /**
     * Build HTML report content
     */
    private function buildHtmlReport(array $metrics): string
    {
        $timestamp = date('Y-m-d H:i:s');
        $duration = round($metrics['duration_seconds'], 2);
        
        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firewall Performance Test Report - {$timestamp}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .metric-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-top: 10px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .danger { color: #dc3545; }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background-color: #007bff;
            transition: width 0.3s ease;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>🛡️ Firewall Performance Test Report</h1>
    <p>Generated: {$timestamp} | Duration: {$duration}s</p>

HTML;

        // Summary Section
        $html .= $this->buildSummarySection($metrics);
        
        // Performance Metrics
        $html .= $this->buildPerformanceMetrics($metrics);
        
        // Traffic Analysis
        $html .= $this->buildTrafficAnalysis($metrics);
        
        // Geographic Distribution
        $html .= $this->buildGeographicDistribution($metrics);
        
        // Plugin Performance
        $html .= $this->buildPluginPerformance($metrics);
        
        // System Resources
        $html .= $this->buildSystemResources($metrics);
        
        // Success Criteria
        $html .= $this->buildSuccessCriteria($metrics);
        
        $html .= <<<HTML
    <script>
        // Add any JavaScript for charts here
        {$this->generateChartScripts($metrics)}
    </script>
</body>
</html>
HTML;

        return $html;
    }
    
    /**
     * Build summary section
     */
    private function buildSummarySection(array $metrics): string
    {
        $totalRequests = $metrics['total_requests'];
        $blockedRequests = $metrics['blocked_requests'];
        $blockRate = $totalRequests > 0 ? round(($blockedRequests / $totalRequests) * 100, 2) : 0;
        
        return <<<HTML
    <div class="summary">
        <h2>📊 Test Summary</h2>
        <div class="metric-grid">
            <div class="metric-box">
                <div class="metric-value">{$totalRequests}</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{$blockedRequests}</div>
                <div class="metric-label">Blocked Requests</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{$blockRate}%</div>
                <div class="metric-label">Block Rate</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{$metrics['requests_per_second']}</div>
                <div class="metric-label">Avg Requests/Second</div>
            </div>
        </div>
    </div>
HTML;
    }
    
    /**
     * Build performance metrics section
     */
    private function buildPerformanceMetrics(array $metrics): string
    {
        $latency = $metrics['latency_percentiles'] ?? [];
        
        $html = <<<HTML
    <div class="metric-card">
        <h2>⚡ Performance Metrics</h2>
        <h3>Response Time Percentiles</h3>
        <table>
            <tr>
                <th>Percentile</th>
                <th>Response Time (ms)</th>
            </tr>
HTML;

        foreach (['p50' => '50th', 'p95' => '95th', 'p99' => '99th'] as $key => $label) {
            $value = $latency[$key] ?? 0;
            $html .= "<tr><td>{$label}</td><td>" . round($value, 2) . "</td></tr>";
        }
        
        if (isset($latency['min']) && isset($latency['max']) && isset($latency['avg'])) {
            $html .= "<tr><td>Min</td><td>" . round($latency['min'], 2) . "</td></tr>";
            $html .= "<tr><td>Max</td><td>" . round($latency['max'], 2) . "</td></tr>";
            $html .= "<tr><td>Average</td><td>" . round($latency['avg'], 2) . "</td></tr>";
        }
        
        $html .= "</table></div>";
        
        return $html;
    }
    
    /**
     * Build traffic analysis section
     */
    private function buildTrafficAnalysis(array $metrics): string
    {
        $html = <<<HTML
    <div class="metric-card">
        <h2>🔍 Traffic Analysis</h2>
        <div class="metric-grid">
            <div class="metric-box">
                <div class="metric-value success">{$metrics['true_positives']}</div>
                <div class="metric-label">True Positives</div>
            </div>
            <div class="metric-box">
                <div class="metric-value danger">{$metrics['false_positives']}</div>
                <div class="metric-label">False Positives</div>
            </div>
            <div class="metric-box">
                <div class="metric-value success">{$metrics['true_negatives']}</div>
                <div class="metric-label">True Negatives</div>
            </div>
            <div class="metric-box">
                <div class="metric-value danger">{$metrics['false_negatives']}</div>
                <div class="metric-label">False Negatives</div>
            </div>
        </div>
        
        <h3>Accuracy Rates</h3>
        <div class="metric-grid">
            <div class="metric-box">
                <div class="metric-value">{$metrics['malicious_block_rate']}%</div>
                <div class="metric-label">Malicious Block Rate</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {$metrics['malicious_block_rate']}%"></div>
                </div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{$metrics['false_positive_rate']}%</div>
                <div class="metric-label">False Positive Rate</div>
                <div class="progress-bar">
                    <div class="progress-fill danger" style="width: {$metrics['false_positive_rate']}%; background-color: #dc3545;"></div>
                </div>
            </div>
        </div>
    </div>
HTML;
        
        return $html;
    }
    
    /**
     * Build geographic distribution section
     */
    private function buildGeographicDistribution(array $metrics): string
    {
        $html = <<<HTML
    <div class="metric-card">
        <h2>🌍 Geographic Distribution</h2>
        <table>
            <tr>
                <th>Country</th>
                <th>Requests</th>
                <th>Percentage</th>
            </tr>
HTML;
        
        $totalByCountry = array_sum($metrics['requests_by_country']);
        arsort($metrics['requests_by_country']);
        
        foreach ($metrics['requests_by_country'] as $country => $count) {
            $percentage = $totalByCountry > 0 ? round(($count / $totalByCountry) * 100, 2) : 0;
            $html .= "<tr><td>{$country}</td><td>{$count}</td><td>{$percentage}%</td></tr>";
        }
        
        $html .= "</table></div>";
        
        return $html;
    }
    
    /**
     * Build plugin performance section
     */
    private function buildPluginPerformance(array $metrics): string
    {
        if (empty($metrics['requests_by_plugin'])) {
            return '';
        }
        
        $html = <<<HTML
    <div class="metric-card">
        <h2>🔌 Plugin Performance</h2>
        <table>
            <tr>
                <th>Plugin</th>
                <th>Blocks</th>
                <th>Percentage</th>
            </tr>
HTML;
        
        $totalBlocks = array_sum($metrics['requests_by_plugin']);
        arsort($metrics['requests_by_plugin']);
        
        foreach ($metrics['requests_by_plugin'] as $plugin => $count) {
            $percentage = $totalBlocks > 0 ? round(($count / $totalBlocks) * 100, 2) : 0;
            $html .= "<tr><td>{$plugin}</td><td>{$count}</td><td>{$percentage}%</td></tr>";
        }
        
        $html .= "</table></div>";
        
        return $html;
    }
    
    /**
     * Build system resources section
     */
    private function buildSystemResources(array $metrics): string
    {
        $peakMemory = $metrics['peak_memory_mb'] ?? 0;
        $cpuUsage = $metrics['cpu_usage'] ?? 0;
        
        return <<<HTML
    <div class="metric-card">
        <h2>💻 System Resources</h2>
        <div class="metric-grid">
            <div class="metric-box">
                <div class="metric-value">{$peakMemory} MB</div>
                <div class="metric-label">Peak Memory Usage</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{$cpuUsage}%</div>
                <div class="metric-label">CPU Usage</div>
            </div>
        </div>
    </div>
HTML;
    }
    
    /**
     * Build success criteria section
     */
    private function buildSuccessCriteria(array $metrics): string
    {
        $criteria = $this->config['success_criteria'];
        
        $html = <<<HTML
    <div class="metric-card">
        <h2>✅ Success Criteria</h2>
        <table>
            <tr>
                <th>Criteria</th>
                <th>Target</th>
                <th>Actual</th>
                <th>Status</th>
            </tr>
HTML;
        
        // Malicious block rate
        $maliciousPass = $metrics['malicious_block_rate'] >= $criteria['malicious_block_rate'];
        $html .= $this->buildCriteriaRow(
            'Malicious Block Rate',
            "≥ {$criteria['malicious_block_rate']}%",
            "{$metrics['malicious_block_rate']}%",
            $maliciousPass
        );
        
        // False positive rate
        $falsePositivePass = $metrics['false_positive_rate'] <= $criteria['max_false_positive_rate'];
        $html .= $this->buildCriteriaRow(
            'False Positive Rate',
            "≤ {$criteria['max_false_positive_rate']}%",
            "{$metrics['false_positive_rate']}%",
            $falsePositivePass
        );
        
        // Memory usage
        $memoryPass = $metrics['peak_memory_mb'] <= $criteria['max_memory_usage_mb'];
        $html .= $this->buildCriteriaRow(
            'Memory Usage',
            "≤ {$criteria['max_memory_usage_mb']} MB",
            "{$metrics['peak_memory_mb']} MB",
            $memoryPass
        );
        
        // Requests per second
        $rpsPass = $metrics['requests_per_second'] >= $criteria['min_requests_per_second'];
        $html .= $this->buildCriteriaRow(
            'Requests Per Second',
            "≥ {$criteria['min_requests_per_second']}",
            round($metrics['requests_per_second'], 2),
            $rpsPass
        );
        
        $html .= "</table></div>";
        
        return $html;
    }
    
    /**
     * Build criteria row
     */
    private function buildCriteriaRow(string $name, string $target, string $actual, bool $pass): string
    {
        $status = $pass ? '<span class="success">✅ PASS</span>' : '<span class="danger">❌ FAIL</span>';
        return "<tr><td>{$name}</td><td>{$target}</td><td>{$actual}</td><td>{$status}</td></tr>";
    }
    
    /**
     * Generate chart scripts
     */
    private function generateChartScripts(array $metrics): string
    {
        // This is a placeholder for chart generation
        // You can add Chart.js code here to visualize the data
        return '';
    }
}