<?php

declare(strict_types=1);

/*
 * Front controller for the Lite Firewall demo.
 *
 * Three demo routes — see example/demo/config.yml for the rules:
 *
 *   /            allowed
 *   /admin       blocked
 *   /secure      challenged (interstitial → solve → pass token → reload)
 *
 * Run with the PHP built-in server (single-process):
 *
 *   php -S localhost:8000 example/demo/index.php
 *
 * Or with the nginx + php-fpm stack for production-shaped concurrency:
 *
 *   cd example/demo && docker compose -f docker-compose.perf.yml up
 */

require __DIR__ . '/../../vendor/autoload.php';

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'])->evaluate();

// Anything past evaluate() means the firewall allowed the request through:
// either nothing matched, or a pass token is held.
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$path = $_SERVER['REQUEST_URI'] ?? '/';
$cookiePresent = isset($_COOKIE['fw_challenge_pass']);

header('Content-Type: text/html; charset=utf-8');

?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Lite Firewall demo</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; line-height: 1.5; padding: 0 1rem; }
    h1 { color: #137333; }
    code { background: #eef; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.95em; }
    table { border-collapse: collapse; margin-top: 1rem; width: 100%; }
    th, td { padding: 0.4rem 0.8rem; border-bottom: 1px solid #ddd; text-align: left; vertical-align: top; }
    th { background: #f3f3f5; }
    .meta { color: #555; font-size: 0.9rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #ddd; }
  </style>
</head>
<body>
  <h1>You passed the firewall.</h1>
  <p>The request hit <code><?= htmlspecialchars($path, ENT_QUOTES, 'UTF-8') ?></code> and nothing blocked or challenged it.</p>

  <h2>Try the other routes</h2>
  <table>
    <thead>
      <tr><th>URL</th><th>Expected behavior</th></tr>
    </thead>
    <tbody>
      <tr><td><a href="/">/</a></td><td>Allowed — this page.</td></tr>
      <tr><td><a href="/admin">/admin</a></td><td>Blocked — the URL plugin rejects anything under <code>/admin</code> with a 400.</td></tr>
      <tr><td><a href="/secure">/secure</a></td><td>Challenged — math interstitial. Solve it once, then <code>/secure</code> stays accessible for 60s via the pass cookie.</td></tr>
    </tbody>
  </table>

  <h2>Re-triggering the challenge</h2>
  <p>The pass token TTL is 60s in this demo. To force the interstitial again sooner:</p>
  <ul>
    <li>Delete the <code>fw_challenge_pass</code> cookie via browser dev tools, or</li>
    <li>Reload <code>/secure</code> in an incognito window.</li>
  </ul>

  <p class="meta">
    Request path: <code><?= htmlspecialchars($path, ENT_QUOTES, 'UTF-8') ?></code><br>
    Client IP (as the firewall sees it): <code><?= htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') ?></code><br>
    Pass cookie present: <code><?= $cookiePresent ? 'yes' : 'no' ?></code>
  </p>
</body>
</html>
