<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Router for the PHP built-in servers that back SourceHttpIntegrationTest.
 *
 * Two instances run on different ports, which is what makes them different
 * origins — enough to prove that a credential is not carried across a redirect
 * to somewhere it was not meant for.
 *
 * Every request is appended to the file named by FIREWALL_TEST_RECORD so the
 * test can assert on what each server actually received.
 */

$headers = function_exists('getallheaders') ? (getallheaders() ?: []) : [];
$normalised = [];

foreach ($headers as $name => $value) {
    $normalised[strtolower((string) $name)] = $value;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$record = getenv('FIREWALL_TEST_RECORD');

if (is_string($record) && $record !== '') {
    file_put_contents(
        $record,
        json_encode([
            'port' => $_SERVER['SERVER_PORT'] ?? null,
            'path' => $path,
            'method' => $_SERVER['REQUEST_METHOD'] ?? null,
            'query' => $_SERVER['QUERY_STRING'] ?? '',
            'headers' => $normalised,
            'body' => file_get_contents('php://input'),
        ], JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX
    );
}

switch ($path) {
    case '/list':
        header('Content-Type: text/plain');
        header('ETag: W/"list-v1"');
        echo "1.1.1.1\n2.2.2.2\n";
        return true;

    case '/protected':
        if (!isset($normalised['authorization'])) {
            http_response_code(401);
            echo 'unauthorized';
            return true;
        }

        header('Content-Type: text/plain');
        echo "3.3.3.3\n";
        return true;

    case '/redirect-same':
        http_response_code(302);
        header('Location: /list');
        return true;

    case '/redirect-cross':
        $to = (int) ($_GET['to'] ?? 0);
        http_response_code(302);
        header('Location: http://127.0.0.1:' . $to . '/list');
        return true;

    case '/conditional':
        if (($normalised['if-none-match'] ?? null) === 'W/"list-v1"') {
            http_response_code(304);
            return true;
        }

        header('Content-Type: text/plain');
        header('ETag: W/"list-v1"');
        echo "4.4.4.4\n";
        return true;

    default:
        http_response_code(404);
        echo 'not found';
        return true;
}
