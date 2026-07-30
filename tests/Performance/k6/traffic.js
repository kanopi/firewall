// Traffic model for the firewall performance harness.
//
// Defines the request population: which client IPs exist, what they ask for,
// and what they look like. Kept separate from load.js so the shape of the
// traffic can be changed without touching the load profile or the metrics.
//
// Everything here runs in k6's init context, which executes once per VU
// before the test starts. Work done at module scope is therefore free at
// request time — important, because a generator that spends CPU building
// each request is a generator that cannot saturate the target.

const pool = JSON.parse(open('./ip-pool.json'));

export const IP_POOL = pool.ips;
export const BURST_SLICE = pool.burst_slice;

// Realistic browser agents. device-detector's cost depends on how many
// distinct strings it sees, so a single repeated agent would let it look
// far cheaper than it is in production.
const BROWSER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
];

// Named scanners. These trip UserAgent directly and also contribute to the
// CRS scanner-detection category.
const SCANNER_AGENTS = [
    'sqlmap/1.8.3#stable (https://sqlmap.org)',
    'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)',
    'masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)',
    'Nmap Scripting Engine; https://nmap.org/book/nse.html',
    'Mozilla/5.0 zgrab/0.x',
    'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)',
];

// Well-behaved crawlers. Blocked by `bot:true`, and worth separating from
// scanners because they are the classic false-positive risk.
const BOT_AGENTS = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
    'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
];

const CONTENT_PATHS = [
    '/', '/about', '/contact', '/blog', '/blog/2026/03/a-post-title',
    '/products', '/products/catalogue', '/pricing', '/docs/getting-started',
    '/search',
];

const SCANNER_PATHS = [
    '/wp-admin/', '/wp-login.php', '/wp-content/plugins/revslider/temp/update_extract/revslider/db.php',
    '/.env', '/.git/config', '/phpmyadmin/index.php', '/admin.php',
    '/config.php', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    '/xmlrpc.php', '/.aws/credentials', '/backup.sql', '/shell.php',
];

const SQLI_PAYLOADS = [
    "1' UNION SELECT 1,2,3--",
    "1 OR 1=1",
    "'; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "1 UNION ALL SELECT NULL,version()--",
];

const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(document.cookie)",
    '<svg/onload=confirm(1)>',
];

const LFI_PAYLOADS = [
    '../../../../etc/passwd',
    '....//....//....//etc/shadow',
    '/proc/self/environ',
    'php://filter/convert.base64-encode/resource=index.php',
];

function pick(list, rnd) {
    return list[Math.floor(rnd * list.length) % list.length];
}

/**
 * Request profiles.
 *
 * `weight` is relative, not a percentage — the weights are normalised at
 * startup, so adding a profile does not require rebalancing every other one.
 *
 * `expect` records what the traffic is *meant* to be. The report uses it to
 * show observed block rates per profile per scenario. It is descriptive, not
 * an assertion: a single-plugin scenario legitimately allows malicious
 * traffic aimed at a different plugin.
 */
export const PROFILES = [
    {
        name: 'browse',
        weight: 30,
        expect: 'allow',
        build: (r) => ({
            method: 'GET',
            path: pick(CONTENT_PATHS, r()),
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'api_read',
        weight: 20,
        expect: 'allow',
        build: (r) => ({
            method: 'GET',
            path: `/api/v1/items?page=${Math.floor(r() * 50) + 1}&per_page=25`,
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'asset',
        weight: 10,
        expect: 'allow',
        build: (r) => ({
            method: 'GET',
            path: pick(['/assets/app.css', '/assets/app.js', '/assets/logo.svg'], r()),
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'api_write',
        weight: 10,
        expect: 'allow',
        build: (r) => ({
            method: 'POST',
            path: '/api/v1/items',
            ua: pick(BROWSER_AGENTS, r()),
            body: JSON.stringify({ title: 'a new item', qty: Math.floor(r() * 10) + 1 }),
            headers: { 'Content-Type': 'application/json' },
        }),
    },
    {
        name: 'scanner_url',
        weight: 7,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: pick(SCANNER_PATHS, r()),
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'sqli',
        weight: 6,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: `/search?q=${encodeURIComponent(pick(SQLI_PAYLOADS, r()))}`,
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'xss',
        weight: 4,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: `/search?q=${encodeURIComponent(pick(XSS_PAYLOADS, r()))}`,
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'lfi',
        weight: 3,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: `/download?file=${encodeURIComponent(pick(LFI_PAYLOADS, r()))}`,
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
    {
        name: 'scanner_ua',
        weight: 4,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: pick(CONTENT_PATHS, r()),
            ua: pick(SCANNER_AGENTS, r()),
        }),
    },
    {
        name: 'bot_ua',
        weight: 3,
        expect: 'block',
        build: (r) => ({
            method: 'GET',
            path: pick(CONTENT_PATHS, r()),
            ua: pick(BOT_AGENTS, r()),
        }),
    },
    {
        name: 'burst',
        weight: 3,
        expect: 'block',
        // Drawn from the burst slice only — see generate-ip-pool.php for why.
        burst: true,
        build: (r) => ({
            method: 'POST',
            path: '/login',
            ua: pick(BROWSER_AGENTS, r()),
            body: 'user=admin&pass=hunter2',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
    },
    {
        name: 'risky_method',
        weight: 3,
        expect: 'block',
        build: (r) => ({
            method: 'DELETE',
            path: `/api/v1/items/${Math.floor(r() * 1000) + 1}`,
            ua: pick(BROWSER_AGENTS, r()),
        }),
    },
];

// Cumulative weight table, built once, so profile selection at request time
// is a single binary-search-free linear scan over 12 entries.
const TOTAL_WEIGHT = PROFILES.reduce((sum, p) => sum + p.weight, 0);
const CUMULATIVE = [];
let running = 0;
for (const p of PROFILES) {
    running += p.weight;
    CUMULATIVE.push({ profile: p, upto: running / TOTAL_WEIGHT });
}

export function pickProfile(rnd) {
    for (const entry of CUMULATIVE) {
        if (rnd <= entry.upto) {
            return entry.profile;
        }
    }
    return PROFILES[0];
}

export function pickClient(profile, rnd) {
    if (profile.burst) {
        return IP_POOL[Math.floor(rnd * BURST_SLICE) % BURST_SLICE];
    }
    return IP_POOL[Math.floor(rnd * IP_POOL.length) % IP_POOL.length];
}
