// k6 load script for the firewall performance harness.
//
// One invocation drives one scenario. bin/run.sh runs it once per scenario
// against a php-fpm container that was recreated for that scenario, so no
// warm state ever leaks between measurements.
//
// The interesting output is not http_req_duration — that mixes nginx, fastcgi,
// PHP startup, the simulated app, and the firewall together. It is the
// fw_eval_us trend, read from a response header, which is the firewall's own
// decision time and nothing else. Comparing the two tells you whether a slow
// scenario is slow because the firewall is working hard, or because workers
// are queueing behind something.

import http from 'k6/http';
import { Counter, Trend } from 'k6/metrics';
import { PROFILES, pickProfile, pickClient, IP_POOL } from './traffic.js';

const TARGET = __ENV.PERF_TARGET || 'http://nginx';
const SCENARIO = __ENV.PERF_SCENARIO || 'unknown';
const VUS = parseInt(__ENV.PERF_VUS || '200', 10);
const DURATION = __ENV.PERF_DURATION || '45s';
const RAMP = __ENV.PERF_RAMP || '15s';
const RESULTS_DIR = __ENV.PERF_RESULTS_DIR || '/results';
const IP_HEADER = __ENV.PERF_IP_HEADER || 'X-Perf-Client-Ip';

// ---------------------------------------------------------------------------
// Metrics
//
// Firewall timings come back as headers. They are recorded as their own
// trends so the report can separate firewall cost from end-to-end latency.
// ---------------------------------------------------------------------------

const fwEvalUs = new Trend('fw_eval_us');
const fwBootUs = new Trend('fw_boot_us');
const fwTotalUs = new Trend('fw_total_us');
const fwMemKb = new Trend('fw_mem_kb');

const outcomeAllow = new Counter('fw_outcome_allow');
const outcomeBlock = new Counter('fw_outcome_block');
const outcomeChallenge = new Counter('fw_outcome_challenge');
const outcomeError = new Counter('fw_outcome_error');
// Responses that carried no X-Fw-Outcome header at all: connection resets,
// nginx 502s from a saturated pool, timeouts. Counting these separately
// matters — without it, a run where half the requests died looks like a run
// with excellent latency, because only the survivors were measured.
const noResponse = new Counter('fw_no_response');

// Per-profile tallies. k6's summary does not break a counter down by tag, so
// one counter per profile is the way to get a per-profile block rate out.
const perProfile = {};
for (const p of PROFILES) {
    perProfile[p.name] = {
        requests: new Counter(`req_${p.name}`),
        blocked: new Counter(`blk_${p.name}`),
        evalUs: new Trend(`evalus_${p.name}`),
    };
}

export const options = {
    // Bodies are a fixed 14 bytes and never inspected; discarding them keeps
    // the generator's own CPU out of the measurement.
    discardResponseBodies: true,
    // k6 computes only p(90) and p(95) by default, so p(99) would silently
    // report as zero. The tail is the interesting part of a firewall
    // measurement — a warm-up effect or a lock contention shows up at p99
    // long before it moves the median.
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    // No thresholds by design. This harness reports, it does not gate — CI
    // runners are shared hardware and an absolute latency threshold would
    // flake far more often than it would catch a real regression.
    thresholds: {},
    scenarios: {
        load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: RAMP, target: VUS },
                { duration: DURATION, target: VUS },
                { duration: '5s', target: 0 },
            ],
            gracefulRampDown: '5s',
        },
    },
};

export function setup() {
    return { startedAt: new Date().toISOString(), poolSize: IP_POOL.length };
}

export default function () {
    // Math.random() is per-VU in k6, which is what we want: VUs must not march
    // through the traffic mix in lockstep.
    const rnd = Math.random;

    const profile = pickProfile(rnd());
    const client = pickClient(profile, rnd());
    const spec = profile.build(rnd);

    const headers = Object.assign(
        {
            'User-Agent': spec.ua,
            [IP_HEADER]: client.ip,
            // Marks the request as harness traffic. Nothing in the firewall
            // reads it; it is there so a packet capture or an access log can
            // be told apart from anything else hitting the box.
            'X-Perf-Profile': profile.name,
        },
        spec.headers || {},
    );

    const res = http.request(spec.method, `${TARGET}${spec.path}`, spec.body || null, {
        headers,
        // A profile tag would explode the metric cardinality; per-profile
        // counters above cover it more cheaply.
        tags: { profile: profile.name },
        timeout: '30s',
    });

    const tally = perProfile[profile.name];
    tally.requests.add(1);

    const outcome = res.headers['X-Fw-Outcome'];

    if (!outcome) {
        // Either the request never reached PHP, or PHP died before headers.
        noResponse.add(1);
        return;
    }

    const evalUs = parseInt(res.headers['X-Fw-Eval-Us'] || '0', 10);
    const bootUs = parseInt(res.headers['X-Fw-Boot-Us'] || '0', 10);
    const totalUs = parseInt(res.headers['X-Fw-Total-Us'] || '0', 10);
    const memKb = parseInt(res.headers['X-Fw-Mem-Kb'] || '0', 10);

    fwEvalUs.add(evalUs);
    fwBootUs.add(bootUs);
    fwTotalUs.add(totalUs);
    fwMemKb.add(memKb);
    tally.evalUs.add(evalUs);

    switch (outcome) {
        case 'block':
            outcomeBlock.add(1);
            tally.blocked.add(1);
            break;
        case 'challenge':
            outcomeChallenge.add(1);
            break;
        case 'error':
            outcomeError.add(1);
            break;
        default:
            outcomeAllow.add(1);
    }
}

/**
 * Emit one JSON file per scenario for bin/report.php to aggregate.
 *
 * The shape is deliberately flat and self-describing: the report should not
 * need to know k6's internal metric layout, so that a future k6 upgrade that
 * reshuffles the summary object breaks in one place instead of everywhere.
 */
export function handleSummary(data) {
    const metric = (name) => data.metrics[name] || { values: {} };
    const count = (name) => metric(name).values.count || 0;

    const trend = (name) => {
        const v = metric(name).values;
        return {
            avg: v.avg || 0,
            min: v.min || 0,
            med: v.med || 0,
            p90: v['p(90)'] || 0,
            p95: v['p(95)'] || 0,
            p99: v['p(99)'] || 0,
            max: v.max || 0,
        };
    };

    const profiles = {};
    for (const p of PROFILES) {
        const requests = count(`req_${p.name}`);
        profiles[p.name] = {
            expect: p.expect,
            requests,
            blocked: count(`blk_${p.name}`),
            block_rate: requests > 0 ? (count(`blk_${p.name}`) / requests) * 100 : 0,
            eval_us: trend(`evalus_${p.name}`),
        };
    }

    const httpReqs = count('http_reqs');
    const durationMs = (data.state && data.state.testRunDurationMs) || 0;

    const summary = {
        scenario: SCENARIO,
        config: {
            vus: VUS,
            duration: DURATION,
            ramp: RAMP,
            target: TARGET,
            ip_pool_size: IP_POOL.length,
        },
        run: {
            duration_ms: durationMs,
            http_reqs: httpReqs,
            // Averaged over the whole run including ramp-up, so it understates
            // steady-state throughput. Consistent across scenarios, which is
            // what makes the comparison valid.
            rps: durationMs > 0 ? httpReqs / (durationMs / 1000) : 0,
            http_req_failed_rate: (metric('http_req_failed').values.rate || 0) * 100,
            no_response: count('fw_no_response'),
        },
        outcomes: {
            allow: count('fw_outcome_allow'),
            block: count('fw_outcome_block'),
            challenge: count('fw_outcome_challenge'),
            error: count('fw_outcome_error'),
        },
        latency: {
            // End to end, as the client sees it.
            http_req_duration_ms: trend('http_req_duration'),
            // The firewall's own decision time, in microseconds.
            fw_eval_us: trend('fw_eval_us'),
            // Firewall::create() — config parse and plugin wiring.
            fw_boot_us: trend('fw_boot_us'),
            // Whole PHP request, in microseconds.
            fw_total_us: trend('fw_total_us'),
        },
        memory: {
            peak_kb: trend('fw_mem_kb'),
        },
        profiles,
    };

    const out = {};
    out[`${RESULTS_DIR}/${SCENARIO}.json`] = JSON.stringify(summary, null, 2);
    // Keep a short human-readable line on stdout so `docker compose logs`
    // during a long run is not silent for twenty minutes.
    out.stdout =
        `\n[${SCENARIO}] ${httpReqs} reqs, ` +
        `${summary.run.rps.toFixed(1)} rps, ` +
        `p95 ${summary.latency.http_req_duration_ms.p95.toFixed(1)}ms end-to-end, ` +
        `p95 ${(summary.latency.fw_eval_us.p95 / 1000).toFixed(2)}ms in firewall, ` +
        `${summary.outcomes.block} blocked, ${summary.outcomes.error} errors, ` +
        `${summary.run.no_response} no-response\n`;

    return out;
}
