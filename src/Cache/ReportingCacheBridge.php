<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Cache;

use DeviceDetector\Cache\PSR6Bridge;
use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * device-detector's PSR-6 bridge, reporting a write the pool refused (#394).
 *
 * `UserAgent::cacheIsUsable()` proves a pool with a probe value of a few bytes. The
 * entries device-detector writes are not a few bytes: against Memcached 1.6.41 the
 * largest was about 1.5 MB before compression, and it fits under Memcached's default 1 MB
 * item limit only because `ext-memcached` compresses by default. With compression off, or
 * a smaller item limit, that write fails -- and the probe, having passed, says nothing.
 * Every request then pays the full parse, about 250 ms against 14 ms warm.
 *
 * So a failed write is reported here, once per plugin instance: the first one says what
 * is wrong, and the rest would only repeat it.
 */
class ReportingCacheBridge extends PSR6Bridge
{
    use LoggingTrait;

    /**
     * Whether a failed write has already been reported.
     */
    private bool $reported = false;

    /**
     * {@inheritdoc}
     */
    public function save(string $id, $data, int $lifeTime = 0): bool
    {
        // The argument count is passed through as it came, because the parent
        // only sets an expiry when a lifetime was given at all.
        $saved = func_num_args() > 2 ? parent::save($id, $data, $lifeTime) : parent::save($id, $data);

        if (!$saved && !$this->reported) {
            $this->reported = true;

            $this->getLogger()->warning('User Agent regex cache refused a write - detection will re-parse what it could not store', [
                'entry' => $id,
                'bytes' => strlen(serialize($data)),
                'impact' => 'Roughly 250ms per request instead of ~15ms, for as long as the write keeps failing.',
                'hint' => 'On Memcached, keep compression on and the item size limit (-I) at 2m or more; '
                    . 'or use a filesystem or Redis pool.',
            ]);
        }

        return $saved;
    }
}
