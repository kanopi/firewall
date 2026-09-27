<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Storage\BestEffortEnumerationInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * A queryable storage that reports a gap in its enumeration, chosen by config.
 *
 * `MemcachedStorage` is the shipped backend that can report one, and it needs a server and
 * an extension. What `BlockList`, `bin/firewall-block` and the doctor do with a gap does not,
 * so they are tested against this.
 *
 * `config.gap` is the sentence returned; `config.throw` makes construction fail, the way a
 * backend that cannot be built does.
 */
class GappyStorage extends InMemoryStorage implements BestEffortEnumerationInterface
{
    public function __construct(array $config = [])
    {
        if (($config['throw'] ?? false) === true) {
            throw new \RuntimeException('This storage refuses to be built.');
        }

        parent::__construct($config);
    }

    public function enumerationGap(): ?string
    {
        return is_string($this->config['gap'] ?? null) ? $this->config['gap'] : null;
    }
}
