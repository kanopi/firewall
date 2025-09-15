<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * LazyObjectRegistry used for loading items.
 *
 * Created as a way to lazy load objects and not create a new instanced until needed.
 */
class LazyObjectRegistry
{
    use LoggingTrait;

    /**
     * @var array<int, array{name: string, priority: int, factory: callable, instance?: object}>
     */
    protected array $entries = [];

    /**
     * Add element to the list of entries.
     *
     * @param string $name
     *   Name of the element to add.
     * @param callable $factory
     *   Callable function to use when initialized.
     * @param int $priority
     *   Priority of the class, used for ordering.
     */
    public function add(string $name, callable $factory, int $priority = 0): void
    {
        $this->entries[] = [
            'name' => $name,
            'priority' => $priority,
            'factory' => $factory,
        ];

        usort($this->entries, fn(array $a, array $b): int =>
            $a['priority'] <=> $b['priority']);

        $this->getLogger()->debug('Object registered in lazy registry', [
            'name' => $name,
            'priority' => $priority,
            'total_entries' => count($this->entries),
        ]);
    }

    /**
     * Return an iterator.
     *
     * @return \Generator
     *   Return the list of the plugins in order.
     */
    public function getIterator(): \Generator
    {
        foreach ($this->entries as &$entry) {
            if (!isset($entry['instance'])) {
                $this->getLogger()->debug('Lazy loading object', [
                    'name' => $entry['name'],
                    'priority' => $entry['priority'],
                ]);

                try {
                    $entry['instance'] = ($entry['factory'])();

                    $this->getLogger()->debug('Object loaded successfully', [
                        'name' => $entry['name'],
                        /** @phpstan-ignore classConstant.nonObject */
                        'class' => $entry['instance']::class,
                    ]);
                } catch (\Exception $e) {
                    $entry['instance'] = null;
                    $this->getLogger()->error('Failed to load object', [
                        'name' => $entry['name'],
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            yield $entry['name'] => $entry['instance'];
        }
    }

    /**
     * Return the count of entires.
     *
     * @return int
     *   Total entries.
     */
    public function getCount(): int
    {
        return count($this->entries);
    }
}
