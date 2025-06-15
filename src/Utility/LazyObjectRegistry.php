<?php

namespace Kanopi\Firewall\Utility;

/**
 * LazyObjectRegistry used for loading items.
 *
 * Created as a way to lazy load objects and not create a new instanced until needed.
 */
class LazyObjectRegistry
{
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

        usort($this->entries, fn($a, $b) =>
            $a['priority'] <=> $b['priority']);
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
                $entry['instance'] = ($entry['factory'])();
            }

            yield $entry['name'] => $entry['instance'];
        }
    }
}
