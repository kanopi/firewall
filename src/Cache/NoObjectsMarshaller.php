<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Cache;

use Symfony\Component\Cache\Marshaller\MarshallerInterface;

/**
 * Serialise cache values, and refuse to hand back an object.
 *
 * Symfony's `DefaultMarshaller` unserialises with `allowed_classes => true`, so a value
 * read back from a shared store may be any object at all -- and whatever can write to that
 * store chooses which. For a filesystem pool that is this host; for a Memcached or Redis
 * pool it is anything that can reach the server.
 *
 * Nothing this library caches is an object: verdicts are booleans, GeoIP values are
 * scalars (`docs/plugins/geolocation.md#only-scalars-are-cached`), rate-limit windows are
 * lists of integers, and device-detector's corpus is arrays of strings. So the pools built
 * from a DSN are given this, and a value that would unserialise into an object is refused
 * as a miss instead (CWE-502, the same line the storage backends hold with JSON).
 */
final class NoObjectsMarshaller implements MarshallerInterface
{
    /**
     * {@inheritdoc}
     *
     * @param-out array<int, int|string> $failed
     */
    public function marshall(array $values, ?array &$failed): array
    {
        $serialized = [];
        $failed = [];

        foreach ($values as $id => $value) {
            try {
                $serialized[$id] = serialize($value);
            } catch (\Throwable) {
                // A closure, or anything else PHP refuses to serialise. Reported
                // to the adapter as a failed write, the way DefaultMarshaller does.
                $failed[] = $id;
            }
        }

        return $serialized;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException
     *   For anything that is not a serialised object-free value. The adapter logs it and
     *   answers with a miss.
     */
    public function unmarshall(string $value): mixed
    {
        // `false` serialises to this, and unserialize() returning false is
        // otherwise also how it reports a failure.
        if ($value === 'b:0;') {
            return false;
        }

        $unserialized = @unserialize($value, ['allowed_classes' => false]);

        if ($unserialized === false) {
            throw new \UnexpectedValueException('A cached value could not be unserialised.');
        }

        // allowed_classes stops a class being instantiated; it still returns
        // __PHP_Incomplete_Class in its place. Refused rather than returned,
        // because no caller here expects an object of any kind.
        if ($this->containsObject($unserialized)) {
            throw new \UnexpectedValueException('A cached value held an object, which nothing in this library caches.');
        }

        return $unserialized;
    }

    /**
     * Is there an object anywhere in this value?
     */
    private function containsObject(mixed $value): bool
    {
        if (is_object($value)) {
            return true;
        }

        if (!is_array($value)) {
            return false;
        }

        foreach ($value as $item) {
            if ($this->containsObject($item)) {
                return true;
            }
        }

        return false;
    }
}
