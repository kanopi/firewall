<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Nothing leaves `Firewall::create()` as an `\Error` (#281).
 *
 * This package's error-handling guide tells integrators to catch
 * `FirewallException`, or `\Exception` at the outside. That is a promise about
 * the boundary, and until #281 it was not kept: six of the malformed configs
 * below left as a `TypeError`, from four separate places, so a host application
 * that had carefully wrapped `create()` still got a white screen.
 *
 * `plugins:` is a hand-edited YAML list. A rule written as a bare string, a
 * commented-out block leaving an orphan list item, a `weight` someone typed as
 * a word -- none of these are exotic, and none of them should be fatal in a way
 * the documented catch cannot reach.
 *
 * Written as a matrix rather than one test per defect because the point is
 * coverage of the *boundary*, not of four fixes. A malformed shape nobody
 * thought of is exactly what this is for, so add rows freely.
 */
final class MalformedConfigBoundaryTest extends AbstractTestCase
{
    /**
     * A plugin entry that is actually valid, to sit beside the broken ones.
     *
     * @return array<string, mixed>
     */
    private static function validPlugin(): array
    {
        return [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'config' => ['203.0.113.5'],
        ];
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function malformedConfigs(): array
    {
        $valid = self::validPlugin();

        return [
            // The four that produced an \Error before #281.
            'a string among the plugins' => [['plugins' => [$valid, 'a string']]],
            'a null among the plugins' => [['plugins' => [$valid, null]]],
            'an integer among the plugins' => [['plugins' => [$valid, 42]]],
            'plugins is not a list at all' => [['plugins' => 'nope']],
            'a plugin class that is not a string' => [['plugins' => [['plugin' => 123]]]],
            'storage config written as a scalar' => [['storage' => [
                'type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage',
                'config' => 'nope',
            ]]],

            // Shapes that already behaved, kept so they cannot start misbehaving.
            'a nested list among the plugins' => [['plugins' => [$valid, [['plugin' => 'x']]]]],
            'plugins keyed as a map' => [['plugins' => ['first' => $valid]]],
            'a plugin entry with no class' => [['plugins' => [['response' => 'block']]]],
            'metadata written as a scalar' => [['plugins' => [$valid + ['metadata' => 'nope']]]],
            'config written as a scalar' => [['plugins' => [['plugin' => $valid['plugin'], 'config' => 'nope']]]],
            'a weight that is a word' => [['plugins' => [$valid + ['weight' => 'heavy']]]],
            'a weight that is an array' => [['plugins' => [$valid + ['weight' => ['a']]]]],
            'an enable that is a string' => [['plugins' => [$valid + ['enable' => 'yes']]]],
            'a response that is an integer' => [['plugins' => [$valid + ['response' => 123]]]],
            'a response that is an array' => [['plugins' => [$valid + ['response' => ['block']]]]],
            'logger written as a scalar' => [['logger' => 'nope']],
            'a scalar among the log handlers' => [['logger' => ['nope']]],
            'a log handler with no class' => [['logger' => [['args' => []]]]],
            'storage written as a scalar' => [['storage' => 'nope']],
            'a storage type that is not a string' => [['storage' => ['type' => 123]]],
            'global written as a scalar' => [['global' => 'nope']],
            'challenge written as a scalar' => [['challenge' => 'nope']],
            'sources written as a scalar' => [['plugins' => [$valid + ['metadata' => ['sources' => 'nope']]]]],
            'a scalar among the sources' => [['plugins' => [$valid + ['metadata' => ['sources' => [42]]]]]],
        ];
    }

    /**
     * Whatever else it does, it does not throw an `\Error`.
     *
     * Starting is fine, and so is refusing to start with a `ConfigurationException`.
     * What is not fine is leaving through a boundary the documentation says
     * does not exist.
     *
     * @param array<string, mixed> $override
     */
    #[DataProvider('malformedConfigs')]
    public function testMalformedConfigNeverEscapesAsAnError(array $override): void
    {
        $config = array_merge(
            ['global' => ['mode' => 'exception'], 'plugins' => [self::validPlugin()]],
            $override
        );

        try {
            Firewall::create([$config]);
        } catch (\Exception) {
            // Refusing to start is a legitimate answer, and it is catchable.
        } catch (\Throwable $throwable) {
            $this->fail(sprintf(
                'Left Firewall::create() as %s, which a host catching \Exception cannot catch: %s',
                $throwable::class,
                $throwable->getMessage()
            ));
        }

        $this->assertTrue(true, 'Nothing escaped the documented boundary');
    }

    /**
     * A stray entry does not take the valid rules with it.
     *
     * Skipping is only the right behaviour if what remains still runs — the
     * alternative reading of "be lenient" is to quietly drop everything.
     */
    public function testTheValidRulesStillRunAlongsideAStrayEntry(): void
    {
        $firewall = Firewall::create([[
            'global' => ['mode' => 'exception'],
            'plugins' => [self::validPlugin(), 'a string', null],
        ]]);

        $this->assertSame([], $firewall->getFailedRules(), 'The valid rule was constructed');
    }
}
