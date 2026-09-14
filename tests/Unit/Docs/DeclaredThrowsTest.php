<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Docs;

use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\TestCase;

/**
 * `Firewall::evaluate()` declares every exception it can raise (#337).
 *
 * PHPStan treats `@throws` as authoritative. An exception the method really
 * raises but does not declare makes a host's correct `catch` look like dead
 * code -- `catch.neverThrown` -- and the advice that error gives is to delete
 * it. Following it means `response: redirect` silently stops redirecting,
 * while the static analysis that caused it reports success. That is how
 * `kanopi/firewall-laravel` found this.
 *
 * So this is not a style check. `evaluate()` is the one method every
 * integration calls, and its `@throws` list is the contract those integrations
 * are written against.
 *
 * ## It checks the code rather than a list
 *
 * Asserting "these six are declared" would pass forever and catch nothing: the
 * next exception added to a helper would go undeclared exactly as these two
 * did. Instead this reads the methods `evaluate()` calls, collects what
 * *they* declare, and requires `evaluate()` to declare the union -- so the
 * omission is reported by the test that exists rather than by an integrator
 * six months later.
 */
final class DeclaredThrowsTest extends TestCase
{
    /**
     * Exceptions `evaluate()` itself declares.
     *
     * @return array<int, string>
     *   Short class names, as written in the docblock.
     */
    private static function declared(): array
    {
        return self::throwsIn((string) (new \ReflectionMethod(Firewall::class, 'evaluate'))->getDocComment());
    }

    /**
     * The `@throws` tags in a docblock.
     *
     * @param string $docblock
     *   The comment.
     *
     * @return array<int, string>
     *   Short class names.
     */
    private static function throwsIn(string $docblock): array
    {
        preg_match_all('/@throws\s+\\\\?([A-Za-z0-9_\\\\]+)/', $docblock, $matches);

        return array_values(array_unique(array_map(
            static fn(string $class): string => substr((string) strrchr('\\' . $class, '\\'), 1),
            $matches[1]
        )));
    }

    /**
     * The body of one method, as source.
     *
     * @param string $method
     *   The method name.
     *
     * @return string
     *   Its lines.
     */
    private static function body(string $method): string
    {
        $reflectionMethod = new \ReflectionMethod(Firewall::class, $method);
        $lines = (array) file((string) $reflectionMethod->getFileName());

        return implode('', array_slice(
            $lines,
            (int) $reflectionMethod->getStartLine() - 1,
            (int) $reflectionMethod->getEndLine() - (int) $reflectionMethod->getStartLine() + 1
        ));
    }

    /**
     * The two that were missing, named individually.
     *
     * The generated check below would catch them, but it would also catch them
     * as part of a set, and these two have specific consequences worth keeping
     * visible: a deleted redirect catch is a redirect rule that stops
     * redirecting, and a lockdown caught on its own is how a host emits
     * `Retry-After`.
     *
     * @param string $exception
     *   The exception that must be declared.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('terminalExceptions')]
    public function testEvaluateDeclaresEveryTerminalException(string $exception): void
    {
        $this->assertContains(
            $exception,
            self::declared(),
            sprintf(
                'Firewall::evaluate() can raise %s but does not declare it, so PHPStan reports a host\'s '
                . 'correct catch as dead code and tells them to delete it.',
                $exception
            )
        );
    }

    /**
     * @return array<string, array{string}>
     *   Keyed by the exception.
     */
    public static function terminalExceptions(): array
    {
        return [
            'blocked' => ['FirewallBlockedException'],
            'lockdown' => ['FirewallLockdownException'],
            'redirect' => ['FirewallRedirectException'],
            'challenge required' => ['ChallengeRequiredException'],
            'challenge solved' => ['ChallengeSolvedException'],
            'configuration' => ['ConfigurationException'],
        ];
    }

    /**
     * Whatever the methods it calls declare, it declares.
     *
     * The check that will still be working after the next exception is added.
     * `evaluate()` catches nothing itself, so anything a helper raises leaves
     * through `evaluate()` and belongs in its contract.
     */
    public function testEvaluateDeclaresWhatItsHelpersDeclare(): void
    {
        $body = self::body('evaluate');

        $this->assertStringNotContainsString(
            'catch (',
            $body,
            'evaluate() now catches something, so this test needs to subtract what it swallows.'
        );

        preg_match_all('/\$this->([a-zA-Z0-9_]+)\(/', $body, $calls);

        $expected = [];

        foreach (array_unique($calls[1]) as $method) {
            if (!method_exists(Firewall::class, $method)) {
                continue;
            }

            $docblock = (new \ReflectionMethod(Firewall::class, $method))->getDocComment();

            if ($docblock === false) {
                continue;
            }

            foreach (self::throwsIn($docblock) as $exception) {
                $expected[$exception] = $method;
            }
        }

        $this->assertNotSame([], $expected, 'The call scan found nothing, so it is no longer checking anything.');

        $declared = self::declared();

        foreach ($expected as $exception => $method) {
            $this->assertContains(
                $exception,
                $declared,
                sprintf(
                    'Firewall::%s() declares @throws %s and is called from evaluate(), which does not '
                    . 'declare it. A host catching it is told by PHPStan that the catch is dead code.',
                    $method,
                    $exception
                )
            );
        }
    }
}
