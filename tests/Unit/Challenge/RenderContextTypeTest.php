<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use PHPUnit\Framework\TestCase;

/**
 * The render context is typed the same everywhere it is handed over (#442).
 *
 * `ChallengeRequiredException` declared `array<string, string>` while the context it
 * carries has held a list, `notices`, since 2.35 -- and the provider interface it is passed
 * to already said `array<string, mixed>`. Static analysis trusts the docblock, so a host
 * reading `notices` correctly was told its `is_array()` check could never be true. A
 * docblock is not checked at runtime, so this checks it here.
 */
final class RenderContextTypeTest extends TestCase
{
    private static function declared(string $docComment, string $tag, ?string $variable = null): ?string
    {
        // A generic type such as `array<string, mixed>` has a space in it.
        $type = '([A-Za-z_\\\\|]+<[^>]*>|\S+)';
        $pattern = $variable === null
            ? '/@' . $tag . '\s+' . $type . '/'
            : '/@' . $tag . '\s+' . $type . '\s+\$' . $variable . '\b/';

        return preg_match($pattern, $docComment, $match) === 1 ? $match[1] : null;
    }

    public function testTheExceptionTypesTheContextAsTheInterfaceDoes(): void
    {
        $interface = self::declared(
            (string) (new \ReflectionMethod(ChallengeProviderInterface::class, 'renderInterstitial'))->getDocComment(),
            'param',
            'context'
        );

        $this->assertSame('array<string, mixed>', $interface);

        $this->assertSame($interface, self::declared(
            (string) (new \ReflectionMethod(ChallengeRequiredException::class, 'getRenderContext'))->getDocComment(),
            'return'
        ), 'getRenderContext() must return what renderInterstitial() takes.');

        $this->assertSame($interface, self::declared(
            (string) (new \ReflectionMethod(ChallengeRequiredException::class, '__construct'))->getDocComment(),
            'param',
            'renderContext'
        ), 'The constructor must accept what renderInterstitial() takes.');
    }

    /**
     * And the value really is a list where the type now says it may be.
     */
    public function testNoticesIsAList(): void
    {
        $exception = new ChallengeRequiredException('x', null, null, 'math', ['notices' => ['One.']]);

        $this->assertIsArray($exception->getRenderContext()['notices']);
    }
}
