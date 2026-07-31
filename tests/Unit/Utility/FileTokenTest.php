<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\TokenSubstitute;

/**
 * The `%file(/path)%` token (#116).
 *
 * Every other route to a file's contents runs through an environment variable,
 * because `$var` in an `%env(...)%` chain is always the last colon-separated
 * segment. That left `%env(file:default:/path:UNUSED)%` as the only way to use
 * a path known up front — a form that depends on a variable never being
 * defined, and truncates on any path containing a colon.
 *
 * These tests cover the new token, and pin the two hazards it removes.
 */
final class FileTokenTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/fw-file-token-' . uniqid('', true);
        mkdir($this->dir, 0777, true);
        mkdir($this->dir . '/sec:rets', 0777, true);

        file_put_contents($this->dir . '/hmac.key', "literal-secret\n");
        file_put_contents($this->dir . '/sec:rets/x.txt', 'colon-ok');

        TokenSubstitute::resetUnsafeProcessors();
    }

    protected function tearDown(): void
    {
        TokenSubstitute::resetUnsafeProcessors();

        foreach ([$this->dir . '/sec:rets/x.txt', $this->dir . '/hmac.key'] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir . '/sec:rets');
        @rmdir($this->dir);

        parent::tearDown();
    }

    private function optIn(): void
    {
        TokenSubstitute::enableUnsafeProcessors(['file'], [$this->dir]);
    }

    // -----------------------------------------------------------------------
    // Safety
    // -----------------------------------------------------------------------

    /**
     * The new form must not be a way around the opt-in.
     */
    public function testReadingIsRefusedWithoutOptingIn(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('disabled');

        TokenSubstitute::substitute('%file(' . $this->dir . '/hmac.key)%');
    }

    public function testPathOutsideTheAllowlistIsRefused(): void
    {
        $this->optIn();

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('escapes the configured allowlist');

        TokenSubstitute::substitute('%file(/etc/passwd)%');
    }

    public function testTraversalOutOfTheAllowlistIsRefused(): void
    {
        $this->optIn();

        $this->expectException(ConfigurationException::class);

        TokenSubstitute::substitute('%file(' . $this->dir . '/../../../../etc/passwd)%');
    }

    public function testMissingFileRaisesRatherThanReturningEmpty(): void
    {
        $this->optIn();

        $this->expectException(ConfigurationException::class);

        TokenSubstitute::substitute('%file(' . $this->dir . '/nope.key)%');
    }

    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    public function testReadsAFileFromALiteralPath(): void
    {
        $this->optIn();

        $this->assertSame(
            "literal-secret\n",
            TokenSubstitute::substitute('%file(' . $this->dir . '/hmac.key)%'),
        );
    }

    /**
     * Contents come back verbatim, newline included, matching the `file:`
     * processor. Documented because a secret carrying a stray newline fails in
     * a way that is annoying to diagnose.
     */
    public function testContentsAreReturnedVerbatim(): void
    {
        $this->optIn();

        $value = TokenSubstitute::substitute('%file(' . $this->dir . '/hmac.key)%');

        $this->assertStringEndsWith("\n", is_string($value) ? $value : '');
    }

    /**
     * The hazard this token exists to remove. `%env(file:default:…)%` splits on
     * `:` and truncates the path; the whole token content is the path here.
     */
    public function testAPathContainingAColonWorks(): void
    {
        $this->optIn();

        $this->assertSame(
            'colon-ok',
            TokenSubstitute::substitute('%file(' . $this->dir . '/sec:rets/x.txt)%'),
        );
    }

    /**
     * And the same path through the old form still fails, so the test is
     * measuring a real difference rather than a coincidence.
     */
    public function testTheOldFormStillTruncatesOnAColon(): void
    {
        $this->optIn();

        $this->expectException(ConfigurationException::class);

        TokenSubstitute::substitute('%env(file:default:' . $this->dir . '/sec:rets/x.txt:UNSET_VAR_FOR_TEST)%');
    }

    /**
     * There is no variable to keep undefined, so nothing in the environment can
     * redirect the read.
     */
    public function testNoEnvironmentVariableCanRedirectTheRead(): void
    {
        $this->optIn();
        putenv('UNUSED=/etc/passwd');

        try {
            $this->assertSame(
                "literal-secret\n",
                TokenSubstitute::substitute('%file(' . $this->dir . '/hmac.key)%'),
            );
        } finally {
            putenv('UNUSED');
        }
    }

    // -----------------------------------------------------------------------
    // Interpolation and coexistence
    // -----------------------------------------------------------------------

    public function testInterpolatesWithinALargerString(): void
    {
        $this->optIn();

        $this->assertSame(
            "key=[literal-secret\n]",
            TokenSubstitute::substitute('key=[%file(' . $this->dir . '/hmac.key)%]'),
        );
    }

    public function testResolvesInsideNestedArrays(): void
    {
        $this->optIn();

        $resolved = TokenSubstitute::substitute([
            'challenge' => ['secret' => '%file(' . $this->dir . '/hmac.key)%'],
        ]);

        $this->assertSame("literal-secret\n", $resolved['challenge']['secret']);
    }

    /**
     * The existing token form must be untouched by the new one.
     */
    public function testEnvTokensStillResolveAlongside(): void
    {
        $this->optIn();
        putenv('FW_TOKEN_TEST_PATH=' . $this->dir . '/hmac.key');

        try {
            $this->assertSame(
                "literal-secret\n",
                TokenSubstitute::substitute('%env(file:FW_TOKEN_TEST_PATH)%'),
            );
            $this->assertSame(
                'x-' . $this->dir . '/hmac.key',
                TokenSubstitute::substitute('x-%env(FW_TOKEN_TEST_PATH)%'),
            );
        } finally {
            putenv('FW_TOKEN_TEST_PATH');
        }
    }

    public function testBothTokenFormsCanAppearInOneString(): void
    {
        $this->optIn();
        putenv('FW_TOKEN_TEST_NAME=alpha');

        try {
            $this->assertSame(
                "alpha:literal-secret\n",
                TokenSubstitute::substitute(
                    '%env(FW_TOKEN_TEST_NAME)%:%file(' . $this->dir . '/hmac.key)%',
                ),
            );
        } finally {
            putenv('FW_TOKEN_TEST_NAME');
        }
    }

    /**
     * A string with no tokens must come back untouched — including one that
     * merely looks tokenish.
     */
    public function testUnrelatedStringsAreLeftAlone(): void
    {
        $this->optIn();

        $this->assertSame('100%', TokenSubstitute::substitute('100%'));
        $this->assertSame('%file%', TokenSubstitute::substitute('%file%'));
        $this->assertSame('file(/x)', TokenSubstitute::substitute('file(/x)'));
    }
}
