<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Diagnostics;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * One finding, and the three statuses it can carry (#211).
 */
class DiagnosisTest extends AbstractTestCase
{
    /**
     * Each constructor carries its status, and the optional parts stay optional.
     */
    public function testEachStatusIsConstructedWithWhatItWasGiven(): void
    {
        $ok = Diagnosis::ok('Config loads', '3 rules configured');

        $this->assertSame(Diagnosis::OK, $ok->status);
        $this->assertSame('Config loads', $ok->title);
        $this->assertSame('3 rules configured', $ok->detail);
        $this->assertNull($ok->reference, 'A passing check has nothing to read about');

        $warning = Diagnosis::warning('GeoIP database is 94 days old', 'path', 'how-to/geoip-setup.md');

        $this->assertSame(Diagnosis::WARNING, $warning->status);
        $this->assertSame('how-to/geoip-setup.md', $warning->reference);

        $error = Diagnosis::error('Rule is not running', 'Connection refused', 'reference/error-handling.md');

        $this->assertSame(Diagnosis::ERROR, $error->status);
        $this->assertSame('Connection refused', $error->detail);
    }

    /**
     * A title on its own is enough.
     */
    public function testDetailAndReferenceAreOptional(): void
    {
        $finding = Diagnosis::ok('Every configured rule is running');

        $this->assertNull($finding->detail);
        $this->assertNull($finding->reference);
    }

    /**
     * The array form is what `--json` emits, so the keys are a contract.
     */
    public function testTheArrayFormCarriesEveryField(): void
    {
        $this->assertSame(
            ['status' => 'error', 'title' => 'Broken', 'detail' => 'why', 'reference' => 'docs.md'],
            Diagnosis::error('Broken', 'why', 'docs.md')->toArray()
        );

        $this->assertSame(
            ['status' => 'ok', 'title' => 'Fine', 'detail' => null, 'reference' => null],
            Diagnosis::ok('Fine')->toArray()
        );
    }
}
