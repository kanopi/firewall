<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Console;

use Kanopi\Firewall\Console\Application;
use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The `firewall` application itself (#289): what it lists, and the two Console defaults it
 * changes.
 */
final class ApplicationTest extends AbstractTestCase
{
    use RunsFirewallCommands;

    public function testItIsNamedAndVersioned(): void
    {
        $application = new Application();

        $this->assertSame('firewall', $application->getName());
        $this->assertNotSame('', $application->getVersion());
    }

    /**
     * An unknown command exits 2, as the dispatcher before it did, not Console's 1.
     */
    public function testAnUnknownCommandExitsTwo(): void
    {
        $result = $this->runFirewall('nope', []);

        $this->assertSame(2, $result['code']);
        $this->assertSame('', $result['stdout']);
        $this->assertStringContainsString('Command "nope" is not defined.', $result['stderr']);
    }

    /**
     * Console's global --quiet is gone: a command's own --quiet keeps the output it asks
     * for, and an option the command does not have is an error, not a silenced run.
     */
    public function testQuietIsTheCommandsOwn(): void
    {
        $config = sys_get_temp_dir() . '/fw-app-' . uniqid('', true) . '.yml';
        file_put_contents($config, "global:\n  mode: log\n");

        try {
            $doctor = $this->runFirewall('doctor', [$config, '--quiet']);
            $init = $this->runFirewall('init', ['--quiet', '--print']);
        } finally {
            unlink($config);
        }

        $this->assertStringContainsString('error', $doctor['stdout'], 'doctor --quiet still prints its summary');
        $this->assertSame(2, $init['code']);
        $this->assertStringContainsString('The "--quiet" option does not exist.', $init['stderr']);
    }

    /**
     * -q is not --quiet's shortcut any more, so it is unknown too.
     */
    public function testTheShortQuietIsNotAnOption(): void
    {
        $result = $this->runFirewall('init', ['-q', '--print']);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('The "-q" option does not exist.', $result['stderr']);
    }
}
