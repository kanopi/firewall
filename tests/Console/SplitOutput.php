<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Console;

use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\ConsoleSectionOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

/**
 * stdout and stderr kept apart in memory, as a terminal keeps them apart (#289).
 *
 * The commands write what a caller parses to stdout and everything else to stderr, and the
 * tests assert both, so the two cannot be captured as one.
 */
final class SplitOutput extends StreamOutput implements ConsoleOutputInterface
{
    private OutputInterface $stderr;

    /**
     * @var array<int, ConsoleSectionOutput>
     */
    private array $sections = [];

    public function __construct()
    {
        parent::__construct(self::memory(), OutputInterface::VERBOSITY_NORMAL, false);

        $this->stderr = new StreamOutput(self::memory(), OutputInterface::VERBOSITY_NORMAL, false);
    }

    public function getErrorOutput(): OutputInterface
    {
        return $this->stderr;
    }

    public function setErrorOutput(OutputInterface $error): void
    {
        $this->stderr = $error;
    }

    public function section(): ConsoleSectionOutput
    {
        return new ConsoleSectionOutput($this->getStream(), $this->sections, $this->getVerbosity(), $this->isDecorated(), $this->getFormatter());
    }

    /**
     * What was written to stdout.
     */
    public function stdout(): string
    {
        return self::read($this);
    }

    /**
     * What was written to stderr.
     */
    public function stderr(): string
    {
        return $this->stderr instanceof StreamOutput ? self::read($this->stderr) : '';
    }

    /**
     * @return resource
     */
    private static function memory()
    {
        $stream = fopen('php://memory', 'w+');
        assert(is_resource($stream));

        return $stream;
    }

    private static function read(StreamOutput $output): string
    {
        $stream = $output->getStream();
        rewind($stream);

        return (string) stream_get_contents($stream);
    }
}
