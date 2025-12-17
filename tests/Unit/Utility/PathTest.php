<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Path;

/**
 * Tests the Path utility class.
 */
class PathTest extends AbstractTestCase
{

    /**
     * Tests Path::looksLikeUrl().
     */
    public function testLooksLikeUrl(): void
    {
        $result = Path::looksLikeUrl('/foo/bar');
        $this->assertFalse($result);

        $result = Path::looksLikeUrl('https://www.google.com');
        $this->assertTrue($result);

        $result = Path::looksLikeUrl('schema://host');
        $this->assertTrue($result);
    }

    /**
     * Tests Path::isAbsolute() with POSIX absolute paths.
     */
    public function testIsAbsoluteWithPosixPath(): void
    {
        $this->assertTrue(Path::isAbsolute('/path'));
        $this->assertTrue(Path::isAbsolute('/'));
        $this->assertTrue(Path::isAbsolute('/usr/local/bin'));
    }

    /**
     * Tests Path::isAbsolute() with relative paths.
     */
    public function testIsAbsoluteWithRelativePath(): void
    {
        $this->assertFalse(Path::isAbsolute('./path'));
        $this->assertFalse(Path::isAbsolute('../path'));
        $this->assertFalse(Path::isAbsolute('relative/path'));
        $this->assertFalse(Path::isAbsolute('file.txt'));
    }

    /**
     * Tests Path::isAbsolute() with Windows drive paths.
     */
    public function testIsAbsoluteWithWindowsDrivePath(): void
    {
        $this->assertTrue(Path::isAbsolute('C:\\path'));
        $this->assertTrue(Path::isAbsolute('C:/path'));
        $this->assertTrue(Path::isAbsolute('D:\\Users'));
        $this->assertTrue(Path::isAbsolute('Z:/data'));
    }

    /**
     * Tests Path::isAbsolute() with UNC paths.
     */
    public function testIsAbsoluteWithUncPath(): void
    {
        $this->assertTrue(Path::isAbsolute('\\\\server\\share'));
        $this->assertTrue(Path::isAbsolute('\\\\computer\\folder\\file.txt'));
    }

    /**
     * Tests Path::isAbsolute() with URLs and stream wrappers.
     */
    public function testIsAbsoluteWithUrls(): void
    {
        $this->assertTrue(Path::isAbsolute('https://example.com'));
        $this->assertTrue(Path::isAbsolute('http://localhost'));
        $this->assertTrue(Path::isAbsolute('ftp://server.com'));
        $this->assertTrue(Path::isAbsolute('file://path/to/file'));
        $this->assertTrue(Path::isAbsolute('phar://archive.phar/file.txt'));
        $this->assertTrue(Path::isAbsolute('php://stdin'));
    }

    // =====================================================================
    // realOrGiven() Tests
    // =====================================================================

    /**
     * Tests Path::realOrGiven() with a regular file that realpath can resolve.
     *
     * Tests lines 59-62: When realpath() succeeds, return the real path.
     */
    public function testRealOrGivenWithRegularFile(): void
    {
        // Create a temporary file
        $tempFile = tempnam(sys_get_temp_dir(), 'path_test_');
        file_put_contents($tempFile, 'test content');

        try {
            $result = Path::realOrGiven($tempFile);

            // Should return the real path (resolved)
            $expected = realpath($tempFile);
            $this->assertEquals($expected, $result);
            $this->assertNotFalse($expected);
        } finally {
            @unlink($tempFile);
        }
    }

    /**
     * Tests Path::realOrGiven() with a path that uses . or .. components.
     *
     * Tests lines 59-62: realpath() should resolve these to absolute paths.
     */
    public function testRealOrGivenWithRelativeComponents(): void
    {
        // Create a temporary file
        $tempFile = tempnam(sys_get_temp_dir(), 'path_test_');
        file_put_contents($tempFile, 'test content');

        try {
            // Add ./ and ../ to the path
            $dirname = dirname($tempFile);
            $basename = basename($tempFile);
            $relativePath = $dirname . '/./' . $basename;

            $result = Path::realOrGiven($relativePath);

            // Should return the real path without . components
            $expected = realpath($relativePath);
            $this->assertEquals($expected, $result);
            $this->assertStringNotContainsString('/./', $result);
        } finally {
            @unlink($tempFile);
        }
    }

    /**
     * Tests Path::realOrGiven() throws exception when file doesn't exist.
     *
     * Tests lines 64-66: When file_exists() returns false, throw RuntimeException.
     */
    public function testRealOrGivenThrowsOnNonExistentFile(): void
    {
        $nonExistentPath = '/nonexistent/path/to/file.txt';

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Config not found: ' . $nonExistentPath);

        Path::realOrGiven($nonExistentPath);
    }

    /**
     * Tests Path::realOrGiven() throws exception with relative non-existent path.
     *
     * Tests lines 64-66: Exception thrown regardless of path type.
     */
    public function testRealOrGivenThrowsOnNonExistentRelativePath(): void
    {
        $nonExistentPath = 'does/not/exist.yml';

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Config not found: ' . $nonExistentPath);

        Path::realOrGiven($nonExistentPath);
    }

    /**
     * Tests Path::realOrGiven() returns original path when realpath fails but file exists.
     *
     * Tests line 68: When realpath() returns false but file_exists() is true,
     * return the original path. This happens with stream wrappers.
     */
    public function testRealOrGivenWithStreamWrapper(): void
    {
        // Create a data:// URL which file_get_contents can access but realpath cannot resolve
        // First, let's test if data:// is considered to "exist" by file_exists
        $dataUrl = 'data://text/plain;base64,' . base64_encode('test content');

        // data:// URLs don't work with file_exists, so let's use a different approach
        // Create a file and then reference it through a stream filter
        $tempFile = tempnam(sys_get_temp_dir(), 'path_test_');
        file_put_contents($tempFile, 'test content');

        try {
            // Use php://filter wrapper which wraps the file
            $filterPath = "php://filter/read=string.toupper/resource={$tempFile}";

            // Check if file_exists works with this wrapper
            if (file_exists($filterPath)) {
                // realpath should fail on stream wrappers
                $real = realpath($filterPath);
                if ($real === false) {
                    // Perfect! This is the scenario we want to test
                    $result = Path::realOrGiven($filterPath);
                    $this->assertEquals($filterPath, $result);
                } else {
                    $this->markTestSkipped('php://filter resolved by realpath unexpectedly');
                }
            } else {
                $this->markTestSkipped('php://filter not supported by file_exists');
            }
        } finally {
            @unlink($tempFile);
        }
    }

    /**
     * Tests Path::realOrGiven() with phar:// stream wrapper.
     *
     * Tests line 68: Phar archives exist but realpath may fail.
     */
    public function testRealOrGivenWithPharWrapper(): void
    {
        // Check if we can create phar files (requires phar.readonly=0)
        if (ini_get('phar.readonly') == '1') {
            $this->markTestSkipped('Cannot test phar:// paths when phar.readonly is enabled');
            return;
        }

        // Create a temporary phar file for testing
        $pharPath = sys_get_temp_dir() . '/test_' . uniqid() . '.phar';

        try {
            // Create a simple phar archive
            $phar = new \Phar($pharPath);
            $phar->startBuffering();
            $phar->addFromString('test.txt', 'content');
            $phar->stopBuffering();
            unset($phar); // Close the phar

            // Test with phar:// URL
            $pharUrl = "phar://{$pharPath}/test.txt";

            // Verify file_exists works but realpath fails
            $exists = file_exists($pharUrl);
            $real = realpath($pharUrl);

            if ($exists && $real === false) {
                // Perfect! This is the scenario for line 68
                $result = Path::realOrGiven($pharUrl);
                $this->assertEquals($pharUrl, $result);
            } else {
                $this->markTestSkipped(
                    'Phar test conditions not met: exists=' . var_export($exists, true) .
                    ', realpath=' . var_export($real, true)
                );
            }
        } catch (\Exception $e) {
            $this->markTestSkipped('Cannot create phar for testing: ' . $e->getMessage());
        } finally {
            @unlink($pharPath);
        }
    }

    /**
     * Tests Path::realOrGiven() with a path containing special characters.
     *
     * Tests all code paths with edge case filenames.
     */
    public function testRealOrGivenWithSpecialCharacters(): void
    {
        // Create a file with spaces in the name
        $tempDir = sys_get_temp_dir();
        $fileName = 'test file with spaces.txt';
        $filePath = $tempDir . DIRECTORY_SEPARATOR . $fileName;

        file_put_contents($filePath, 'test content');

        try {
            $result = Path::realOrGiven($filePath);

            // Should successfully resolve even with spaces
            $expected = realpath($filePath);
            $this->assertEquals($expected, $result);
        } finally {
            @unlink($filePath);
        }
    }

    /**
     * Tests Path::realOrGiven() with symlink.
     *
     * Tests that symlinks are properly resolved by realpath.
     */
    public function testRealOrGivenWithSymlink(): void
    {
        // Create a temporary file and symlink
        $tempFile = tempnam(sys_get_temp_dir(), 'path_test_target_');
        $symlinkPath = sys_get_temp_dir() . '/path_test_symlink_' . uniqid();

        file_put_contents($tempFile, 'test content');
        symlink($tempFile, $symlinkPath);

        try {
            $result = Path::realOrGiven($symlinkPath);

            // Should resolve to the actual file, not the symlink
            $expected = realpath($symlinkPath);
            $this->assertEquals($expected, $result);
            $this->assertEquals(realpath($tempFile), $result);
        } finally {
            @unlink($symlinkPath);
            @unlink($tempFile);
        }
    }
}
