<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\TokenSubstitute;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests the TokenSubstitute utility class.
 */
class TokenSubstituteTest extends AbstractTestCase
{
    private string $tempFile;
    private string $tempPhpFile;
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        // Create temporary files for testing file and require processors
        $this->tempFile = tempnam(sys_get_temp_dir(), 'token_test_');
        file_put_contents($this->tempFile, 'file content');

        $this->tempPhpFile = tempnam(sys_get_temp_dir(), 'token_php_');
        file_put_contents($this->tempPhpFile, '<?php return ["key" => "value"];');

        $this->tempDir = sys_get_temp_dir();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        @unlink($this->tempFile);
        @unlink($this->tempPhpFile);
    }

    // =====================================================================
    // Basic Functionality Tests
    // =====================================================================

    public function testSubstituteReturnsNonStringValueAsIs(): void
    {
        $this->assertSame(123, TokenSubstitute::substitute(123));
        $this->assertSame(45.67, TokenSubstitute::substitute(45.67));
        $this->assertSame(true, TokenSubstitute::substitute(true));
        $this->assertSame(false, TokenSubstitute::substitute(false));
        $this->assertSame(null, TokenSubstitute::substitute(null));
    }

    public function testSubstituteArrayRecursively(): void
    {
        putenv('VAR1=value1');
        putenv('VAR2=123');

        $config = [
            'key1' => '%env(VAR1)%',
            'key2' => '%env(int:VAR2)%',
            'nested' => [
                'key3' => '%env(VAR1)%',
            ],
        ];

        $result = TokenSubstitute::substitute($config);

        $this->assertEquals('value1', $result['key1']);
        $this->assertSame(123, $result['key2']);
        $this->assertEquals('value1', $result['nested']['key3']);
    }

    public function testSubstituteSingleTokenReturnsTypedValue(): void
    {
        putenv('INT_VAR=42');
        $result = TokenSubstitute::substitute('%env(int:INT_VAR)%');
        $this->assertSame(42, $result);
        $this->assertIsInt($result);
    }

    public function testSubstituteInterpolatedTokenReturnsString(): void
    {
        putenv('PORT=8080');
        $result = TokenSubstitute::substitute('Server running on port %env(PORT)%');
        $this->assertEquals('Server running on port 8080', $result);
        $this->assertIsString($result);
    }

    public function testSubstituteMultipleTokensInString(): void
    {
        putenv('HOST=localhost');
        putenv('PORT=3000');
        $result = TokenSubstitute::substitute('http://%env(HOST)%:%env(PORT)%');
        $this->assertEquals('http://localhost:3000', $result);
    }

    public function testSubstituteNoTokensReturnsOriginalString(): void
    {
        $result = TokenSubstitute::substitute('plain string');
        $this->assertEquals('plain string', $result);
    }

    // =====================================================================
    // String Processor Tests
    // =====================================================================

    public function testStringProcessor(): void
    {
        putenv('STR_VAR=hello');
        $result = TokenSubstitute::substitute('%env(string:STR_VAR)%');
        $this->assertSame('hello', $result);
        $this->assertIsString($result);
    }

    // =====================================================================
    // Int Processor Tests
    // =====================================================================

    public function testIntProcessor(): void
    {
        putenv('INT_VAR=42');
        $result = TokenSubstitute::substitute('%env(int:INT_VAR)%');
        $this->assertSame(42, $result);
    }

    public function testIntProcessorWithNegative(): void
    {
        putenv('NEG_INT=-99');
        $result = TokenSubstitute::substitute('%env(int:NEG_INT)%');
        $this->assertSame(-99, $result);
    }

    public function testIntProcessorThrowsOnNonNumeric(): void
    {
        putenv('NOT_INT=abc');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        TokenSubstitute::substitute('%env(int:NOT_INT)%');
    }

    // =====================================================================
    // Float Processor Tests
    // =====================================================================

    public function testFloatProcessor(): void
    {
        putenv('FLOAT_VAR=3.14');
        $result = TokenSubstitute::substitute('%env(float:FLOAT_VAR)%');
        $this->assertSame(3.14, $result);
    }

    public function testFloatProcessorWithInteger(): void
    {
        putenv('FLOAT_INT=42');
        $result = TokenSubstitute::substitute('%env(float:FLOAT_INT)%');
        $this->assertSame(42.0, $result);
    }

    public function testFloatProcessorThrowsOnNonNumeric(): void
    {
        putenv('NOT_FLOAT=xyz');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        TokenSubstitute::substitute('%env(float:NOT_FLOAT)%');
    }

    // =====================================================================
    // Bool Processor Tests
    // =====================================================================

    #[DataProvider('boolTruthyProvider')]
    public function testBoolProcessorTruthy(string $value): void
    {
        putenv("BOOL_VAR={$value}");
        $result = TokenSubstitute::substitute('%env(bool:BOOL_VAR)%');
        $this->assertTrue($result);
    }

    public static function boolTruthyProvider(): array
    {
        return [
            ['1'],
            ['true'],
            ['TRUE'],
            ['yes'],
            ['YES'],
            ['on'],
            ['ON'],
        ];
    }

    #[DataProvider('boolFalseyProvider')]
    public function testBoolProcessorFalsey(string $value): void
    {
        putenv("BOOL_VAR={$value}");
        $result = TokenSubstitute::substitute('%env(bool:BOOL_VAR)%');
        $this->assertFalse($result);
    }

    public static function boolFalseyProvider(): array
    {
        return [
            ['0'],
            ['false'],
            ['FALSE'],
            ['no'],
            ['NO'],
            ['off'],
            ['OFF'],
            [''],
        ];
    }

    public function testBoolProcessorThrowsOnInvalidValue(): void
    {
        putenv('WEIRD_BOOL=maybe');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cannot cast');
        TokenSubstitute::substitute('%env(bool:WEIRD_BOOL)%');
    }

    // =====================================================================
    // Not Processor Tests
    // =====================================================================

    public function testNotProcessorWithTruthy(): void
    {
        putenv('NOT_VAR=true');
        $result = TokenSubstitute::substitute('%env(not:NOT_VAR)%');
        $this->assertFalse($result);
    }

    public function testNotProcessorWithNumericPositive(): void
    {
        putenv('NOT_VAR=5');
        $result = TokenSubstitute::substitute('%env(not:NOT_VAR)%');
        $this->assertFalse($result);
    }

    public function testNotProcessorWithFalsey(): void
    {
        putenv('NOT_VAR=0');
        $result = TokenSubstitute::substitute('%env(not:NOT_VAR)%');
        $this->assertTrue($result);
    }

    public function testNotProcessorWithEmptyString(): void
    {
        putenv('NOT_VAR=');
        $result = TokenSubstitute::substitute('%env(not:NOT_VAR)%');
        $this->assertTrue($result);
    }

    // =====================================================================
    // JSON Processor Tests
    // =====================================================================

    public function testJsonProcessorDecodeString(): void
    {
        putenv('JSON_VAR={"key":"value","number":42}');
        $result = TokenSubstitute::substitute('%env(json:JSON_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals('value', $result['key']);
        $this->assertEquals(42, $result['number']);
    }

    public function testJsonProcessorDecodeArray(): void
    {
        putenv('JSON_ARRAY=[1,2,3]');
        $result = TokenSubstitute::substitute('%env(json:JSON_ARRAY)%');
        $this->assertIsArray($result);
        $this->assertEquals([1, 2, 3], $result);
    }

    public function testJsonProcessorThrowsOnInvalidJson(): void
    {
        putenv('BAD_JSON={oops]');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid JSON');
        TokenSubstitute::substitute('%env(json:BAD_JSON)%');
    }

    public function testJsonProcessorArrayToJsonString(): void
    {
        // Test the array->JSON encoding path (line 213-220)
        // This happens when an array is passed to json processor (e.g., from csv)
        putenv('JSON_VAR=one,two,three');
        $result = TokenSubstitute::substitute('%env(csv:json:JSON_VAR)%');
        $this->assertIsString($result);
        $decoded = json_decode($result, true);
        $this->assertEquals(['one', 'two', 'three'], $decoded);
    }

    public function testJsonProcessorThrowsOnEncodeFailure(): void
    {
        // Test json_encode failure (line 216)
        // json_encode can fail with deeply nested arrays or invalid UTF-8
        // Create a recursive reference which causes json_encode to fail
        $tempFile = tempnam(sys_get_temp_dir(), 'json_test_');

        // Create a PHP file that returns an array with invalid UTF-8
        $phpCode = '<?php return ["invalid" => "\xFF\xFE"];';
        file_put_contents($tempFile, $phpCode);

        try {
            putenv("JSON_VAR={$tempFile}");
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('Failed to encode array to JSON');
            // This will require the file, get an array, then try to json:encode it
            TokenSubstitute::substitute('%env(require:json:JSON_VAR)%');
        } finally {
            @unlink($tempFile);
        }
    }

    // =====================================================================
    // Base64 Processor Tests
    // =====================================================================

    public function testBase64ProcessorDecode(): void
    {
        $encoded = base64_encode('secret');
        putenv("B64_VAR={$encoded}");
        $result = TokenSubstitute::substitute('%env(base64:B64_VAR)%');
        $this->assertEquals('secret', $result);
    }

    public function testBase64ProcessorEncode(): void
    {
        $encoded = base64_encode('secret');
        putenv("B64_VAR=secret");
        $result = TokenSubstitute::substitute('%env(base64:B64_VAR)%');
        $this->assertEquals($encoded, $result);
    }

    public function testJsonProcessorEncodeArray(): void
    {
        // Test json encoding an array (from csv processor)
        putenv('JSON_VAR=one,two,three');
        $result = TokenSubstitute::substitute('%env(csv:json:JSON_VAR)%');
        $this->assertIsString($result);
        $this->assertJson($result);
        $decoded = json_decode($result, true);
        $this->assertEquals(['one', 'two', 'three'], $decoded);
    }

    public function testCsvProcessorArrayToString(): void
    {
        // Test CSV converting array back to string
        putenv('CSV_VAR=[1,2,3]');
        $result = TokenSubstitute::substitute('%env(json:csv:CSV_VAR)%');
        $this->assertEquals('1,2,3', $result);
    }

    public function testBase64ProcessorThrowsOnInvalidBase64(): void
    {
        putenv('B64_VAR=!!!invalid!!!');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to base64 decode');
        TokenSubstitute::substitute('%env(base64:B64_VAR)%');
    }

    public function testBase64ProcessorDecodesToEncode(): void
    {
        // Test the second base64_decode check (line 237) and the encode path (line 239)
        // Use a string with valid base64 characters that can be decoded but isn't actually base64
        // The string 'test' can be decoded (all valid chars) but encode(decode('test')) != 'test'
        $testString = 'notbase64';
        putenv("B64_VAR={$testString}");

        // First check: can it be decoded? (line 228-230)
        $decoded = base64_decode($testString, true);

        if ($decoded === false) {
            // Will fail the first check and throw exception
            $this->expectException(\RuntimeException::class);
            TokenSubstitute::substitute('%env(base64:B64_VAR)%');
        } else {
            // Passes first check, now check if it's valid base64 (line 233-234)
            $reencoded = base64_encode($decoded);
            if ($reencoded === $testString) {
                // It IS valid base64, so decode it (line 235-238)
                $result = TokenSubstitute::substitute('%env(base64:B64_VAR)%');
                $this->assertEquals($decoded, $result);
            } else {
                // It's NOT valid base64, so encode it (line 239)
                $result = TokenSubstitute::substitute('%env(base64:B64_VAR)%');
                $this->assertEquals(base64_encode($testString), $result);
            }
        }
    }

    // =====================================================================
    // File Processor Tests
    // =====================================================================

    public function testFileProcessor(): void
    {
        putenv("FILE_VAR={$this->tempFile}");
        $result = TokenSubstitute::substitute('%env(file:FILE_VAR)%');
        $this->assertEquals('file content', $result);
    }

    public function testFileProcessorThrowsOnNonExistentFile(): void
    {
        putenv('FILE_VAR=/nonexistent/file.txt');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found or unreadable');
        TokenSubstitute::substitute('%env(file:FILE_VAR)%');
    }

    public function testFileProcessorThrowsOnUnreadableFile(): void
    {
        $unreadable = tempnam(sys_get_temp_dir(), 'unreadable_');
        file_put_contents($unreadable, 'content');
        chmod($unreadable, 0000);

        putenv("FILE_VAR={$unreadable}");

        try {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessageMatches('/not found or unreadable|Failed reading file/');
            TokenSubstitute::substitute('%env(file:FILE_VAR)%');
        } finally {
            chmod($unreadable, 0644);
            @unlink($unreadable);
        }
    }

    // =====================================================================
    // Resolve Processor Tests
    // =====================================================================

    public function testResolveProcessor(): void
    {
        $realPath = realpath($this->tempFile);
        $dirname = dirname($realPath);
        $basename = basename($realPath);
        $relative = $dirname . '/./' . $basename;

        putenv("RESOLVE_VAR={$relative}");
        $result = TokenSubstitute::substitute('%env(resolve:RESOLVE_VAR)%');
        $this->assertEquals($realPath, $result);
    }

    public function testResolveProcessorThrowsOnInvalidPath(): void
    {
        putenv('RESOLVE_VAR=/nonexistent/path');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not resolve path');
        TokenSubstitute::substitute('%env(resolve:RESOLVE_VAR)%');
    }

    // =====================================================================
    // Require Processor Tests
    // =====================================================================

    public function testRequireProcessor(): void
    {
        putenv("REQUIRE_VAR={$this->tempPhpFile}");
        $result = TokenSubstitute::substitute('%env(require:REQUIRE_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals('value', $result['key']);
    }

    public function testRequireProcessorThrowsOnNonExistentFile(): void
    {
        putenv('REQUIRE_VAR=/nonexistent/file.php');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found or unreadable');
        TokenSubstitute::substitute('%env(require:REQUIRE_VAR)%');
    }

    public function testRequireProcessorThrowsOnUnreadableFile(): void
    {
        $unreadable = tempnam(sys_get_temp_dir(), 'unreadable_php_');
        file_put_contents($unreadable, '<?php return [];');
        chmod($unreadable, 0000);

        putenv("REQUIRE_VAR={$unreadable}");

        try {
            $this->expectException(\Throwable::class);
            $this->expectExceptionMessageMatches('/not found or unreadable|Failed opening required/');
            TokenSubstitute::substitute('%env(require:REQUIRE_VAR)%');
        } finally {
            chmod($unreadable, 0644);
            @unlink($unreadable);
        }
    }

    // =====================================================================
    // Trim Processor Tests
    // =====================================================================

    public function testTrimProcessor(): void
    {
        putenv('TRIM_VAR=  spaces  ');
        $result = TokenSubstitute::substitute('%env(trim:TRIM_VAR)%');
        $this->assertEquals('spaces', $result);
    }

    public function testTrimProcessorWithTabs(): void
    {
        putenv("TRIM_VAR=\t\ttabs\t\t");
        $result = TokenSubstitute::substitute('%env(trim:TRIM_VAR)%');
        $this->assertEquals('tabs', $result);
    }

    // =====================================================================
    // Lower Processor Tests
    // =====================================================================

    public function testLowerProcessor(): void
    {
        putenv('LOWER_VAR=UPPERCASE');
        $result = TokenSubstitute::substitute('%env(lower:LOWER_VAR)%');
        $this->assertEquals('uppercase', $result);
    }

    // =====================================================================
    // Upper Processor Tests
    // =====================================================================

    public function testUpperProcessor(): void
    {
        putenv('UPPER_VAR=lowercase');
        $result = TokenSubstitute::substitute('%env(upper:UPPER_VAR)%');
        $this->assertEquals('LOWERCASE', $result);
    }

    // =====================================================================
    // URL Encode/Decode Processor Tests
    // =====================================================================

    public function testUrlencodeProcessor(): void
    {
        putenv('URL_VAR=hello world');
        $result = TokenSubstitute::substitute('%env(urlencode:URL_VAR)%');
        $this->assertEquals('hello+world', $result);
    }

    public function testUrldecodeProcessor(): void
    {
        putenv('URL_VAR=hello+world');
        $result = TokenSubstitute::substitute('%env(urldecode:URL_VAR)%');
        $this->assertEquals('hello world', $result);
    }

    // =====================================================================
    // CSV Processor Tests
    // =====================================================================

    public function testCsvProcessorStringToArray(): void
    {
        putenv('CSV_VAR=one,two,three');
        $result = TokenSubstitute::substitute('%env(csv:CSV_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals(['one', 'two', 'three'], $result);
    }

    public function testCsvProcessorWithSpaces(): void
    {
        putenv('CSV_VAR=one, two , three');
        $result = TokenSubstitute::substitute('%env(csv:CSV_VAR)%');
        $this->assertEquals(['one', 'two', 'three'], $result);
    }

    public function testCsvProcessorEmptyValues(): void
    {
        putenv('CSV_VAR=one,,three');
        $result = TokenSubstitute::substitute('%env(csv:CSV_VAR)%');
        $this->assertEquals(['one', 'three'], $result);
    }

    // =====================================================================
    // Shuffle Processor Tests
    // =====================================================================

    public function testShuffleProcessorWithArray(): void
    {
        putenv('SHUFFLE_VAR=[1,2,3,4,5]');
        $result = TokenSubstitute::substitute('%env(json:shuffle:SHUFFLE_VAR)%');
        $this->assertIsArray($result);
        $this->assertCount(5, $result);
        $this->assertContains(1, $result);
        $this->assertContains(5, $result);
    }

    public function testShuffleProcessorThrowsOnNonArray(): void
    {
        putenv('SHUFFLE_VAR=string');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('shuffle processor requires an array');
        TokenSubstitute::substitute('%env(shuffle:SHUFFLE_VAR)%');
    }

    // =====================================================================
    // Query String Processor Tests
    // =====================================================================

    public function testQueryStringProcessor(): void
    {
        putenv('QS_VAR=foo=1&bar=2');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals('1', $result['foo']);
        $this->assertEquals('2', $result['bar']);
    }

    public function testQueryStringProcessorWithDuplicates(): void
    {
        putenv('QS_VAR=foo=1&bar=2&bar=3');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertIsArray($result['bar']);
        $this->assertEquals(['2', '3'], $result['bar']);
    }

    public function testQueryStringProcessorEmpty(): void
    {
        putenv('QS_VAR=');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testQueryStringProcessorUrlDecoding(): void
    {
        putenv('QS_VAR=name=John+Doe&city=New%20York');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertEquals('John Doe', $result['name']);
        $this->assertEquals('New York', $result['city']);
    }

    public function testQueryStringProcessorEmptyPairs(): void
    {
        putenv('QS_VAR=foo=1&&bar=2');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertEquals('1', $result['foo']);
        $this->assertEquals('2', $result['bar']);
        $this->assertCount(2, $result);
    }

    public function testQueryStringProcessorNoValue(): void
    {
        putenv('QS_VAR=key1&key2=value2');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertEquals('', $result['key1']);
        $this->assertEquals('value2', $result['key2']);
    }

    // =====================================================================
    // URL Processor Tests
    // =====================================================================

    public function testUrlProcessor(): void
    {
        putenv('URL_VAR=https://user:pass@example.com:8080/path?query=1#fragment');
        $result = TokenSubstitute::substitute('%env(url:URL_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals('https', $result['scheme']);
        $this->assertEquals('example.com', $result['host']);
        $this->assertEquals(8080, $result['port']);
        $this->assertEquals('/path', $result['path']);
        $this->assertEquals('query=1', $result['query']);
        $this->assertEquals('fragment', $result['fragment']);
        $this->assertEquals('user', $result['user']);
        $this->assertEquals('pass', $result['pass']);
    }

    public function testUrlProcessorThrowsOnInvalidUrl(): void
    {
        putenv('URL_VAR=http://');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid URL');
        TokenSubstitute::substitute('%env(url:URL_VAR)%');
    }

    // =====================================================================
    // Key Processor Tests
    // =====================================================================

    public function testKeyProcessor(): void
    {
        putenv('KEY_VAR={"foo":"bar","num":42}');
        $result = TokenSubstitute::substitute('%env(json:key:foo:KEY_VAR)%');
        $this->assertEquals('bar', $result);
    }

    public function testKeyProcessorWithNumericKey(): void
    {
        putenv('KEY_VAR=[10,20,30]');
        $result = TokenSubstitute::substitute('%env(json:key:1:KEY_VAR)%');
        $this->assertEquals(20, $result);
    }

    public function testKeyProcessorThrowsOnMissingKeyParameter(): void
    {
        putenv('KEY_VAR={"foo":"bar"}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('key processor requires a key name');
        TokenSubstitute::substitute('%env(json:key:KEY_VAR)%');
    }

    public function testKeyProcessorThrowsOnNonArray(): void
    {
        putenv('KEY_VAR=string');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('key processor requires an array value');
        TokenSubstitute::substitute('%env(key:foo:KEY_VAR)%');
    }

    public function testKeyProcessorThrowsOnMissingKey(): void
    {
        putenv('KEY_VAR={"foo":"bar"}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Key "baz" not found');
        TokenSubstitute::substitute('%env(json:key:baz:KEY_VAR)%');
    }

    public function testKeyProcessorWithDefaultOnMissingKey(): void
    {
        putenv('KEY_VAR={"foo":"bar"}');
        $result = TokenSubstitute::substitute('%env(json:key:baz:fallback:KEY_VAR)%');
        $this->assertEquals('fallback', $result);
    }

    public function testKeyProcessorWithDefaultOnNonArray(): void
    {
        putenv('KEY_VAR=string');
        $result = TokenSubstitute::substitute('%env(key:foo:fallback:KEY_VAR)%');
        $this->assertEquals('fallback', $result);
    }

    public function testKeyProcessorWithDefaultChained(): void
    {
        putenv('KEY_VAR={"databases":{"default":{}}}');
        $result = TokenSubstitute::substitute('%env(json:key:databases:empty:key:default:empty:key:database:fallback_db:KEY_VAR)%');
        $this->assertEquals('fallback_db', $result);
    }

    public function testKeyProcessorDefaultNotUsedWhenKeyExists(): void
    {
        putenv('KEY_VAR={"foo":"actual"}');
        $result = TokenSubstitute::substitute('%env(json:key:foo:fallback:KEY_VAR)%');
        $this->assertEquals('actual', $result);
    }

    public function testKeyProcessorWithPressflowSettingsSimple(): void
    {
        // Test with PRESSFLOW_SETTINGS set - extracting nested database value
        $json = '{"databases":{"default":{"default":{"database":"pantheon"}}}}';
        putenv("PRESSFLOW_SETTINGS={$json}");
        $result = TokenSubstitute::substitute('%env(json:key:databases:key:default:key:default:key:database:db:string:PRESSFLOW_SETTINGS)%');
        $this->assertEquals('pantheon', $result);

        // Test with PRESSFLOW_SETTINGS missing nested 'default' key - use default on that step
        $partialJson = '{"databases":{"default":{"default":{}}}}';
        putenv("PRESSFLOW_SETTINGS={$partialJson}");
        $result = TokenSubstitute::substitute('%env(json:key:databases:key:default:key:default:key:database:db:string:PRESSFLOW_SETTINGS)%');
        $this->assertEquals('db', $result);
    }

    // =====================================================================
    // Safe Processor Tests
    // =====================================================================

    public function testSafeProcessorReturnsValueWhenSuccessful(): void
    {
        $json = '{"databases":{"default":{"default":{"username":"testuser"}}}}';
        putenv("SAFE_VAR={$json}");
        $result = TokenSubstitute::substitute('%env(safe:fallback:json:key:databases:key:default:key:default:key:username:SAFE_VAR)%');
        $this->assertEquals('testuser', $result);
    }

    public function testSafeProcessorReturnsFallbackWhenVarNotSet(): void
    {
        putenv('SAFE_VAR');
        $result = TokenSubstitute::substitute('%env(safe:db:json:key:databases:key:default:key:default:key:username:SAFE_VAR)%');
        $this->assertEquals('db', $result);
    }

    public function testSafeProcessorReturnsFallbackOnInvalidJson(): void
    {
        putenv('SAFE_VAR=not valid json');
        $result = TokenSubstitute::substitute('%env(safe:fallback:json:key:database:SAFE_VAR)%');
        $this->assertEquals('fallback', $result);
    }

    public function testSafeProcessorReturnsFallbackOnMissingKey(): void
    {
        putenv('SAFE_VAR={"foo":"bar"}');
        $result = TokenSubstitute::substitute('%env(safe:default_value:json:key:missing:SAFE_VAR)%');
        $this->assertEquals('default_value', $result);
    }

    public function testSafeProcessorReturnsFallbackOnNonArrayValue(): void
    {
        putenv('SAFE_VAR=string value');
        $result = TokenSubstitute::substitute('%env(safe:fallback:key:foo:SAFE_VAR)%');
        $this->assertEquals('fallback', $result);
    }

    public function testSafeProcessorWithPressflowSettings(): void
    {
        // Test with full structure
        $json = '{"databases":{"default":{"default":{"username":"testuser"}}}}';
        putenv("SAFE_PRESSFLOW={$json}");
        $result = TokenSubstitute::substitute('%env(safe:db:json:key:databases:key:default:key:default:key:username:SAFE_PRESSFLOW)%');
        $this->assertEquals('testuser', $result);

        // Test with variable not set
        putenv('SAFE_PRESSFLOW');
        $result = TokenSubstitute::substitute('%env(safe:db:json:key:databases:key:default:key:default:key:username:SAFE_PRESSFLOW)%');
        $this->assertEquals('db', $result);

        // Test with missing intermediate keys
        $partialJson = '{"databases":{}}';
        putenv("SAFE_PRESSFLOW={$partialJson}");
        $result = TokenSubstitute::substitute('%env(safe:db:json:key:databases:key:default:key:default:key:username:SAFE_PRESSFLOW)%');
        $this->assertEquals('db', $result);
    }

    public function testSafeProcessorThrowsWhenMissingFallback(): void
    {
        putenv('SAFE_VAR=test');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('safe processor requires a fallback value');
        TokenSubstitute::substitute('%env(safe:SAFE_VAR)%');
    }

    // =====================================================================
    // Raw Key Processor Tests
    // =====================================================================

    public function testRawKeyProcessor(): void
    {
        putenv('RAW_KEY_VAR={"foo:bar":"value"}');
        $result = TokenSubstitute::substitute('%env(json:raw_key:foo:bar:RAW_KEY_VAR)%');
        $this->assertEquals('value', $result);
    }

    public function testRawKeyProcessorMultipleColons(): void
    {
        putenv('RAW_KEY_VAR={"a:b:c":"xyz"}');
        $result = TokenSubstitute::substitute('%env(json:raw_key:a:b:c:RAW_KEY_VAR)%');
        $this->assertEquals('xyz', $result);
    }

    public function testRawKeyProcessorThrowsOnMissingParameter(): void
    {
        putenv('RAW_KEY_VAR={"foo":"bar"}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('raw_key processor requires a key name');
        TokenSubstitute::substitute('%env(json:raw_key:RAW_KEY_VAR)%');
    }

    public function testRawKeyProcessorThrowsOnNonArray(): void
    {
        putenv('RAW_KEY_VAR=string');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('raw_key processor requires an array value');
        TokenSubstitute::substitute('%env(raw_key:foo:RAW_KEY_VAR)%');
    }

    public function testRawKeyProcessorThrowsOnMissingKey(): void
    {
        putenv('RAW_KEY_VAR={"foo":"bar"}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Key "baz:qux" not found');
        TokenSubstitute::substitute('%env(json:raw_key:baz:qux:RAW_KEY_VAR)%');
    }

    public function testRawKeyProcessorWithColonInKey(): void
    {
        // Test that raw_key properly handles keys with colons
        // This verifies the loop that collects all parts until a processor is found
        putenv('RAW_KEY_VAR={"foo:bar:baz":"value123"}');
        $result = TokenSubstitute::substitute('%env(json:raw_key:foo:bar:baz:RAW_KEY_VAR)%');
        $this->assertEquals('value123', $result);
    }

    public function testRawKeyProcessorThrowsOnEmptyKeyParts(): void
    {
        // Test empty($keyParts) check (line 357-359)
        // This happens when raw_key is immediately followed by another processor
        // We need to construct a token where after raw_key, the next part is a processor
        // Example: %env(json:raw_key:string:VAR)% - 'string' is a processor, so keyParts is empty
        putenv('RAW_KEY_VAR={"foo":"bar"}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('raw_key processor requires a key name');
        // Use a chained processor where the part after raw_key is itself a processor
        TokenSubstitute::substitute('%env(json:raw_key:trim:RAW_KEY_VAR)%');
    }

    // =====================================================================
    // Defined Processor Tests
    // =====================================================================

    public function testDefinedProcessorReturnsTrueWhenSet(): void
    {
        putenv('DEFINED_VAR=value');
        $result = TokenSubstitute::substitute('%env(defined:DEFINED_VAR)%');
        $this->assertTrue($result);
    }

    public function testDefinedProcessorReturnsFalseWhenNotSet(): void
    {
        putenv('UNDEFINED_VAR');
        $result = TokenSubstitute::substitute('%env(defined:UNDEFINED_VAR)%');
        $this->assertFalse($result);
    }

    // =====================================================================
    // Const Processor Tests
    // =====================================================================

    public function testConstProcessor(): void
    {
        if (!defined('TEST_CONSTANT_FOR_TOKEN')) {
            define('TEST_CONSTANT_FOR_TOKEN', 'constant_value');
        }
        $result = TokenSubstitute::substitute('%env(const:TEST_CONSTANT_FOR_TOKEN)%');
        $this->assertEquals('constant_value', $result);
    }

    public function testConstProcessorThrowsOnUndefinedConstant(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Constant "UNDEFINED_CONSTANT_XYZ" is not defined');
        TokenSubstitute::substitute('%env(const:UNDEFINED_CONSTANT_XYZ)%');
    }

    // =====================================================================
    // Default Processor Tests
    // =====================================================================

    public function testDefaultProcessorUsesDefaultWhenNotSet(): void
    {
        putenv('MISSING_VAR');
        $result = TokenSubstitute::substitute('%env(default:fallback:MISSING_VAR)%');
        $this->assertEquals('fallback', $result);
    }

    public function testDefaultProcessorUsesEnvValueWhenSet(): void
    {
        putenv('PRESENT_VAR=actual');
        $result = TokenSubstitute::substitute('%env(default:fallback:PRESENT_VAR)%');
        $this->assertEquals('actual', $result);
    }

    public function testDefaultProcessorWithTypeConversion(): void
    {
        putenv('MISSING_INT');
        $result = TokenSubstitute::substitute('%env(int:default:42:MISSING_INT)%');
        $this->assertSame(42, $result);
    }

    public function testDefaultProcessorThrowsWhenMissingValue(): void
    {
        putenv('MISSING_VAR');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('default processor requires a value');
        TokenSubstitute::substitute('%env(default:MISSING_VAR)%');
    }

    // =====================================================================
    // Chained Processor Tests
    // =====================================================================

    public function testChainedProcessors(): void
    {
        putenv('CHAIN_VAR=  HELLO  ');
        $result = TokenSubstitute::substitute('%env(trim:lower:CHAIN_VAR)%');
        $this->assertEquals('hello', $result);
    }

    public function testChainedProcessorsComplex(): void
    {
        putenv('CHAIN_VAR={"key":"  VALUE  "}');
        $result = TokenSubstitute::substitute('%env(json:key:key:trim:lower:CHAIN_VAR)%');
        $this->assertEquals('value', $result);
    }

    public function testChainedProcessorsMultipleTransformations(): void
    {
        putenv('CHAIN_VAR=hello+world');
        $result = TokenSubstitute::substitute('%env(urldecode:upper:CHAIN_VAR)%');
        $this->assertEquals('HELLO WORLD', $result);
    }

    // =====================================================================
    // Error Cases Tests
    // =====================================================================

    public function testMissingEnvVarThrowsWithHelpfulMessage(): void
    {
        putenv('DOES_NOT_EXIST');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Environment variable "DOES_NOT_EXIST" is not set (checked both getenv() and $_SERVER)');
        TokenSubstitute::substitute('%env(int:DOES_NOT_EXIST)%');
    }

    public function testUnknownProcessorThrows(): void
    {
        putenv('VAR=value');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unknown env processor "unknown"');
        TokenSubstitute::substitute('%env(unknown:VAR)%');
    }

    // =====================================================================
    // $_SERVER Fallback Tests
    // =====================================================================

    public function testServerFallbackWhenEnvNotSet(): void
    {
        // Make sure it's not in getenv()
        putenv('SERVER_ONLY');

        // Set in $_SERVER only
        $_SERVER['SERVER_ONLY'] = 'from_server';

        $result = TokenSubstitute::substitute('%env(SERVER_ONLY)%');
        $this->assertEquals('from_server', $result);

        // Cleanup
        unset($_SERVER['SERVER_ONLY']);
    }

    public function testGetenvTakesPrecedenceOverServer(): void
    {
        // Set in both places
        putenv('BOTH_VAR=from_getenv');
        $_SERVER['BOTH_VAR'] = 'from_server';

        $result = TokenSubstitute::substitute('%env(BOTH_VAR)%');
        $this->assertEquals('from_getenv', $result);

        // Cleanup
        putenv('BOTH_VAR');
        unset($_SERVER['BOTH_VAR']);
    }

    public function testServerFallbackWithJsonProcessor(): void
    {
        // Make sure it's not in getenv()
        putenv('JSON_SERVER_VAR');

        // Set JSON in $_SERVER
        $_SERVER['JSON_SERVER_VAR'] = '{"key":"value","nested":{"item":"data"}}';

        $result = TokenSubstitute::substitute('%env(json:JSON_SERVER_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals('value', $result['key']);
        $this->assertEquals('data', $result['nested']['item']);

        // Cleanup
        unset($_SERVER['JSON_SERVER_VAR']);
    }

    public function testServerFallbackWithNestedKeys(): void
    {
        // Make sure it's not in getenv()
        putenv('NESTED_SERVER_VAR');

        // Set JSON in $_SERVER
        $_SERVER['NESTED_SERVER_VAR'] = '{"databases":{"default":{"username":"testuser"}}}';

        $result = TokenSubstitute::substitute('%env(json:key:databases:key:default:key:username:NESTED_SERVER_VAR)%');
        $this->assertEquals('testuser', $result);

        // Cleanup
        unset($_SERVER['NESTED_SERVER_VAR']);
    }

    public function testDefinedProcessorChecksServerFallback(): void
    {
        // Make sure it's not in getenv()
        putenv('DEFINED_TEST');

        // Set in $_SERVER only
        $_SERVER['DEFINED_TEST'] = 'exists';

        $result = TokenSubstitute::substitute('%env(defined:DEFINED_TEST)%');
        $this->assertTrue($result);

        // Cleanup
        unset($_SERVER['DEFINED_TEST']);
    }

    public function testDefinedProcessorReturnsFalseWhenNotInEither(): void
    {
        // Make sure it's not in either place
        putenv('NOT_DEFINED');
        if (isset($_SERVER['NOT_DEFINED'])) {
            unset($_SERVER['NOT_DEFINED']);
        }

        $result = TokenSubstitute::substitute('%env(defined:NOT_DEFINED)%');
        $this->assertFalse($result);
    }

    // =====================================================================
    // normalizeInclude Tests
    // =====================================================================

    public function testNormalizeIncludeWithConfigDir(): void
    {
        $result = TokenSubstitute::normalizeInclude('{config_dir}/rel/thing.yml', '/base/dir');
        $this->assertEquals('/base/dir/rel/thing.yml', $result);
    }

    public function testNormalizeIncludeWithEnvVar(): void
    {
        putenv('INCLUDE_PATH=configs/app.yml');
        $result = TokenSubstitute::normalizeInclude('%env(INCLUDE_PATH)%', '/base/dir');
        $this->assertEquals('/base/dir/configs/app.yml', $result);
    }

    public function testNormalizeIncludeWithAbsolutePath(): void
    {
        $result = TokenSubstitute::normalizeInclude('/absolute/path.yml', '/base/dir');
        $this->assertEquals('/absolute/path.yml', $result);
    }

    public function testNormalizeIncludeWithUrl(): void
    {
        $result = TokenSubstitute::normalizeInclude('https://example.com/config.yml', '/base/dir');
        $this->assertEquals('https://example.com/config.yml', $result);
    }

    public function testNormalizeIncludeWithRelativePath(): void
    {
        $result = TokenSubstitute::normalizeInclude('rel/thing.yml', '/base/dir');
        $expected = '/base/dir' . DIRECTORY_SEPARATOR . 'rel/thing.yml';
        $this->assertEquals($expected, $result);
    }

    public function testNormalizeIncludeThrowsWhenEnvVarMissing(): void
    {
        putenv('FAIL_ONE');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Environment variable "FAIL_ONE" is not set');
        TokenSubstitute::normalizeInclude('%env(string:FAIL_ONE)%', '/base/dir');
    }

    public function testNormalizeIncludeThrowsWhenEnvVarNotString(): void
    {
        putenv('INT_VAL=1');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('%env(...)% for include must resolve to a string path');
        TokenSubstitute::normalizeInclude('%env(int:INT_VAL)%', '/base/dir');
    }

    // =====================================================================
    // Edge Cases and Complex Scenarios
    // =====================================================================

    public function testEmptyEnvVarWithBoolProcessor(): void
    {
        putenv('EMPTY_VAR=');
        $result = TokenSubstitute::substitute('%env(bool:EMPTY_VAR)%');
        $this->assertFalse($result);
    }

    public function testNestedArraySubstitution(): void
    {
        putenv('VAR1=a');
        putenv('VAR2=b');
        putenv('VAR3=c');

        $config = [
            'level1' => [
                'level2' => [
                    'level3' => '%env(VAR1)%',
                    'items' => [
                        '%env(VAR2)%',
                        '%env(VAR3)%',
                    ],
                ],
            ],
        ];

        $result = TokenSubstitute::substitute($config);
        $this->assertEquals('a', $result['level1']['level2']['level3']);
        $this->assertEquals('b', $result['level1']['level2']['items'][0]);
        $this->assertEquals('c', $result['level1']['level2']['items'][1]);
    }

    public function testMultipleEnvVarsInSingleString(): void
    {
        putenv('PROTO=https');
        putenv('HOST=example.com');
        putenv('PORT=443');
        putenv('PATH=/api/v1');

        $result = TokenSubstitute::substitute('%env(PROTO)%://%env(HOST)%:%env(PORT)%%env(PATH)%');
        $this->assertEquals('https://example.com:443/api/v1', $result);
    }

    public function testBoolProcessorInInterpolatedString(): void
    {
        putenv('DEBUG=true');
        $result = TokenSubstitute::substitute('Debug mode: %env(bool:DEBUG)%');
        $this->assertEquals('Debug mode: 1', $result);
    }

    public function testIntProcessorInInterpolatedString(): void
    {
        putenv('COUNT=42');
        $result = TokenSubstitute::substitute('Count: %env(int:COUNT)%');
        $this->assertEquals('Count: 42', $result);
    }

    public function testCsvProcessorEmptyString(): void
    {
        putenv('CSV_VAR=');
        $result = TokenSubstitute::substitute('%env(csv:CSV_VAR)%');
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testQueryStringWithMultipleDuplicates(): void
    {
        putenv('QS_VAR=a=1&a=2&a=3&b=4');
        $result = TokenSubstitute::substitute('%env(query_string:QS_VAR)%');
        $this->assertIsArray($result['a']);
        $this->assertEquals(['1', '2', '3'], $result['a']);
        $this->assertEquals('4', $result['b']);
    }

    public function testDefaultProcessorSkippedInLoop(): void
    {
        putenv('TEST_VAR=value');
        $result = TokenSubstitute::substitute('%env(default:fallback:string:TEST_VAR)%');
        $this->assertEquals('value', $result);
    }

    // =====================================================================
    // Enum Processor Tests (Added for complete coverage)
    // =====================================================================

    public function testEnumProcessor(): void
    {
        // Create a simple backed enum for testing
        eval('enum TestStatus: string { case Active = "active"; case Inactive = "inactive"; }');
        
        putenv('STATUS_VAR=active');
        $result = TokenSubstitute::substitute('%env(enum:TestStatus:STATUS_VAR)%');
        $this->assertInstanceOf('TestStatus', $result);
        $this->assertEquals('active', $result->value);
    }

    public function testEnumProcessorThrowsOnNonExistentEnum(): void
    {
        putenv('ENUM_VAR=value');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Enum class "NonExistentEnum" does not exist');
        TokenSubstitute::substitute('%env(enum:NonExistentEnum:ENUM_VAR)%');
    }

    public function testEnumProcessorThrowsOnMissingEnumParameter(): void
    {
        putenv('ENUM_VAR=value');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('enum processor requires an enum class');
        TokenSubstitute::substitute('%env(enum:ENUM_VAR)%');
    }

    public function testEnumProcessorThrowsOnInvalidEnumValue(): void
    {
        // Create a test enum
        if (!enum_exists('TestStatusForInvalid')) {
            eval('enum TestStatusForInvalid: string { case Active = "active"; case Inactive = "inactive"; }');
        }

        putenv('STATUS_VAR=invalid_value');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid enum value');
        TokenSubstitute::substitute('%env(enum:TestStatusForInvalid:STATUS_VAR)%');
    }

    public function testEnumProcessorGetValueOnCase(): void
    {
        // Test the getValue() path (line 395) by using a case name instead of value
        if (!enum_exists('TestStatusByName')) {
            eval('enum TestStatusByName: string { case Active = "active"; case Inactive = "inactive"; }');
        }

        // Use the case name instead of the value - this will fail tryFrom and enter catch block
        putenv('STATUS_VAR=Active');
        $result = TokenSubstitute::substitute('%env(enum:TestStatusByName:STATUS_VAR)%');
        $this->assertInstanceOf('TestStatusByName', $result);
        // Check the value was correctly resolved
        $this->assertEquals('active', $result->value);
    }

    public function testTrimProcessorNonString(): void
    {
        // Test trim with non-string value (should pass through)
        putenv('TRIM_VAR=[1,2,3]');
        $result = TokenSubstitute::substitute('%env(json:trim:TRIM_VAR)%');
        $this->assertIsArray($result);
        $this->assertEquals([1, 2, 3], $result);
    }

    public function testResolveEnvTokenTyped(): void
    {
        putenv('DATABASE_URL=postgresql://db_user:db_password@127.0.0.1:5432/db_name');
        $value = TokenSubstitute::substitute('%env(url:key:host:DATABASE_URL)%');
        $this->assertEquals('127.0.0.1', $value);
    }

    public function testResolveEnvTokenTypedExceptionFile(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Environment variable " " is not set');
        TokenSubstitute::substitute('%env( )%');
    }

    public function testResolveEnvTokenTypedExceptionUrl(): void
    {
        putenv('TEST_URL=http:///example.com');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid URL in TEST_URL');
        TokenSubstitute::substitute('%env(url:TEST_URL)%');
    }
}
