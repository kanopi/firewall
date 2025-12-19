<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the Url plugin.
 */
class UrlTest extends AbstractTestCase
{
    /**
     * Create a Url plugin instance with config.
     */
    protected function createPlugin(array $config = []): Url
    {
        return new class([], $config) extends Url {
            public function getRequestValueWrapper(Request $request, string $variable): mixed {
                return $this->getRequestValue($request, $variable);
            }

            public function getValueWrapper(Request $request, string $variable): mixed {
                return $this->getValue($request, $variable);
            }
        };
    }

    /**
     * Tests getName returns 'URL'
     */
    public function testGetName(): void
    {
        $plugin = $this->createPlugin();
        $this->assertSame('URL', $plugin->getName());
    }

    /**
     * Tests getDescription returns expected message
     */
    public function testGetDescription(): void
    {
        $plugin = $this->createPlugin();
        $this->assertSame('Block access based on the URL being requested.', $plugin->getDescription());
    }

    /**
     * Tests evaluate returns false if no rules match
     */
    public function testEvaluateReturnsFalseWithoutRules(): void
    {
        $plugin = $this->createPlugin();
        $request = new Request();
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests evaluate returns true with matching rules.
     */
    public function testEvaluateReturnsTrueWithMatchingRules(): void
    {
        $plugin = $this->createPlugin([
            'method:GET'
        ]);
        $request = new Request();
        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Tests getRequestValue for HTTP method
     */
    public function testGetRequestValueMethod(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/test', 'POST');
        $this->assertSame('POST', $plugin->getRequestValueWrapper($request, 'method'));
    }

    /**
     * Tests getRequestValue for host
     */
    public function testGetRequestValueHost(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('https://example.com');
        $this->assertSame('example.com', $plugin->getRequestValueWrapper($request, 'host'));
    }

    /**
     * Tests getRequestValue for path
     */
    public function testGetRequestValuePath(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/admin/zone');
        $this->assertSame('/admin/zone', $plugin->getRequestValueWrapper($request, 'path'));
    }

    /**
     * Tests getRequestValue for scheme
     */
    public function testGetRequestValueScheme(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('https://example.com');
        $this->assertSame('https', $plugin->getRequestValueWrapper($request, 'scheme'));
    }

    /**
     * Tests getRequestValue for port
     */
    public function testGetRequestValuePort(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('http://localhost:8080');
        $this->assertSame(8080, $plugin->getRequestValueWrapper($request, 'port'));
    }

    /**
     * Tests getRequestValue from query string
     */
    public function testGetRequestValueQuery(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/?foo=bar&baz[qux]=val');
        $this->assertSame('bar', $plugin->getRequestValueWrapper($request, 'query.foo'));
        $this->assertSame('val', $plugin->getRequestValueWrapper($request, 'query.baz.qux'));
        $this->assertSame('baz%5Bqux%5D=val&foo=bar', $plugin->getRequestValueWrapper($request, 'query'));
    }

    /**
     * Tests getRequestValue from POST data
     */
    public function testGetRequestValuePost(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/submit', 'POST', ['user' => ['name' => 'Alice'], 'title' => 'Wonderland']);
        $this->assertSame('Alice', $plugin->getRequestValueWrapper($request, 'post.user.name'));
        $this->assertSame('user%5Bname%5D=Alice title=Wonderland', $plugin->getRequestValueWrapper($request, 'post'));
    }

    /**
     * Tests getRequestValue from headers
     */
    public function testGetRequestValueHeader(): void
    {
        $plugin = $this->createPlugin();
        $request = new Request([], [], [], [], [], ['HTTP_X_CUSTOM_HEADER' => '123abc']);
        $this->assertSame('123abc', $plugin->getRequestValueWrapper($request, 'header.x-custom-header.0'));
    }

    /**
     * Tests getRequestValue from cookies
     */
    public function testGetRequestValueCookie(): void
    {
        $plugin = $this->createPlugin();
        $request = new Request([], [], [], ['session_id' => 'xyz789']);
        $this->assertSame('xyz789', $plugin->getRequestValueWrapper($request, 'cookie.session_id'));
    }

    /**
     * Tests getRequestValue returns null for unknown root field
     */
    public function testGetRequestValueUnknown(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/');
        $this->assertNull($plugin->getRequestValueWrapper($request, 'unknown'));
    }

    /**
     * Tests getRequestValue returns null for empty segment string
     */
    public function testGetRequestValueEmptyString(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/');
        $this->assertNull($plugin->getRequestValueWrapper($request, ''));
    }

    /**
     * Tests getRequestValue returns null for valid query root but missing key
     */
    public function testGetRequestValueQueryKeyNotFound(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/?foo=bar');
        $this->assertNull($plugin->getRequestValueWrapper($request, 'query.bar'));
    }

    /**
     * Tests getRequestValue returns null if query key exists but nested key is missing
     */
    public function testGetRequestValueNestedMissingKey(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/?foo[bar]=baz');
        $this->assertNull($plugin->getRequestValueWrapper($request, 'query.foo.nonexistent'));
    }

    /**
     * Tests getRequestValue returns string only (no arrays)
     */
    public function testGetRequestValueReturnsStringOnly(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/?items[0]=a&items[1]=b');
        $this->assertNull($plugin->getRequestValueWrapper($request, 'query.items'));
    }

    /**
     * Tests getRequestValue returns null when empty string is passed
     */
    public function testGetRequestValueEmptySegmentReturnsNull(): void
    {
        $plugin = $this->createPlugin();
        $request = Request::create('/');
        $this->assertNull($plugin->getRequestValueWrapper($request, ''));
        $this->assertNull($plugin->getValueWrapper($request, ''));
    }

    /**
     * Tests regex patterns with commas are not split incorrectly
     * Regex patterns can contain commas in quantifiers like {1,2}
     */
    public function testRegexPatternsWithCommas(): void
    {
        // Test pattern with comma in quantifier {1,2}
        $plugin = $this->createPlugin([
            'path@regex:#^/[a-z]{1,2}\.php$#',
        ]);

        // Should match: 1-2 letter filenames
        $this->assertTrue($plugin->evaluate(Request::create('/a.php')));
        $this->assertTrue($plugin->evaluate(Request::create('/ab.php')));

        // Should NOT match: 3+ letter filenames
        $this->assertFalse($plugin->evaluate(Request::create('/abc.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/test.php')));
    }

    /**
     * Tests regex patterns with multiple commas work correctly
     */
    public function testRegexPatternsWithMultipleCommas(): void
    {
        // Pattern with multiple comma-separated quantifiers
        $plugin = $this->createPlugin([
            'path@regex:#/test-[0-9]{2,4}\.html$#',
        ]);

        // Should match: 2-4 digits
        $this->assertTrue($plugin->evaluate(Request::create('/test-12.html')));
        $this->assertTrue($plugin->evaluate(Request::create('/test-123.html')));
        $this->assertTrue($plugin->evaluate(Request::create('/test-1234.html')));

        // Should NOT match: 1 digit or 5+ digits
        $this->assertFalse($plugin->evaluate(Request::create('/test-1.html')));
        $this->assertFalse($plugin->evaluate(Request::create('/test-12345.html')));
    }

    /**
     * Tests that invalid regex patterns are handled gracefully
     */
    public function testInvalidRegexPatternsAreHandled(): void
    {
        // Missing delimiters - should not match (returns false)
        $plugin = $this->createPlugin([
            'path@regex:test',
        ]);
        $this->assertFalse($plugin->evaluate(Request::create('/test')));

        // Mismatched delimiters - should not match (returns false)
        $plugin = $this->createPlugin([
            'path@regex:/test#',
        ]);
        $this->assertFalse($plugin->evaluate(Request::create('/test')));

        // Empty pattern - should not match (returns false)
        $plugin = $this->createPlugin([
            'path@regex:',
        ]);
        $this->assertFalse($plugin->evaluate(Request::create('/test')));

        // Too short pattern - should not match (returns false)
        $plugin = $this->createPlugin([
            'path@regex://',
        ]);
        $this->assertFalse($plugin->evaluate(Request::create('/test')));
    }

    /**
     * Tests that valid regex patterns with different delimiters work
     */
    public function testRegexWithDifferentDelimiters(): void
    {
        // Using / delimiter
        $plugin = $this->createPlugin([
            'path@regex:/^\/test/',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/other.php')));

        // Using # delimiter
        $plugin = $this->createPlugin([
            'path@regex:#^/test#',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/other.php')));

        // Using @ delimiter
        $plugin = $this->createPlugin([
            'path@regex:@^/test@',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/other.php')));

        // Using ~ delimiter
        $plugin = $this->createPlugin([
            'path@regex:~^/test~',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/other.php')));
    }

    /**
     * Tests regex patterns with modifiers work correctly
     */
    public function testRegexWithModifiers(): void
    {
        // Case-insensitive modifier
        $plugin = $this->createPlugin([
            'path@regex:/test/i',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/TEST.php')));
        $this->assertTrue($plugin->evaluate(Request::create('/Test.php')));
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));

        // Multiline and case-insensitive modifiers combined
        $plugin = $this->createPlugin([
            'path@regex:/TEST/im',
        ]);
        $this->assertTrue($plugin->evaluate(Request::create('/test.php')));
        $this->assertFalse($plugin->evaluate(Request::create('/other.php')));
    }

}
