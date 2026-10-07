<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ResponseReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Reading what providers actually send (#473).
 *
 * The bodies here were captured from each provider on 2026-10-05, unedited, so the quirks
 * they show -- `Answer` missing or `null`, an SOA record in place of answers, extra fields --
 * are the ones a reader has to survive.
 */
class ResponseReaderTest extends TestCase
{
    private const CLOUDFLARE_PTR = '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"1.66.249.66.in-addr.arpa","type":12}],"Answer":[{"name":"1.66.249.66.in-addr.arpa","type":12,"TTL":86400,"data":"crawl-66-249-66-1.googlebot.com."}]}';

    private const CLOUDFLARE_NX = '{"Status":3,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"1.2.0.192.in-addr.arpa","type":12}]}';

    private const GOOGLE_A = '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"crawl-66-249-66-1.googlebot.com.","type":1}],"Answer":[{"name":"crawl-66-249-66-1.googlebot.com.","type":1,"TTL":21600,"data":"66.249.66.1"}],"Comment":"Response from 216.239.34.10."}';

    private const GOOGLE_NX = '{"Status":3,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,"Question":[{"name":"1.2.0.192.in-addr.arpa.","type":12}],"Authority":[{"name":"192.in-addr.arpa.","type":6,"TTL":1783,"data":"z.arin.net. dns-ops.arin.net. 2017041681 1800 900 691200 10800"}]}';

    private const NEXTDNS_PTR = '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"1.66.249.66.in-addr.arpa.","type":12}],"Answer":[{"name":"1.66.249.66.in-addr.arpa.","type":12,"TTL":86400,"data":"crawl-66-249-66-1.googlebot.com."}],"Additional":[{"name":".","type":41,"TTL":0,"data":"\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232"}]}';

    private const ADGUARD_NX = '{"Question":[{"name":"1.2.0.192.in-addr.arpa.","type":12}],"Answer":null,"Extra":null,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Status":3}';

    private const ADGUARD_PTR_STATUS_ZERO_NULL_ANSWER = '{"Question":[{"name":"1.2.0.192.in-addr.arpa.","type":12}],"Answer":null,"Status":0}';

    private function dnsJson(): ResponseReader
    {
        return ResponseReader::fromConfig('dns-json');
    }

    public function testCloudflareAnswersAPtrLookup(): void
    {
        $lookupResult = $this->dnsJson()->read(200, self::CLOUDFLARE_PTR, 'PTR');

        $this->assertTrue($lookupResult->isAnswer());
        $this->assertSame(['crawl-66-249-66-1.googlebot.com.'], $lookupResult->values);
    }

    public function testGoogleAnswersAForwardLookup(): void
    {
        $this->assertSame(['66.249.66.1'], $this->dnsJson()->read(200, self::GOOGLE_A, 'A')->values);
    }

    public function testExtraSectionsAreIgnored(): void
    {
        $this->assertSame(['crawl-66-249-66-1.googlebot.com.'], $this->dnsJson()->read(200, self::NEXTDNS_PTR, 'PTR')->values);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function noRecordBodies(): array
    {
        return [
            'Cloudflare: no Answer' => [self::CLOUDFLARE_NX],
            'Google: an SOA record instead' => [self::GOOGLE_NX],
            'AdGuard: Answer is null' => [self::ADGUARD_NX],
            'status 0 with a null Answer' => [self::ADGUARD_PTR_STATUS_ZERO_NULL_ANSWER],
        ];
    }

    #[DataProvider('noRecordBodies')]
    public function testEveryWayOfSayingNoRecordIsNoRecord(string $body): void
    {
        $this->assertSame(LookupResult::NONE, $this->dnsJson()->read(200, $body, 'PTR')->status);
    }

    public function testAnAliasNeverStandsInForAnAddress(): void
    {
        $body = '{"Status":0,"Answer":[{"type":5,"data":"alias.googlebot.com."},{"type":1,"data":"66.249.66.1"}]}';

        $this->assertSame(['66.249.66.1'], $this->dnsJson()->read(200, $body, 'A')->values);
    }

    public function testOnlyAnAliasIsNoRecord(): void
    {
        $body = '{"Status":0,"Answer":[{"type":5,"data":"alias.googlebot.com."}]}';

        $this->assertSame(LookupResult::NONE, $this->dnsJson()->read(200, $body, 'A')->status);
    }

    public function testEveryPtrRecordIsRead(): void
    {
        $body = '{"Status":0,"Answer":[{"type":12,"data":"a.example."},{"type":12,"data":"b.example."}]}';

        $this->assertSame(['a.example.', 'b.example.'], $this->dnsJson()->read(200, $body, 'PTR')->values);
    }

    public function testATypeWrittenAsANameIsMatched(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'select' => 'records.*', 'type' => 'kind', 'template' => '{value[value]}']);
        $body = '{"records":[{"kind":"aaaa","value":"2001:db8::1"},{"kind":"A","value":"192.0.2.1"},{"kind":"28","value":"2001:db8::2"}]}';

        $this->assertSame(['2001:db8::1', '2001:db8::2'], $reader->read(200, $body, 'AAAA')->values);
    }

    public function testAnUnknownTypeNameMatchesNothing(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'select' => 'records.*', 'type' => 'kind', 'template' => '{value[value]}']);

        $this->assertSame(LookupResult::NONE, $reader->read(200, '{"records":[{"kind":12,"value":"x"}]}', 'TXT')->status);
    }

    /**
     * @return array<string, array{0: int, 1: string, 2: string}>
     */
    public static function unknownAnswers(): array
    {
        return [
            'a server error' => [503, self::CLOUDFLARE_PTR, 'HTTP 503'],
            'not JSON' => [200, '<html>busy</html>', 'not valid JSON'],
            'JSON that is not a document' => [200, '5', 'not a JSON object or list'],
            'no status' => [200, '{"Answer":[]}', 'has no DNS status'],
            'SERVFAIL' => [200, '{"Status":2}', 'DNS status 2'],
            'too large' => [200, str_repeat(' ', ResponseReader::MAX_BODY_BYTES + 1), 'larger than'],
        ];
    }

    #[DataProvider('unknownAnswers')]
    public function testAnswersThatSayNothingAboutTheNameAreUnknown(int $status, string $body, string $reason): void
    {
        $lookupResult = $this->dnsJson()->read($status, $body, 'PTR');

        $this->assertTrue($lookupResult->isUnknown());
        $this->assertStringContainsString($reason, $lookupResult->reason);
    }

    public function testAnHttpStatusCanMeanNoRecord(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'template' => '{value[hostname]}', 'none_http' => [404]]);

        $this->assertSame(LookupResult::NONE, $reader->read(404, 'Not Found', 'PTR')->status);
        $this->assertTrue($reader->read(500, '', 'PTR')->isUnknown());
    }

    public function testWithoutSelectTheBodyIsTheRecord(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'template' => '{value[hostname]}']);

        $this->assertSame(['crawl.example'], $reader->read(200, '{"hostname":"crawl.example"}', 'PTR')->values);
    }

    public function testWithoutSelectAListIsTheRecords(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'template' => '{value[ip]}']);

        $this->assertSame(['192.0.2.1', '192.0.2.2'], $reader->read(200, '[{"ip":"192.0.2.1"},{"ip":"192.0.2.2"}]', 'A')->values);
    }

    public function testWithoutStatusAnEmptyListIsNoRecord(): void
    {
        $reader = ResponseReader::fromConfig(['format' => 'json', 'template' => '{value[ip]}']);

        $this->assertSame(LookupResult::NONE, $reader->read(200, '[]', 'A')->status);
    }

    public function testWhereFiltersAsItDoesForASource(): void
    {
        $reader = ResponseReader::fromConfig([
            'format' => 'json',
            'select' => 'items.*',
            'where' => ['verified:yes'],
            'template' => '{value[name]}',
        ]);

        $body = '{"items":[{"name":"kept.example","verified":"yes"},{"name":"dropped.example","verified":"no"}]}';

        $this->assertSame(['kept.example'], $reader->read(200, $body, 'PTR')->values);
    }

    public function testARecordTheTemplateCannotReadIsDropped(): void
    {
        $this->assertSame(['ok.example.'], $this->dnsJson()->read(200, '{"Status":0,"Answer":[{"type":12},{"type":12,"data":"ok.example."}]}', 'PTR')->values);
    }

    public function testNoMoreThanTheCapOfRecordsIsRead(): void
    {
        $answers = [];

        for ($i = 0; $i < ResponseReader::MAX_RECORDS + 5; $i++) {
            $answers[] = ['type' => 12, 'data' => 'h' . $i . '.example.'];
        }

        $values = $this->dnsJson()->read(200, (string) json_encode(['Status' => 0, 'Answer' => $answers]), 'PTR')->values;

        $this->assertCount(ResponseReader::MAX_RECORDS, $values);
    }

    public function testNoLayoutMeansDnsJson(): void
    {
        $this->assertSame(['66.249.66.1'], ResponseReader::fromConfig(null)->read(200, self::GOOGLE_A, 'A')->values);
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function unusableLayouts(): array
    {
        return [
            'an unknown name' => ['dns-xml', '"dns-xml" is not a known layout'],
            'neither a name nor a map' => [12, 'not int'],
            'an unknown key' => [['format' => 'json', 'template' => '{value}', 'shape' => 'x'], 'unknown key "shape"'],
            'no format' => [['template' => '{value}'], 'format is required'],
            'the binary format' => [['format' => 'wire', 'template' => '{value}'], 'not supported yet'],
            'another format' => [['format' => 'csv', 'template' => '{value}'], 'format "csv" is not supported'],
            'no template' => [['format' => 'json'], 'template is required'],
            'a path that is not text' => [['format' => 'json', 'template' => '{value}', 'select' => []], 'select must be a path'],
            'where that is not a list' => [['format' => 'json', 'template' => '{value}', 'where' => 'x'], 'where must be a list'],
            'none_http that are not codes' => [['format' => 'json', 'template' => '{value}', 'none_http' => [404, 'x']], 'none_http must be'],
            'none_http out of range' => [['format' => 'json', 'template' => '{value}', 'none_http' => [42]], 'none_http must be'],
            'none_http that is not a list' => [['format' => 'json', 'template' => '{value}', 'none_http' => 404], 'none_http must be'],
        ];
    }

    #[DataProvider('unusableLayouts')]
    public function testUnusableLayoutsAreNamed(mixed $layout, string $expected): void
    {
        $this->assertStringContainsString($expected, implode('; ', ResponseReader::problems($layout)));
    }

    public function testAnUnusableLayoutIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('response: format is required');

        ResponseReader::fromConfig(['template' => '{value}']);
    }
}
