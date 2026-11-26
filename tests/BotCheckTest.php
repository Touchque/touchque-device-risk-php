<?php

namespace Touchque\DeviceRisk\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueAPIException;
use Touchque\DeviceRisk\Exceptions\TouchqueConfigException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureException;
use Touchque\DeviceRisk\TouchqueDeviceRisk;

/**
 * botCheck(): one visitor request checked from its IP and headers, against a fake of the API
 * that checks the signature. Sensitive values never leave, the order is kept, the limits hold,
 * and an answer from a newer server still reads.
 */
class BotCheckTest extends TestCase
{
    private const CHATGPT_USER = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';

    private const VERIFIED = [
        'bot' => [
            'result' => 'detected', 'category' => 'ai_assistant', 'provider' => 'OpenAI', 'name' => 'ChatGPT-User',
            'identity' => 'verified', 'verifiedBy' => 'ip_list', 'confidence' => 'high', 'rule' => 'directory.chatgpt_user',
            'reasons' => [['code' => 'bot_ip_list', 'text' => 'The address is in the list OpenAI publishes for ChatGPT-User.']],
        ],
        'network' => ['asn' => 8075, 'asnOrg' => 'MICROSOFT-CORP-MSN-AS-BLOCK', 'countryCode' => 'US', 'hosting' => true],
        'suggestion' => 'allow',
        'rulesVersion' => '2026.11.25-1',
    ];

    private static ?FakeBotCheckApi $api = null;

    public static function setUpBeforeClass(): void
    {
        self::$api = FakeBotCheckApi::start();
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$api) {
            self::$api->close();
        }
    }

    private function dr(): TouchqueDeviceRisk
    {
        self::$api->reset();
        return new TouchqueDeviceRisk(new Config('tq_test_key', 'test_secret', self::$api->baseUrl));
    }

    public function testTheRequestIsSignedAndShapedAsTheContractSays(): void
    {
        $dr = $this->dr();
        self::$api->answer(200, self::VERIFIED);
        $r = $dr->botCheck([
            'ip' => ' 203.0.113.7 ',
            'headers' => [['Host', 'shop.example'], ['User-Agent', self::CHATGPT_USER], ['Accept', '*/*']],
            'method' => 'GET',
            'url' => 'https://ada:hunter2@shop.example/login?email=ada%40example.com#form',
            'httpVersion' => 'HTTP/1.1',
            'tls' => ['ja4' => 't13d1516h2_8daaf6152771_e5627efa2ab1', 'ciphers' => null],
        ]);
        $last = self::$api->last();
        $this->assertSame(['POST', '/device-risk/bot-check', true], [$last['method'], $last['path'], $last['signed']]);
        $this->assertSame([
            'ip' => '203.0.113.7',
            'headers' => [['Host', 'shop.example'], ['User-Agent', self::CHATGPT_USER], ['Accept', '*/*']],
            'method' => 'GET',
            'url' => 'https://shop.example/login',
            'httpVersion' => '1.1',
            'tls' => ['ja4' => 't13d1516h2_8daaf6152771_e5627efa2ab1'],
        ], $last['body']);
        // Only the host and path of the URL leave: never the query string, a fragment or a user:password@.
        foreach (['email', 'ada', 'hunter2', 'form'] as $kept) {
            $this->assertStringNotContainsString($kept, $last['raw']);
        }
        $this->assertSame(self::VERIFIED, $r);
    }

    public function testSensitiveValuesGoEmptyAndKeepTheirPlace(): void
    {
        $dr = $this->dr();
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => [
            ['Host', 'shop.example'],
            ['Authorization', 'Bearer secret_1'],
            ['cookie', 'session=secret_2'],
            ['PROXY-AUTHORIZATION', 'Basic secret_3'],
            ['X-Api-Key', 'secret_4'],
            ['Set-Cookie', 'secret_5=1'],
            ['Accept', 'text/html'],
        ]]);
        $last = self::$api->last();
        $this->assertSame([
            ['Host', 'shop.example'], ['Authorization', ''], ['cookie', ''], ['PROXY-AUTHORIZATION', ''],
            ['X-Api-Key', ''], ['Set-Cookie', ''], ['Accept', 'text/html'],
        ], $last['body']['headers']);
        $this->assertStringNotContainsString('secret', $last['raw']);

        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => ['Cookie' => ['a=secret_6', 'b=secret_7'], 'Accept' => '*/*']]);
        $this->assertSame(['Cookie' => '', 'Accept' => '*/*'], self::$api->last()['body']['headers']);
        $this->assertStringNotContainsString('secret', self::$api->last()['raw']);
    }

    public function testTheOrderIsKeptAndAMapGoesAsAnObject(): void
    {
        $dr = $this->dr();
        $pairs = [['user-agent', 'curl/8.5.0'], ['accept', '*/*'], ['host', 'shop.example'], ['accept', 'text/html'], ['x-b', '2'], ['x-a', '1']];
        $dr->botCheck(['ip' => '2001:db8::7', 'headers' => $pairs]);
        $this->assertSame($pairs, self::$api->last()['body']['headers']);

        // An associative array is a map: it goes as a JSON object (its order unknown), a list of values joined.
        $dr->botCheck(['ip' => '2001:db8::7', 'headers' => ['User-Agent' => 'curl/8.5.0', 'Accept' => ['text/html', '*/*'], 'Content-Length' => 0]]);
        $this->assertStringContainsString('"headers":{"User-Agent":"curl\/8.5.0","Accept":"text\/html, *\/*","Content-Length":"0"}', self::$api->last()['raw']);

        // A request that came with no headers at all (HTTP/1.0 allows it) is still sent.
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => []]);
        $this->assertSame('{"ip":"203.0.113.7","headers":[]}', self::$api->last()['raw']);
    }

    /** @return array<string, array{0: array}> */
    public function wrongRequests(): array
    {
        $ok = ['ip' => '203.0.113.7', 'headers' => [['user-agent', 'curl/8.5.0']]];
        return [
            'no ip' => [['headers' => $ok['headers']]],
            'an empty ip' => [['ip' => ''] + $ok],
            'not an address' => [['ip' => 'localhost'] + $ok],
            'an address with a port' => [['ip' => '203.0.113.7:443'] + $ok],
            'no headers' => [['ip' => '203.0.113.7']],
            'headers as a string' => [['headers' => "User-Agent: curl/8.5.0\r\n"] + $ok],
            'a header that is not a pair' => [['headers' => [['user-agent']]] + $ok],
            'an empty header name' => [['headers' => [[' ', 'x']]] + $ok],
            'a header value that is not a string' => [['headers' => [['x-on', true]]] + $ok],
            'an unknown field' => [['query' => 'a=1'] + $ok],
            'an unknown tls field' => [['tls' => ['ja3' => '771,4865']] + $ok],
        ];
    }

    /** @dataProvider wrongRequests */
    public function testAWrongRequestThrowsBeforeAnythingIsSent(array $request): void
    {
        $dr = $this->dr();
        try {
            $dr->botCheck($request);
            $this->fail('refused: ' . json_encode($request));
        } catch (TouchqueConfigException $e) {
            $this->assertStringStartsWith('botCheck()', $e->getMessage());
        }
        $this->assertSame(0, self::$api->calls());
    }

    public function testPast100HeadersTheRestIsLeftOutNeverAnError(): void
    {
        $dr = $this->dr();
        $headers = [];
        for ($i = 0; $i < 150; $i++) {
            $headers[] = ["x-pad-{$i}", '1'];
        }
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => $headers]);
        $this->assertSame(array_slice($headers, 0, 100), self::$api->last()['body']['headers']);
        $this->assertTrue(self::$api->last()['body']['truncated']); // Touchque is told: a sign in itself

        // Exactly 100, and a pseudo-header, which never counts: nothing left out, no truncated.
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => array_merge([[':path', '/?q=1']], array_slice($headers, 0, 100))]);
        $this->assertCount(100, self::$api->last()['body']['headers']);
        $this->assertArrayNotHasKey('truncated', self::$api->last()['body']);
        // A blanked secret is not a cut.
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => [['Cookie', str_repeat('c', 5000)]]]);
        $this->assertArrayNotHasKey('truncated', self::$api->last()['body']);
    }

    public function testTheAddressPseudoHeadersAndEmptyValuesAreReadAsTheApiNeedsThem(): void
    {
        $body = fn (array $request) => TouchqueDeviceRisk::botCheckBody($request + ['headers' => []]);
        $this->assertSame('203.0.113.7', $body(['ip' => '::FFFF:203.0.113.7'])['ip']); // a dual-stack server's IPv4 visitor
        $this->assertSame('fe80::1', $body(['ip' => 'fe80::1%en0'])['ip']); // a zone means nothing outside your host
        $this->assertSame('::ffff:1:2', $body(['ip' => '::ffff:1:2'])['ip']);
        // :path holds the query string: HTTP/2 pseudo-headers never go; a null value is no header.
        $this->assertSame(
            [['accept', '*/*']],
            $body(['ip' => '203.0.113.7', 'headers' => [[':authority', 'shop.example'], [':path', '/reset?token=secret_1'], ['x-none', null], ['accept', '*/*']]])['headers']
        );
    }

    public function testValuesAndNamesAreCutNotRefused(): void
    {
        $dr = $this->dr();
        $headers = [
            ['x-long', str_repeat('a', 5000)],
            [str_repeat('n', 200), 'v'],
            ['x-emoji', str_repeat("\u{1F600}", 3000)],
            ['x-latin1', "caf\xE9"],
        ];
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => array_merge($headers, array_fill(0, 96, ['x-pad', '1']))]);
        $sent = self::$api->last()['body']['headers'];
        $this->assertCount(100, $sent); // 100 is the most, and it goes
        $this->assertSame(str_repeat('a', 4096), $sent[0][1]);
        $this->assertSame(str_repeat('n', 128), $sent[1][0]);
        $this->assertSame(str_repeat("\u{1F600}", 2048), $sent[2][1]); // 4096 characters as the API counts them (UTF-16)
        $this->assertSame("caf\u{E9}", $sent[3][1]); // a byte that is not UTF-8 is read as Latin-1
        $this->assertTrue(self::$api->last()['body']['truncated']);
    }

    public function testAnOversizedRequestIsFitIntoTheApis32Kb(): void
    {
        $dr = $this->dr();
        $headers = [['user-agent', 'curl/8.5.0']];
        for ($i = 1; $i < 100; $i++) {
            $headers[] = ["x-pad-{$i}", str_repeat('p', 4000)];
        }
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => $headers]);
        $last = self::$api->last();
        $sent = $last['body']['headers'];
        $this->assertLessThanOrEqual(32000, strlen($last['raw'])); // under either reading of 32 KB
        $this->assertSame(array_column($headers, 0), array_column($sent, 0)); // every name, in order
        $this->assertSame(['user-agent', 'curl/8.5.0'], $sent[0]); // a short value stays whole
        $lengths = array_values(array_unique(array_map('strlen', array_column(array_slice($sent, 1), 1))));
        $this->assertCount(1, $lengths); // the long ones are cut to one length...
        $this->assertGreaterThan(32000, strlen($last['raw']) + 99); // ...the longest that fits
    }

    public function testALongUrlAndCipherListLeaveLessRoomButEveryNameStays(): void
    {
        $dr = $this->dr();
        $headers = [];
        for ($i = 0; $i < 100; $i++) {
            $headers[] = [sprintf('%03d', $i) . str_repeat('n', 125), str_repeat('v', 100)];
        }
        // Each \u{E9} goes as six bytes in JSON: tls goes first, the values shrink, every name stays.
        $url = 'https://shop.example/' . str_repeat("\u{E9}", 3000);
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => $headers, 'url' => $url, 'tls' => ['ciphers' => str_repeat("\u{E9}", 4096)]]);
        $last = self::$api->last();
        $this->assertLessThanOrEqual(32000, strlen($last['raw']));
        $this->assertSame($url, $last['body']['url']);
        $this->assertArrayNotHasKey('tls', $last['body']);
        $this->assertSame(array_column($headers, 0), array_column($last['body']['headers'], 0));
        $this->assertGreaterThan(0, strlen($last['body']['headers'][0][1]));
        $this->assertLessThan(100, strlen($last['body']['headers'][0][1]));
        $this->assertTrue($last['body']['truncated']);

        // Only escaping can make the url crowd out the names too: then it goes as well, never an error.
        $dr->botCheck(['ip' => '203.0.113.7', 'headers' => $headers, 'url' => '/' . str_repeat("\u{E9}", 4095), 'tls' => ['ciphers' => str_repeat("\u{E9}", 4096)]]);
        $last = self::$api->last();
        $this->assertLessThanOrEqual(32000, strlen($last['raw']));
        $this->assertSame([false, false], [isset($last['body']['url']), isset($last['body']['tls'])]);
        $this->assertSame(array_column($headers, 0), array_column($last['body']['headers'], 0));
    }

    public function testAHeaderHttpDoesNotAllowIsLeftOutNeverARefusedCheck(): void
    {
        $body = TouchqueDeviceRisk::botCheckBody(['ip' => '203.0.113.7', 'headers' => [
            ['X Bad', '1'], ["Caf\u{E9}", '2'], ['X-Nul', "a\0b"], ['X-Break', "a\r\nX-Evil: 1"], ['Accept', '*/*'],
        ]]);
        $this->assertSame(['ip' => '203.0.113.7', 'headers' => [['Accept', '*/*']], 'truncated' => true], $body);
    }

    /** @return array<string, array{0: string, 1: ?string}> */
    public function urls(): array
    {
        return [
            'host and path' => ['https://Shop.Example:8443/a/b?c=d#e', 'https://Shop.Example:8443/a/b'],
            'an IPv4 host' => ['https://203.0.113.7/login', 'https://203.0.113.7/login'],
            'no path' => ['http://shop.example', 'http://shop.example'],
            'a path' => ['/sign-in?x=1', '/sign-in'],
            'wss' => ['wss://shop.example/socket', 'https://shop.example/socket'], // a WebSocket is the same origin over http(s)
            'ws' => ['ws://shop.example/socket', 'http://shop.example/socket'],
            // The Host header is the visitor's: one the API could not read goes as the path alone.
            'a space' => ['https://exa mple.com/login', '/login'],
            'ends in a number' => ['https://shop.example.123/login', '/login'],
            'not an IPv4' => ['https://1.2.3.256/login', '/login'],
            'a port too big' => ['https://shop.example:99999/login', '/login'],
            'an IPv6 host' => ['https://[2001:db8::1]/login', '/login'],
            'punycode' => ['https://xn--zz.example/login', '/login'],
            'colons' => ['https://a:b:c/login', '/login'],
            'percent' => ['https://shop%2eexample/login', '/login'],
            // Anything that is not a path or an http(s) URL is left out, and so is one over 4096 characters (never cut).
            'a star' => ['*', null],
            'ftp' => ['ftp://shop.example/x', null],
            'no scheme' => ['shop.example/x', null],
            'a query only' => ['?q=1', null],
            'too long' => ['https://shop.example/' . str_repeat('p', 4096), null],
            '4096 characters' => ['/' . str_repeat('p', 4095), '/' . str_repeat('p', 4095)],
        ];
    }

    /** @dataProvider urls */
    public function testTheUrlGoesAsTheApiReadsIt(string $given, ?string $sent): void
    {
        $this->assertSame($sent, TouchqueDeviceRisk::botCheckBody(['ip' => '203.0.113.7', 'headers' => [], 'url' => $given])['url'] ?? null);
    }

    public function testTheMethodAndTlsGoOnlyAsTheApiReadsThem(): void
    {
        $body = fn (array $request) => TouchqueDeviceRisk::botCheckBody($request + ['ip' => '203.0.113.7', 'headers' => []]);
        $this->assertSame(
            ['GET', 'post', 'PROPFIND', null, null],
            array_map(fn ($m) => $body(['method' => $m])['method'] ?? null, ['GET', ' post ', 'PROPFIND', 'M-SEARCH', str_repeat('M', 17)])
        );
        $this->assertSame(['ciphers' => str_repeat('c', 4096)], $body(['tls' => ['ciphers' => str_repeat('c', 5000), 'ja4' => str_repeat('j', 129)]])['tls']);
        $this->assertArrayNotHasKey('tls', $body(['tls' => ['ja4' => str_repeat('j', 129)]])); // a longer one is not a JA4
    }

    public function testTheRequestFromServerKeepsPhpsOrderAndNeverTheSecrets(): void
    {
        $server = [
            'HTTP_PROXY' => '', // a FastCGI config line, not the visitor
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded', // also below as HTTP_CONTENT_TYPE, in its place
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/login?next=%2Faccount',
            'SERVER_PROTOCOL' => 'HTTP/2.0',
            'HTTPS' => 'on',
            'REMOTE_ADDR' => '203.0.113.7',
            'PHP_AUTH_PW' => 'secret_1',
            'HTTP_HOST' => 'shop.example',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)',
            'HTTP_COOKIE' => 'session=secret_2',
            'HTTP_AUTHORIZATION' => 'Bearer secret_3',
            'HTTP_CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            'HTTP_X_API_KEY' => 'secret_4',
            'HTTP_ACCEPT' => '*/*',
            'REQUEST_TIME' => 1764072000,
        ];
        $request = TouchqueDeviceRisk::botCheckRequestFromServer($server);
        $this->assertSame([
            'ip' => '203.0.113.7',
            'headers' => [
                ['host', 'shop.example'],
                ['user-agent', 'Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)'],
                ['cookie', ''],
                ['authorization', ''],
                ['content-type', 'application/x-www-form-urlencoded'],
                ['x-api-key', ''],
                ['accept', '*/*'],
            ],
            'method' => 'POST',
            'url' => 'https://shop.example/login',
        ], $request); // no httpVersion: SERVER_PROTOCOL is the connection to this server (behind a proxy, the proxy's)
        // Behind a proxy, the address your framework trusts.
        $this->assertSame('198.51.100.9', TouchqueDeviceRisk::botCheckRequestFromServer($server, '198.51.100.9')['ip']);

        $dr = $this->dr();
        $dr->botCheck($request);
        $this->assertSame($request, self::$api->last()['body']);
        $this->assertStringNotContainsString('secret', self::$api->last()['raw']);
    }

    public function testCgiContentHeadersKeepTheirPlace(): void
    {
        // Apache names Content-Type and Content-Length CONTENT_TYPE and CONTENT_LENGTH only.
        $r = TouchqueDeviceRisk::botCheckRequestFromServer([
            'HTTP_HOST' => 'a.example', 'CONTENT_TYPE' => 'text/plain', 'CONTENT_LENGTH' => '3', 'HTTP_ACCEPT' => '*/*',
            'REMOTE_ADDR' => '::1', 'SERVER_PROTOCOL' => 'HTTP/1.0', 'REQUEST_URI' => '/',
        ]);
        $this->assertSame([['host', 'a.example'], ['content-type', 'text/plain'], ['content-length', '3'], ['accept', '*/*']], $r['headers']);
        $this->assertSame(['::1', 'http://a.example/'], [$r['ip'], $r['url']]);
        $this->assertArrayNotHasKey('method', $r);
        $this->assertArrayNotHasKey('httpVersion', $r);
    }

    public function testAVisitorsManyHeadersNeverMakeItThrow(): void
    {
        $server = ['REMOTE_ADDR' => '203.0.113.7'];
        for ($i = 0; $i < 150; $i++) {
            $server["HTTP_X_PAD_{$i}"] = str_repeat('p', 4000);
        }
        $request = TouchqueDeviceRisk::botCheckRequestFromServer($server);
        $this->assertCount(150, $request['headers']);

        $dr = $this->dr();
        $dr->botCheck($request);
        $last = self::$api->last();
        $this->assertCount(100, $last['body']['headers']);
        $this->assertSame(['x-pad-0', 'x-pad-99'], [$last['body']['headers'][0][0], $last['body']['headers'][99][0]]);
        $this->assertTrue($last['body']['truncated']);
        $this->assertLessThanOrEqual(32000, strlen($last['raw']));
    }

    public function testTheRequestFromServerReadsServerByDefault(): void
    {
        $saved = $_SERVER;
        $_SERVER = ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'curl/8.5.0', 'REQUEST_METHOD' => 'HEAD'];
        try {
            $this->assertSame(
                ['ip' => '203.0.113.7', 'headers' => [['user-agent', 'curl/8.5.0']], 'method' => 'HEAD'],
                TouchqueDeviceRisk::botCheckRequestFromServer()
            );
        } finally {
            $_SERVER = $saved;
        }
    }

    public function testTheHttpVersionIsReadAsServersGiveIt(): void
    {
        $version = fn ($v) => TouchqueDeviceRisk::botCheckBody(['ip' => '203.0.113.7', 'headers' => [], 'httpVersion' => $v])['httpVersion'] ?? null;
        $this->assertSame(
            ['1.0', '1.1', '2', '2', '2', '3', '3'],
            [$version('HTTP/1.0'), $version('1.1'), $version('HTTP/2.0'), $version(2), $version('h2'), $version('3.0'), $version('HTTP/3')]
        );
        // Anything else is left out, never an error: it may be what the visitor sent.
        $this->assertSame([null, null, null], [$version('HTTP/0.9'), $version('4'), $version(['2'])]);
    }

    public function testTheUrlNeedsAHostAndNeverTakesTheQuery(): void
    {
        $url = fn (array $server) => TouchqueDeviceRisk::botCheckRequestFromServer($server + ['REMOTE_ADDR' => '203.0.113.7'])['url'] ?? null;
        $this->assertSame('http://shop.example/a', $url(['SERVER_NAME' => 'shop.example', 'REQUEST_URI' => '/a?b=c'])); // HTTP/1.0 without Host
        $this->assertSame('https://shop.example/a', $url(['HTTP_HOST' => 'shop.example', 'REQUEST_URI' => '/a', 'REQUEST_SCHEME' => 'https']));
        $this->assertSame('http://other.example/x', $url(['HTTP_HOST' => 'shop.example', 'REQUEST_URI' => 'http://other.example/x?y=1'])); // a proxy request
        // No host at all (HTTP/1.0 without Host): the path alone; `*` (OPTIONS *): no URL.
        $this->assertSame(['/a', null], [$url(['REQUEST_URI' => '/a']), $url(['HTTP_HOST' => 'shop.example', 'REQUEST_URI' => '*'])]);
        $this->assertSame('http://shop.example/a', $url(['HTTP_HOST' => 'shop.example', 'REQUEST_URI' => '/a', 'HTTPS' => 'off']));
    }

    public function testAnAnswerFromANewerServerStillReads(): void
    {
        $dr = $this->dr();
        self::$api->answer(200, [
            'bot' => [
                'result' => 'detected', 'category' => 'ai_browser', 'provider' => 'OpenAI', 'name' => 'ChatGPT Atlas',
                'identity' => 'claimed', 'verifiedBy' => null, 'confidence' => 'medium', 'rule' => 'directory.chatgpt_atlas',
                'reasons' => [['code' => 'ua_token', 'text' => 'The browser names itself ChatGPT Atlas.', 'weight' => 2], 'junk', ['text' => 'no code']],
                'firstSeen' => '2026-11-25',
            ],
            'network' => ['asn' => 15169, 'asnOrg' => 'GOOGLE', 'countryCode' => 'US', 'hosting' => 'yes', 'type' => 'hosting'],
            'suggestion' => 'observe',
            'rulesVersion' => '2026.12.01-1',
            'velocity' => ['perMinute' => 3],
        ]);
        $r = $dr->botCheck(['ip' => '203.0.113.7', 'headers' => [['user-agent', 'Mozilla/5.0 ChatGPT-Atlas']]]);
        // A category, a suggestion or a field this version does not list comes as it was sent.
        $this->assertNotContains('ai_browser', TouchqueDeviceRisk::BOT_CHECK_CATEGORIES);
        $this->assertSame('ai_browser', $r['bot']['category']);
        $this->assertSame('observe', $r['suggestion']);
        $this->assertSame('2026-11-25', $r['bot']['firstSeen']);
        $this->assertSame(['perMinute' => 3], $r['velocity']);
        $this->assertSame('2026.12.01-1', $r['rulesVersion']);
        $this->assertSame(['claimed', null, 'medium'], [$r['bot']['identity'], $r['bot']['verifiedBy'], $r['bot']['confidence']]);
        $this->assertSame([['code' => 'ua_token', 'text' => 'The browser names itself ChatGPT Atlas.', 'weight' => 2]], $r['bot']['reasons']);
        $this->assertSame(['asn' => 15169, 'asnOrg' => 'GOOGLE', 'countryCode' => 'US', 'hosting' => null, 'type' => 'hosting'], $r['network']);
    }

    public function testAJunkAnswerIsCannotTellNeverABlock(): void
    {
        $cannotTell = [
            'bot' => ['result' => 'not_detected', 'category' => null, 'provider' => null, 'name' => null, 'identity' => null, 'verifiedBy' => null, 'confidence' => null, 'rule' => null, 'reasons' => []],
            'network' => null,
            'suggestion' => 'allow',
            'rulesVersion' => null,
        ];
        $this->assertSame($cannotTell, TouchqueDeviceRisk::parseBotCheck(null));
        $this->assertSame($cannotTell, TouchqueDeviceRisk::parseBotCheck(['bot' => 'x', 'network' => 'x', 'suggestion' => false, 'rulesVersion' => 7]));
        $r = TouchqueDeviceRisk::parseBotCheck(['bot' => ['result' => 7, 'identity' => ['verified'], 'reasons' => 'x'], 'network' => ['asn' => '15169']]);
        $this->assertSame(['not_detected', null, []], [$r['bot']['result'], $r['bot']['identity'], $r['bot']['reasons']]);
        $this->assertSame(['asn' => null, 'asnOrg' => null, 'countryCode' => null, 'hosting' => null], $r['network']);
    }

    public function testAnApiErrorIsATouchqueApiException(): void
    {
        $dr = $this->dr();
        self::$api->answer(400, ['error' => 'ip must be an IPv4 or IPv6 address', 'code' => 'invalid_ip']);
        try {
            $dr->botCheck(['ip' => '203.0.113.7', 'headers' => []]);
            $this->fail('a 400 answer must throw');
        } catch (TouchqueAPIException $e) {
            $this->assertNotInstanceOf(TouchqueFeatureException::class, $e);
            $this->assertSame([400, 'invalid_ip'], [$e->getStatus(), $e->getErrorCode()]);
        }
        self::$api->answer(429, ['error' => 'Too many bot checks', 'code' => 'rate_limited'], ['Retry-After' => '12']);
        try {
            $dr->botCheck(['ip' => '203.0.113.7', 'headers' => []]);
            $this->fail('a 429 answer must throw');
        } catch (TouchqueAPIException $e) {
            $this->assertSame([429, 12], [$e->getStatus(), $e->getRetryAfter()]);
        }
    }
}
