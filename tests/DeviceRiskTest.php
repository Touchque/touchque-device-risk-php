<?php

namespace Touchque\DeviceRisk\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueConfigException;
use Touchque\DeviceRisk\TouchqueDeviceRisk;
use Touchque\DeviceRisk\WebhookEvents;

/**
 * Device risk against the shared fake Touchque API: the report goes through
 * untouched and the answer fails toward asking. Same scenarios as the Node
 * package's tests.
 */
class DeviceRiskTest extends TestCase
{
    private static ?FakeApi $api = null;

    public static function setUpBeforeClass(): void
    {
        exec('which node', $out, $code);
        if ($code !== 0) {
            self::markTestSkipped('node is required for contract tests');
        }
        self::$api = FakeApi::start();
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

    public function testTheVisitorMarkIsTrustedStepUpOrNull(): void
    {
        $mark = fn ($m) => TouchqueDeviceRisk::parse(['report' => 'ok', 'visitor' => ['status' => 'trusted', 'mark' => $m]])['visitor']['mark'];
        $this->assertSame(['trusted', 'step_up', null, null, null], [$mark('trusted'), $mark('step_up'), $mark(null), $mark('blocked'), $mark(1)]);
        // Older servers send no mark: the visitor stays as it came.
        $this->assertSame(['status' => 'none'], TouchqueDeviceRisk::parse(['visitor' => ['status' => 'none']])['visitor']);
        $this->assertNull(TouchqueDeviceRisk::parse(['visitor' => 'x'])['visitor']);
    }

    public function testTheVisitorMarkIsTheMarkAppliedAgainstTheFake(): void
    {
        $dr = $this->dr();
        $key = 'dre_' . str_repeat('a', 22);
        $traits = 'dre_flagged' . str_repeat('a', 15);
        $v = $dr->check($key)['visitor'];
        $this->assertSame(['none', null], [$v['status'], $v['mark']]);
        self::$api->opts(['deviceMark' => 'trusted']);
        $v = $dr->check($key)['visitor'];
        $this->assertSame(['trusted', 'trusted', 'key'], [$v['status'], $v['mark'], $v['matchedBy']]);
        $v = $dr->check($traits)['visitor'];
        $this->assertSame(['trusted', null, 'traits'], [$v['status'], $v['mark'], $v['matchedBy']]);
        $this->assertSame('trusted', $dr->getEvent($key)['visitor']['mark']);
        self::$api->opts(['deviceMark' => 'step_up']);
        $this->assertSame('step_up', $dr->check($traits)['visitor']['mark']);
    }

    public function testCheckSendsTheReportAndReadsTheAnswer(): void
    {
        $r = $this->dr()->check('dre_flaggedaaaaaaaaaaaaaaa', 'sign_up', 'ayse@acme.com', '203.0.113.7');
        $this->assertSame('ok', $r['report']);
        $this->assertSame('tqv_fakeVisitor00000001', $r['visitorId']);
        $this->assertSame('DRK-2QX', $r['caseCode']);
        $this->assertFalse($r['signals'][0]['enforced']);
        $event = $this->dr()->getEvent('dre_aaaaaaaaaaaaaaaaaaaaaa');
        $this->assertSame('tqv_fakeVisitor00000001', $event['visitorId']);
        $relay = $this->dr()->check(null, 'sign_in', null, null, 'REPORT');
        $this->assertSame([], $relay['signals']);
        $this->assertSame(['device_many_accounts'], array_column($r['signals'], 'code'));
        $this->assertFalse($r['stepUp']);
        $this->assertTrue($r['wouldStepUp']);
        $this->assertSame('shadow', $r['mode']);
        $this->assertNull($r['suspect']);
        $this->assertNull($r['accountDevice']);
    }

    public function testTheFormFieldAsItCameIsAnsweredNeverThrown(): void
    {
        foreach ([null, '', ['x']] as $value) {
            $r = $this->dr()->check($value, 'sign_in', 'ayse@acme.com');
            $this->assertSame('missing', $r['report']);
            $this->assertNull($r['visitorId']);
            $this->assertSame(['device_identification_missing'], array_column($r['signals'], 'code'));
            $this->assertFalse($r['stepUp']);
            $this->assertTrue($r['wouldStepUp']);
        }
        $this->assertSame('unknown', $this->dr()->check('nope')['report']);
        $this->assertSame('invalid', TouchqueDeviceRisk::parse(['report' => 'whatever'])['report']);
    }

    public function testAWrongEventFailsBeforeAnyRequest(): void
    {
        $this->expectException(TouchqueConfigException::class);
        $this->dr()->check('nope', 'tracking');
    }

    public function testAWrongRequestIdFailsBeforeAnyRequest(): void
    {
        $this->expectException(TouchqueConfigException::class);
        $this->dr()->getEvent('../users');
    }

    public function testTheAnswerFailsTowardAsking(): void
    {
        $this->assertTrue(TouchqueDeviceRisk::parse([])['stepUp']);
        $this->assertFalse(TouchqueDeviceRisk::parse(['stepUp' => false])['stepUp']);
        $r = TouchqueDeviceRisk::parse(['signals' => [['code' => 'device_tampered', 'text' => 't'], null, ['text' => 'x']], 'requires' => 'passkey']);
        $this->assertSame([['code' => 'device_tampered', 'text' => 't', 'strength' => 'number_match']], $r['signals']);
        $this->assertSame('passkey', $r['requires']);
    }

    public function testEngineUnavailableComesThroughAndANormalAnswerHasNull(): void
    {
        $down = TouchqueDeviceRisk::parse(['report' => 'ok', 'signals' => [], 'stepUp' => true, 'wouldStepUp' => true, 'requires' => 'number_match', 'mode' => 'enforce', 'engine' => 'unavailable']);
        $this->assertSame('unavailable', $down['engine']);
        $this->assertTrue($down['stepUp']);
        $this->assertSame('number_match', $down['requires']);
        $normal = TouchqueDeviceRisk::parse(['report' => 'ok', 'signals' => [], 'stepUp' => false, 'requires' => 'none', 'mode' => 'shadow']);
        $this->assertNull($normal['engine']);
        $this->assertFalse($normal['stepUp']);
        $this->assertNull(TouchqueDeviceRisk::parse(['engine' => 42])['engine']);
    }

    public function testTheAddressTheCountsAndABotAnswerComeThrough(): void
    {
        $r = TouchqueDeviceRisk::parse(['report' => 'ok', 'network' => ['type' => 'hosting'], 'velocity' => ['identifications1h' => 2], 'bot' => ['result' => 'suspected', 'reasons' => ['pointer_synthetic']]]);
        $this->assertSame('hosting', $r['network']['type']);
        $this->assertSame(2, $r['velocity']['identifications1h']);
        $this->assertSame('suspected', $r['bot']['result']);
        $this->assertNull(TouchqueDeviceRisk::parse(['network' => 'x'])['network']);
    }

    public function testTheNetworkKindAndTheSharedFieldsComeThroughAsTheApiSendsThem(): void
    {
        $network = [
            'countryCode' => 'NL', 'region' => null, 'city' => null, 'accuracyKm' => null, 'timeZone' => 'Europe/Amsterdam',
            'asn' => 64500, 'asnOrg' => 'EXAMPLE-UNIVERSITY', 'type' => 'isp', 'tor' => false, 'hosting' => false, 'hostingProvider' => null,
            'proxy' => true, 'timezoneMismatch' => false,
            'kind' => 'education', 'kindSource' => 'network', 'vpn' => false,
            'shared' => true, 'sharedVisitors24h' => 100, 'sharedAccounts24h' => 10, 'lookAlikeMatching' => false,
        ];
        $this->assertSame($network, TouchqueDeviceRisk::parse(['report' => 'ok', 'network' => $network])['network']);
        // A private relay; a VPN company's address that a check assessed instead of the identification's (the shared fields null).
        $relay = ['type' => 'relay', 'proxy' => false, 'kind' => 'relay', 'kindSource' => 'address', 'vpn' => false];
        $this->assertSame($relay, TouchqueDeviceRisk::parse(['network' => $relay])['network']);
        $vpn = ['type' => 'hosting', 'kind' => 'vpn', 'kindSource' => 'network', 'vpn' => true, 'shared' => null, 'sharedVisitors24h' => null, 'sharedAccounts24h' => null, 'lookAlikeMatching' => null];
        $this->assertSame($vpn, TouchqueDeviceRisk::parse(['network' => $vpn])['network']);
        // An open list: a kind this version does not list comes as it was sent; an older server's network gets nothing made up.
        $newer = ['type' => 'unknown', 'kind' => 'satellite', 'kindSource' => 'operator', 'vpn' => false];
        $this->assertNotContains('satellite', TouchqueDeviceRisk::NETWORK_KINDS);
        $this->assertSame($newer, TouchqueDeviceRisk::parse(['network' => $newer])['network']);
        $older = ['countryCode' => 'DE', 'asn' => 64501, 'type' => 'hosting', 'tor' => false, 'hosting' => true, 'timezoneMismatch' => null];
        $this->assertSame($older, TouchqueDeviceRisk::parse(['network' => $older])['network']);
        $this->assertSame(
            ['residential', 'mobile_carrier', 'education', 'business', 'public_wifi', 'hosting', 'proxy', 'vpn', 'tor', 'relay', 'unknown'],
            TouchqueDeviceRisk::NETWORK_KINDS
        );
    }

    public function testTheAiAgentToolsAndTheNewBotReasonsComeThrough(): void
    {
        $bot = [
            'result' => 'detected',
            'reasons' => ['tool_claude_agent', 'tool_comet_agent', 'tool_playwright', 'headless_window', 'emulator', 'cdp', 'cdp_input', 'input_no_focus', 'insert_text_bulk', 'scripted_click'],
            'type' => 'ai_agent',
            'tools' => ['claude_agent', 'comet_agent', 'genspark_agent', 'browser_use', 'stagehand', 'skyvern', 'playwright'],
            'agent' => null,
            'input' => ['agent_pace'],
        ];
        $this->assertSame($bot, TouchqueDeviceRisk::parse(['report' => 'ok', 'bot' => $bot])['bot']);
        // A server from before the AI-agent tools sends no type, tools, agent or input: the bot stays as it came.
        $older = ['result' => 'suspected', 'reasons' => ['zero_window', 'soft_gpu']];
        $this->assertSame($older, TouchqueDeviceRisk::parse(['bot' => $older])['bot']);
    }

    public function testTheSuspectScoreAndTheAccountDeviceAreRead(): void
    {
        $r = TouchqueDeviceRisk::parse([
            'report' => 'ok',
            'suspect' => ['score' => 64, 'band' => 'high', 'wouldDo' => 'passkey', 'mode' => 'shadow', 'reasons' => [
                ['code' => 'abuse_card_testing', 'points' => 40, 'by' => 'site', 'text' => 'Cards tested'],
                ['code' => 'known_browser', 'points' => -10, 'by' => 'server', 'text' => 'Seen before'],
                'junk',
            ]],
            'accountDevice' => ['status' => 'likely', 'visitorId' => 'tqv_other00000000000000'],
        ]);
        $this->assertSame(64, $r['suspect']['score']);
        $this->assertSame('high', $r['suspect']['band']);
        $this->assertSame('passkey', $r['suspect']['wouldDo']);
        $this->assertSame('shadow', $r['suspect']['mode']);
        $this->assertSame(['abuse_card_testing', 'known_browser'], array_column($r['suspect']['reasons'], 'code'));
        $this->assertSame(['site', 'server'], array_column($r['suspect']['reasons'], 'by'));
        $this->assertSame(['status' => 'likely', 'visitorId' => 'tqv_other00000000000000'], $r['accountDevice']);
        $this->assertNull(TouchqueDeviceRisk::parseSuspect(['score' => 'x']));
        $this->assertSame('critical', TouchqueDeviceRisk::parseSuspect(['score' => 130])['band']);
        $this->assertSame(100, TouchqueDeviceRisk::parseSuspect(['score' => 130])['score']);
        $this->assertNull(TouchqueDeviceRisk::parseAccountDevice(['status' => 'maybe']));
        $this->assertSame(['status' => 'known', 'since' => '2026-11-01T00:00:00.000Z'], TouchqueDeviceRisk::parseAccountDevice(['status' => 'known', 'since' => '2026-11-01T00:00:00.000Z']));
        $this->assertContains('fpc', TouchqueDeviceRisk::MATCHED_BY);
    }

    public function testSearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters(): void
    {
        $first = $this->dr()->searchEvents(['account' => 'ada@example.com', 'stepUp' => false, 'ip' => '203.0.113.0/24', 'limit' => 1]);
        $this->assertEquals(['account' => 'ada@example.com', 'ip' => '203.0.113.0/24', 'stepUp' => 'false', 'limit' => '1'], self::$api->lastDeviceRiskSearch());
        $this->assertSame(['dre_fakeEvent00000000002'], array_column($first['events'], 'requestId'));
        $this->assertNull($first['nextCursor']);
        $seen = [];
        $cursor = null;
        do {
            $page = $this->dr()->searchEvents(['limit' => 1] + ($cursor ? ['cursor' => $cursor] : []));
            $seen = array_merge($seen, array_column($page['events'], 'requestId'));
            $cursor = $page['nextCursor'];
        } while ($cursor);
        $this->assertSame(['dre_fakeEvent00000000003', 'dre_fakeEvent00000000002', 'dre_fakeEvent00000000001'], $seen);
        $this->expectException(TouchqueConfigException::class);
        $this->dr()->searchEvents(['limit' => 101]);
    }

    public function testSearchEventsSendsTheNetworkKindAndTheSharedFilters(): void
    {
        // The fake checks the signature over the path and the query: the new filters are signed with it.
        $this->dr()->searchEvents(['networkKind' => 'public_wifi', 'shared' => true, 'kind' => 'sign_up']);
        $this->assertEquals(['networkKind' => 'public_wifi', 'shared' => 'true', 'kind' => 'sign_up'], self::$api->lastDeviceRiskSearch());
        $page = $this->dr()->searchEvents(['networkKind' => 'vpn', 'shared' => false, 'stepUp' => true, 'limit' => 1]);
        $this->assertEquals(['networkKind' => 'vpn', 'shared' => 'false', 'stepUp' => 'true', 'limit' => '1'], self::$api->lastDeviceRiskSearch());
        $this->assertSame(['dre_fakeEvent00000000003'], array_column($page['events'], 'requestId'));
        // An open list: a kind this version does not list is sent as it is (the API answers 400 invalid_network_kind if it does not know it).
        $this->dr()->searchEvents(['networkKind' => 'satellite']);
        $this->assertEquals(['networkKind' => 'satellite'], self::$api->lastDeviceRiskSearch());
        // As with stepUp: shared is a bool, anything else is no filter; an empty kind is none either.
        $this->dr()->searchEvents(['networkKind' => '', 'shared' => 'true']);
        $this->assertEquals([], self::$api->lastDeviceRiskSearch());
        $this->dr()->searchEvents(['networkKind' => null, 'shared' => null]);
        $this->assertEquals([], self::$api->lastDeviceRiskSearch());
    }

    public function testTheWebhookEventNames(): void
    {
        $this->assertSame('DEVICE_RISK_SIGNAL', WebhookEvents::DEVICE_RISK_SIGNAL);
        $this->assertSame('DEVICE_RISK_ALERT', WebhookEvents::DEVICE_RISK_ALERT);
    }
}
