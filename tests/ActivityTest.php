<?php

namespace Touchque\DeviceRisk\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueConfigException;
use Touchque\DeviceRisk\TouchqueDeviceRisk;

/** activity(): what the server saw, against the shared fake Touchque API. A card number never leaves. */
class ActivityTest extends TestCase
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

    public function testAPaymentIsSentAndRecorded(): void
    {
        $a = $this->dr()->activity([
            'type' => 'payment_attempt', 'requestId' => 'dre_aaaaaaaaaaaaaaaaaaaaaa', 'clientIp' => '203.0.113.7',
            'externalUsername' => 'ayse@acme.com', 'outcome' => 'declined', 'card' => ['bin' => '411111', 'last4' => '1111'],
        ]);
        $this->assertSame(['recorded' => true, 'visitorId' => 'tqv_fakeVisitor00000001', 'signals' => []], $a);
        $this->assertSame([
            'type' => 'payment_attempt', 'requestId' => 'dre_aaaaaaaaaaaaaaaaaaaaaa', 'clientIp' => '203.0.113.7',
            'externalUsername' => 'ayse@acme.com', 'outcome' => 'declined', 'card' => ['bin' => '411111', 'last4' => '1111'],
        ], self::$api->lastDeviceRiskActivity());
    }

    public function testAFlaggedVisitorRaisesCardTesting(): void
    {
        $a = $this->dr()->activity(['type' => 'payment_attempt', 'requestId' => 'dre_flaggedaaaaaaaaaaaaaaa', 'outcome' => 'declined', 'card' => ['bin' => '41111111', 'last4' => '0004']]);
        $this->assertSame(['abuse_card_testing'], $a['signals']);
        $this->assertTrue($a['recorded']);
    }

    public function testAProbedPathAnswersItsClass(): void
    {
        $a = $this->dr()->activity(['type' => 'not_found', 'clientIp' => '203.0.113.7', 'path' => '/.env']);
        $this->assertSame('secrets', $a['pathClass']);
        $this->assertNull($a['visitorId']);
        $this->assertSame([], $a['signals']);
    }

    /** @return array<string, array{0: mixed}> */
    public function cardNumbers(): array
    {
        return [
            'number key' => [['number' => '4111111111111111']],
            'pan key' => [['bin' => '411111', 'last4' => '1111', 'pan' => '4111111111111111']],
            'number as bin' => [['bin' => '4111111111111111', 'last4' => '1111']],
            'a string' => ['4111111111111111'],
            'an int' => [4111111111111111],
            'short last4' => [['bin' => '411111', 'last4' => '111']],
            'int bin' => [['bin' => 411111, 'last4' => '1111']],
        ];
    }

    /** @dataProvider cardNumbers */
    public function testACardNumberIsRefusedBeforeAnythingIsSent($card): void
    {
        $dr = $this->dr();
        try {
            $dr->activity(['type' => 'payment_attempt', 'clientIp' => '203.0.113.7', 'card' => $card]);
            $this->fail('a card number must be refused');
        } catch (TouchqueConfigException $e) {
            $this->assertStringContainsString('never send the card number', $e->getMessage());
        }
        $this->assertSame([], self::$api->lastDeviceRiskActivity());
        $this->assertSame([], self::$api->calls());
    }

    public function testWrongFieldsAreRefusedBeforeAnyRequest(): void
    {
        $bad = [
            ['type' => 'tracking', 'clientIp' => '203.0.113.7'],
            ['clientIp' => '203.0.113.7'],
            ['type' => 'login_failed'],
            ['type' => 'login_failed', 'requestId' => ['x']],
            ['type' => 'payment_attempt', 'clientIp' => '203.0.113.7', 'outcome' => 'maybe'],
            ['type' => 'otp_sent', 'clientIp' => '203.0.113.7', 'phone' => 'call me'],
            ['type' => 'login_failed', 'clientIp' => '203.0.113.7', 'externalUsername' => str_repeat('a', 256)],
            ['type' => 'not_found', 'clientIp' => '203.0.113.7', 'path' => '/' . str_repeat('a', 2048)],
            ['type' => 'login_failed', 'clientIp' => '203.0.113.7', 'cardNumber' => '4111111111111111'],
        ];
        $dr = $this->dr();
        foreach ($bad as $activity) {
            try {
                $dr->activity($activity);
                $this->fail('refused: ' . json_encode($activity));
            } catch (TouchqueConfigException $e) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame([], self::$api->calls());
    }

    public function testTheAnswerIsReadStrictly(): void
    {
        $this->assertSame(['recorded' => false, 'visitorId' => null, 'signals' => []], TouchqueDeviceRisk::parseActivity(null));
        $this->assertSame(
            ['recorded' => false, 'visitorId' => null, 'signals' => ['abuse_probing']],
            TouchqueDeviceRisk::parseActivity(['recorded' => 'yes', 'signals' => ['abuse_probing', 7], 'pathClass' => 'nowhere'])
        );
    }
}
