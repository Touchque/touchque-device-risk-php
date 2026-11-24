<?php

namespace Touchque\DeviceRisk\Tests;

use PHPUnit\Framework\TestCase;
use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueAPIException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureNotInPlanException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureOffException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureReadOnlyException;
use Touchque\DeviceRisk\TouchqueDeviceRisk;

/** Device risk not in the organization's plan comes back as a typed exception, still a TouchqueAPIException. */
class FeatureErrorTest extends TestCase
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

    public function refusals(): array
    {
        return [
            ['feature_not_in_plan', TouchqueFeatureNotInPlanException::class, 'not_in_plan'],
            ['feature_read_only', TouchqueFeatureReadOnlyException::class, 'read_only'],
            ['feature_off', TouchqueFeatureOffException::class, 'off'],
        ];
    }

    /** @dataProvider refusals */
    public function testEachFeatureRefusalHasItsOwnException(string $code, string $class, string $reason): void
    {
        self::$api->reset();
        self::$api->opts(['featureRefused' => $code, 'feature' => 'device_risk']);
        try {
            (new TouchqueDeviceRisk(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->check('dre_aaaaaaaaaaaaaaaaaaaaaa');
            $this->fail('expected a feature exception');
        } catch (TouchqueAPIException $e) {
            $this->assertInstanceOf($class, $e);
            $this->assertInstanceOf(TouchqueFeatureException::class, $e);
            $this->assertSame(403, $e->getStatus());
            $this->assertSame('device_risk', $e->getFeature());
            $this->assertSame($reason, $e->getFeatureReason());
        }
    }

    public function testAnApiErrorCarriesItsStatusAndCode(): void
    {
        self::$api->reset();
        try {
            (new TouchqueDeviceRisk(new Config('tq_test_key', 'test_secret', self::$api->baseUrl)))->getEvent('dre_unknownaaaaaaaaaaaaaaa');
            $this->fail('an unknown requestId is a 404');
        } catch (TouchqueAPIException $e) {
            $this->assertNotInstanceOf(TouchqueFeatureException::class, $e);
            $this->assertSame(404, $e->getStatus());
            $this->assertSame('not_found', $e->getErrorCode());
        }
    }
}
