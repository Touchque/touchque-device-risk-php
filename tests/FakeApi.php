<?php

namespace Touchque\DeviceRisk\Tests;

/**
 * Spawns the shared Node fake Touchque API (sdks/testing/fake-touchque-api.mjs)
 * for contract tests: verifies this SDK's requests are signed exactly like the
 * real backend expects, using a real HTTP round trip (not mocks).
 */
class FakeApi
{
    private $process;
    public string $baseUrl;

    /** testing/fake-touchque-api.mjs next to this package (sdks/ in the monorepo), or above it. */
    public static function script(): ?string
    {
        $dir = dirname(__DIR__);
        while (true) {
            $candidate = $dir . '/testing/fake-touchque-api.mjs';
            if (is_file($candidate)) {
                return $candidate;
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                return null;
            }
            $dir = $parent;
        }
    }

    public static function start(): self
    {
        $script = self::script();
        if ($script === null) {
            throw new \RuntimeException('testing/fake-touchque-api.mjs not found');
        }
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(['node', $script], $descriptors, $pipes);
        if (!is_resource($process)) {
            throw new \RuntimeException('could not start fake-touchque-api.mjs');
        }
        $line = fgets($pipes[1]);
        $data = json_decode((string)$line, true);
        if (!isset($data['port'])) {
            throw new \RuntimeException('fake-touchque-api.mjs did not report a port: ' . $line);
        }
        $api = new self();
        $api->process = $process;
        $api->baseUrl = "http://127.0.0.1:{$data['port']}";
        return $api;
    }

    private function call(string $path, array $body = []): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body === [] ? new \stdClass() : $body),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ]);
        $res = curl_exec($ch);
        return json_decode((string)$res, true) ?? [];
    }

    public function opts(array $opts): void
    {
        $this->call('/__test/opts', $opts);
    }

    /** Every signed call the fake received. */
    public function calls(): array
    {
        return $this->getJson('/__test/calls') ?? [];
    }

    /** The query of the last GET /device-risk/events. */
    public function lastDeviceRiskSearch(): ?array
    {
        return $this->getJson('/__test/last-device-risk-search');
    }

    /** The body of the last POST /device-risk/activity. */
    public function lastDeviceRiskActivity(): ?array
    {
        return $this->getJson('/__test/last-device-risk-activity');
    }

    /** Forgets every request and option. */
    public function reset(): void
    {
        $this->call('/__test/reset');
    }

    private function getJson(string $path): ?array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        $data = json_decode((string)$res, true);
        return is_array($data) ? $data : null;
    }

    public function close(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }
}
