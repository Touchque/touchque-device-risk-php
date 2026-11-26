<?php

namespace Touchque\DeviceRisk\Tests;

/**
 * A small fake of POST /device-risk/bot-check on 127.0.0.1, in PHP: the shared Node fake API
 * (testing/fake-touchque-api.mjs) has no bot check yet. Like the real API it checks the
 * request signature over the exact body; it keeps the last call and answers what the test
 * set with answer().
 */
class FakeBotCheckApi
{
    private const SERVER = <<<'PHP'
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
echo parse_url('tcp://' . stream_socket_get_name($server, false), PHP_URL_PORT), "\n";
$fresh = (object)['status' => 200, 'body' => new stdClass(), 'headers' => new stdClass()];
$answer = $fresh;
$last = null;
$calls = 0;
$reply = static function ($conn, int $status, $body, array $headers = []): void {
    $json = json_encode($body);
    $head = "HTTP/1.1 {$status} Fake\r\nContent-Type: application/json\r\nContent-Length: " . strlen($json) . "\r\nConnection: close\r\n";
    foreach ($headers as $name => $value) {
        $head .= "{$name}: {$value}\r\n";
    }
    fwrite($conn, $head . "\r\n" . $json);
};
while ($conn = @stream_socket_accept($server, 60)) {
    $start = explode(' ', trim((string)fgets($conn)));
    $method = $start[0];
    $target = $start[1] ?? '';
    $headers = [];
    while (($line = fgets($conn)) !== false && trim($line) !== '') {
        $kv = explode(':', $line, 2);
        $headers[strtolower(trim($kv[0]))] = trim($kv[1] ?? '');
    }
    if (strtolower($headers['expect'] ?? '') === '100-continue') {
        fwrite($conn, "HTTP/1.1 100 Continue\r\n\r\n"); // curl asks before a body over 1 KB
    }
    $length = (int)($headers['content-length'] ?? 0);
    $raw = '';
    while (strlen($raw) < $length && !feof($conn)) {
        $raw .= (string)fread($conn, $length - strlen($raw));
    }
    if ($target === '/__test/answer') {
        $answer = json_decode($raw);
        $reply($conn, 200, new stdClass());
    } elseif ($target === '/__test/last') {
        $reply($conn, 200, ['calls' => $calls, 'last' => $last]);
    } elseif ($target === '/__test/reset') {
        [$answer, $last, $calls] = [$fresh, null, 0];
        $reply($conn, 200, new stdClass());
    } else {
        $calls++;
        $message = strtoupper($method) . ':' . $target . ':' . ($headers['x-timestamp'] ?? '') . ':' . ($headers['x-nonce'] ?? '') . ':' . hash('sha256', $raw);
        $signed = ($headers['x-api-key'] ?? '') === 'tq_test_key'
            && hash_equals(hash_hmac('sha256', $message, 'test_secret'), $headers['x-signature'] ?? '');
        $last = ['method' => $method, 'path' => $target, 'signed' => $signed, 'raw' => $raw, 'body' => json_decode($raw, true)];
        if ($signed) {
            $reply($conn, $answer->status, $answer->body, (array)$answer->headers);
        } else {
            $reply($conn, 401, ['error' => 'Invalid signature', 'code' => 'invalid_signature']);
        }
    }
    fclose($conn);
}
PHP;

    /** @var resource */
    private $process;
    public string $baseUrl;

    public static function start(): self
    {
        $process = proc_open([PHP_BINARY, '-r', self::SERVER], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw new \RuntimeException('could not start the fake bot check API');
        }
        $port = (int)trim((string)fgets($pipes[1]));
        if ($port <= 0) {
            throw new \RuntimeException('the fake bot check API did not report a port');
        }
        $api = new self();
        $api->process = $process;
        $api->baseUrl = "http://127.0.0.1:{$port}";
        return $api;
    }

    /** What the next bot checks answer: an HTTP status, a JSON body and extra response headers. */
    public function answer(int $status, array $body, array $headers = []): void
    {
        $this->call('/__test/answer', [
            'status' => $status,
            'body' => $body === [] ? new \stdClass() : $body,
            'headers' => $headers === [] ? new \stdClass() : $headers,
        ]);
    }

    /** The last signed call: method, path, signed (the signature checked out), raw (the body as sent) and body (decoded). */
    public function last(): ?array
    {
        return $this->call('/__test/last')['last'] ?? null;
    }

    /** How many calls reached the fake since the last reset(). */
    public function calls(): int
    {
        return (int)($this->call('/__test/last')['calls'] ?? 0);
    }

    /** Forgets the calls and the answer (back to 200 with an empty body). */
    public function reset(): void
    {
        $this->call('/__test/reset');
    }

    private function call(string $path, ?array $body = null): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($body ?? new \stdClass()),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ]);
        $data = json_decode((string)curl_exec($ch), true);
        return is_array($data) ? $data : [];
    }

    public function close(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }
}
