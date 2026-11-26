<?php

namespace Touchque\DeviceRisk\Http;

use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueAPIException;
use Touchque\DeviceRisk\Exceptions\TouchqueFeatureException;
use Touchque\DeviceRisk\Exceptions\TouchqueNetworkException;

/**
 * @internal Every partner API call: signed with HMAC-SHA256 over
 * "METHOD:pathWithQuery:timestamp:nonce:sha256(body)", sent once, never redirected.
 * The same signing as the main Touchque SDK.
 */
class HttpClient
{
    public const SDK_VERSION = '1.1.0';
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function post(string $endpoint, array $body): array
    {
        return $this->send('POST', $endpoint, self::encode($body));
    }

    /** JSON with `{}` for an empty body (never `[]`): exactly what post() sends (botCheck() measures it). */
    public static function encode(array $body): string
    {
        $bodyStr = json_encode($body === [] ? new \stdClass() : $body);
        if ($bodyStr === false) {
            throw new \InvalidArgumentException('Invalid JSON body provided.');
        }
        return $bodyStr;
    }

    public function get(string $endpoint, array $params = []): array
    {
        $pathWithQuery = $endpoint . self::buildQuery($params);
        return $this->send('GET', $pathWithQuery, '');
    }

    /** Deterministic query string: keys sorted, booleans as `true`/`false`, `?`-prefixed (or ''). */
    private static function buildQuery(array $params): string
    {
        $params = array_filter($params, static fn ($v) => $v !== null);
        if (empty($params)) {
            return '';
        }
        ksort($params);
        // http_build_query() would send 1/0, which the API reads as no filter at all.
        $params = array_map(static fn ($v) => is_bool($v) ? ($v ? 'true' : 'false') : $v, $params);
        return '?' . http_build_query($params);
    }

    private function send(string $method, string $pathWithQuery, string $bodyStr): array
    {
        $url = $this->config->getBaseUrl() . $pathWithQuery;
        $timestamp = (string)(time() * 1000);
        $nonce = bin2hex(random_bytes(16));
        $signature = $this->signRequest($method, $pathWithQuery, $bodyStr, $timestamp, $nonce);

        $headers = [
            'x-api-key: ' . $this->config->getApiKey(),
            'x-signature: ' . $signature,
            'x-timestamp: ' . $timestamp,
            'x-nonce: ' . $nonce,
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: touchque-device-risk-php/' . self::SDK_VERSION,
        ];

        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT_MS => $this->config->getTimeout(),
            // An API endpoint should never redirect; following one could replay
            // the signed auth headers to another host.
            CURLOPT_FOLLOWLOCATION => false,
        ];
        if ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $bodyStr;
        }
        curl_setopt_array($ch, $opts);

        $raw = curl_exec($ch);
        $error = curl_error($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        if (\PHP_VERSION_ID < 80000) {
            curl_close($ch); // no-op + deprecated on PHP >= 8.0
        }

        if ($error || $raw === false) {
            throw new TouchqueNetworkException('Network error: ' . $error);
        }

        $headerText = substr($raw, 0, $headerSize);
        $body = substr($raw, $headerSize);
        $responseData = json_decode($body, true);
        if (!is_array($responseData)) {
            $responseData = [];
        }

        // A redirect is not followed (see above) and is never an answer: a 3xx is an error too, or a
        // wrong baseUrl would read as an empty success.
        if ($statusCode >= 300) {
            $errorMessage = $responseData['error'] ?? $responseData['message']
                ?? ($statusCode < 400 ? "Unexpected redirect (HTTP {$statusCode}) from the API: check the baseUrl" : 'Unknown API Error');
            $retryAfter = $responseData['retryAfter'] ?? self::readRetryAfterHeader($headerText);
            if ($retryAfter !== null) {
                $responseData['retryAfter'] = (int)$retryAfter;
            }
            throw TouchqueFeatureException::fromResponse((string)$errorMessage, $statusCode, $responseData);
        }

        return $responseData;
    }

    private static function readRetryAfterHeader(string $headerText): ?int
    {
        if (preg_match('/^Retry-After:\s*(\d+)/mi', $headerText, $m)) {
            return (int)$m[1];
        }
        return null;
    }

    private function signRequest(string $method, string $pathWithQuery, string $body, string $timestamp, string $nonce): string
    {
        $bodyHash = hash('sha256', $body);
        $message = strtoupper($method) . ':' . $pathWithQuery . ':' . $timestamp . ':' . $nonce . ':' . $bodyHash;
        return hash_hmac('sha256', $message, $this->config->getApiSecret());
    }
}
