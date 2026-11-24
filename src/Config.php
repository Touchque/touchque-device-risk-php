<?php

namespace Touchque\DeviceRisk;

use Touchque\DeviceRisk\Exceptions\TouchqueConfigException;

class Config
{
    public const DEFAULT_BASE_URL = 'https://api.touchque.com';

    /** @internal The message of the TouchqueConfigException for a missing key or secret. */
    public const MISSING_KEYS = 'Set TQ_API_KEY and TQ_API_SECRET (or pass them to Config).';

    private string $apiKey;
    private string $apiSecret;
    private string $baseUrl;
    private int $timeout;

    /**
     * Falls back to the environment when an argument is omitted: `TQ_API_KEY`,
     * `TQ_API_SECRET`, `TQ_API_URL` (default `https://api.touchque.com`).
     * The same API key and secret as the main Touchque SDK. `$timeout` is milliseconds.
     */
    public function __construct(
        ?string $apiKey = null,
        ?string $apiSecret = null,
        ?string $baseUrl = null,
        int $timeout = 10000
    ) {
        $apiKey = $apiKey ?? (getenv('TQ_API_KEY') ?: null);
        $apiSecret = $apiSecret ?? (getenv('TQ_API_SECRET') ?: null);
        $baseUrl = $baseUrl ?? (getenv('TQ_API_URL') ?: self::DEFAULT_BASE_URL);

        if (!$apiKey || !$apiSecret) {
            throw new TouchqueConfigException(self::MISSING_KEYS);
        }
        if (strpos($apiKey, 'tq_') !== 0) {
            throw new TouchqueConfigException('apiKey must start with "tq_". Did you accidentally swap apiKey and apiSecret?');
        }
        self::assertSafeBaseUrl($baseUrl);
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->timeout = $timeout;
    }

    /** Allow plaintext http only for localhost / loopback (local development). */
    private static function assertSafeBaseUrl(string $baseUrl): void
    {
        $scheme = strtolower((string)parse_url($baseUrl, PHP_URL_SCHEME));
        $host = strtolower((string)parse_url($baseUrl, PHP_URL_HOST));
        if ($scheme === 'https') {
            return;
        }
        // parse_url() keeps the brackets of an IPv6 host: http://[::1]:3000 gives "[::1]".
        if ($scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true)) {
            return;
        }
        if ($scheme === 'http') {
            throw new TouchqueConfigException(
                "Refusing a plaintext http:// baseUrl for \"{$host}\". The API key and request "
                . 'signature would be sent in the clear — use https://.'
            );
        }
        throw new TouchqueConfigException("baseUrl must be http(s): {$baseUrl}");
    }

    public function getApiKey(): string
    {
        return $this->apiKey;
    }

    public function getApiSecret(): string
    {
        return $this->apiSecret;
    }

    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }
}
