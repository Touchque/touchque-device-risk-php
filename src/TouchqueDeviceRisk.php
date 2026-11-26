<?php

namespace Touchque\DeviceRisk;

use Touchque\DeviceRisk\Exceptions\TouchqueConfigException;
use Touchque\DeviceRisk\Http\HttpClient;

/**
 * Touchque Device Risk (a paid add-on, off until your workspace turns it on): a
 * visitor ID for every browser on your sign-up, password-reset, sign-in or
 * approval page, and what your server saw it do.
 *
 * The page identifies with `@touchque/device-risk` (the script tag, or
 * `identify({ siteKey, purpose })`, which gives `{ visitorId, requestId, confidence }`)
 * and sends you the requestId. Never trust the page's copy: read the
 * identification here (`getEvent`) or check it for an account (`check`).
 * Touchque keeps keyed hashes only, with a key of your workspace alone, and its
 * risk engine decides.
 *
 * Every signal only ever asks for more: `stepUp` means an extra check on this
 * page (an emailed code, a passkey, a number-matched approval), never a
 * refusal. For phone-approved sign-ins with the main Touchque SDK, pass the
 * requestId as `deviceRiskRequestId` to its `login->request` / `risk->check`.
 * Collect it only on these pages and name it in your privacy notice.
 *
 * With the script tag (device.js), the form arrives with `touchque_request_id`:
 *
 *     $dr = new TouchqueDeviceRisk();   // TQ_API_KEY, TQ_API_SECRET
 *     $r = $dr->check($_POST['touchque_request_id'] ?? null, 'sign_in', $email);
 *
 * Pass it as it came. Missing, empty, made up or expired, it is still a
 * verdict (`report`: missing, unknown, expired; the signal
 * device_identification_missing), never an exception: a page without the tag,
 * or with it blocked, only gets the visitor a step-up.
 *
 * Many bots never run JavaScript, so the tag never sees them (ChatGPT-User,
 * GPTBot, Meta's crawlers, curl, scripts): `botCheck()` checks one request on
 * your server from its IP and headers alone.
 */
class TouchqueDeviceRisk
{
    /** The pages a device report may come from. */
    public const EVENTS = ['sign_in', 'sign_up', 'password_reset', 'approval'];
    /** What the page had sent: ok, replayed, or no usable identification. */
    public const REPORTS = ['ok', 'replayed', 'missing', 'unknown', 'expired', 'invalid'];
    /** How a visitor was recognised (an event's `matchedBy`). */
    public const MATCHED_BY = ['key', 'fpc', 'sid', 'traits', 'new'];
    /** The kind of network (`network['kind']`, searchEvents()' `networkKind`). New ones may be added in minor versions: a kind this version does not list comes as it was sent. */
    public const NETWORK_KINDS = ['residential', 'mobile_carrier', 'education', 'business', 'public_wifi', 'hosting', 'proxy', 'vpn', 'tor', 'relay', 'unknown'];
    /** What your server saw the visitor do (`activity()`'s `type`). */
    public const ACTIVITY_TYPES = ['payment_attempt', 'login_failed', 'not_found', 'forbidden', 'otp_sent', 'code_failed'];
    /** payment_attempt: what the payment provider answered. */
    public const ACTIVITY_OUTCOMES = ['approved', 'declined', 'error'];
    /** The abuse codes an activity can raise. New codes may be added. */
    public const ACTIVITY_SIGNALS = ['abuse_card_testing', 'abuse_card_shared', 'abuse_login_failures', 'abuse_probing', 'abuse_otp_pumping', 'abuse_code_guessing'];
    /** The class of a not_found / forbidden path. */
    public const PATH_CLASSES = ['admin', 'wordpress', 'secrets', 'source', 'db_admin', 'debug', 'shell', 'other'];
    /** What a bot check found (`bot['result']`): detected (sure), suspected (signs point to software) or not_detected. */
    public const BOT_CHECK_RESULTS = ['detected', 'suspected', 'not_detected'];
    /** The kind of bot (`bot['category']`). New ones may be added: a category this version does not list comes as it was sent. */
    public const BOT_CHECK_CATEGORIES = ['ai_agent', 'ai_assistant', 'ai_crawler', 'ai_search', 'search_crawler', 'link_preview', 'seo', 'monitoring', 'archiver', 'feed_reader', 'security_scanner', 'http_client', 'headless_browser', 'automation'];
    /** Is the bot who it says (`bot['identity']`): verified (proven), unverified (a spoofed name) or claimed (a name that cannot be checked). */
    public const BOT_CHECK_IDENTITIES = ['verified', 'unverified', 'claimed'];
    /** What proved a verified bot (`bot['verifiedBy']`). */
    public const BOT_CHECK_VERIFIED_BY = ['signature', 'ip_list', 'reverse_dns', 'asn'];
    /** How sure the answer is (`bot['confidence']`). */
    public const BOT_CHECK_CONFIDENCES = ['high', 'medium', 'low'];
    /** What Touchque would do (`suggestion`): advice in shadow, Touchque never enforces it. */
    public const BOT_CHECK_SUGGESTIONS = ['allow', 'block', 'challenge'];
    /** The request's HTTP version (`httpVersion`). */
    public const BOT_CHECK_HTTP_VERSIONS = ['1.0', '1.1', '2', '3'];
    /** Headers a bot check always sends with an empty value: the name stays, for the order. */
    public const BOT_CHECK_BLANKED_HEADERS = ['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'set-cookie'];

    private const REQUEST_ID = '/^dre_[A-Za-z0-9_-]{22}$/';
    private const ACTIVITY_FIELDS = ['type', 'requestId', 'visitorId', 'clientIp', 'externalUsername', 'outcome', 'card', 'phone', 'path'];
    private const BOT_CHECK_FIELDS = ['ip', 'headers', 'method', 'url', 'httpVersion', 'tls'];
    // The API's limits for a bot check (a browser sends 10 to 30 headers, a few KB in all).
    private const BOT_CHECK_MAX_HEADERS = 100;
    private const BOT_CHECK_MAX_NAME = 128;
    private const BOT_CHECK_MAX_VALUE = 4096;
    // 32 KB, kept a little under 32 KiB so either reading of the API's limit holds.
    private const BOT_CHECK_MAX_BODY = 32000;
    // A longer URL is left out, never cut: a signature may cover its path.
    private const BOT_CHECK_MAX_URL = 4096;
    private const BOT_CHECK_MAX_JA4 = 128;
    // The methods the API reads; anything else is left out.
    private const BOT_CHECK_METHOD = '/^[A-Za-z]{1,16}$/D';
    // A header name as HTTP allows it (RFC 9110 token).
    private const BOT_CHECK_TOKEN = "/^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$/D";

    private HttpClient $http;

    /** Reads TQ_API_KEY, TQ_API_SECRET and TQ_API_URL when no Config is given. */
    public function __construct(?Config $config = null)
    {
        $this->http = new HttpClient($config ?? new Config());
    }

    /**
     * Checks the page's identification for an account: binds it (one account
     * per identification, 15 minutes) and asks the risk engine. Pass the form
     * field as it came: null, empty or made up is still a verdict (`report`:
     * missing, unknown), never an exception. 409 `device_risk_off` until your
     * workspace turns Device risk on.
     *
     *     $r = $dr->check($_POST['touchque_request_id'] ?? null, 'sign_up', $email, $_SERVER['REMOTE_ADDR']);
     *     if ($r['stepUp']) { askForEmailCode(); }   // never refuse on it alone
     *
     * @param mixed   $requestId  the touchque_request_id form field (the script tag) or identify()'s requestId, as it came
     * @param ?string $deviceRisk instead of $requestId: the page's report (collect()), relayed untouched
     * @throws TouchqueConfigException when the event is unknown (a bug in your code, not the page).
     */
    public function check($requestId, string $event = 'sign_in', ?string $externalUsername = null, ?string $clientIp = null, ?string $deviceRisk = null): array
    {
        if (!in_array($event, self::EVENTS, true)) {
            throw new TouchqueConfigException('check(): event must be one of ' . implode(', ', self::EVENTS));
        }
        $body = [];
        if (is_string($requestId) && $requestId !== '') {
            $body['requestId'] = substr($requestId, 0, 64);
        } elseif ($deviceRisk !== null && $deviceRisk !== '') {
            $body['deviceRisk'] = $deviceRisk;
        }
        $body['event'] = $event;
        if ($externalUsername !== null && $externalUsername !== '') {
            $body['externalUsername'] = $externalUsername;
        }
        if ($clientIp !== null && $clientIp !== '') {
            $body['clientIp'] = $clientIp;
        }
        return self::parse($this->http->post('/device-risk/check', $body));
    }

    /**
     * Your workspace's identifications, newest first, one page at a time: a date range
     * (`from`/`to`: YYYY-MM-DD or ISO times; 7 days by default, at most 90, within your
     * retention) and any of `signal`, `stepUp`, `kind` (the page), `origin`, `ip` (an address
     * or a CIDR range, never returned), `account`, `visitorId`, `requestId`, `networkKind`,
     * `shared`, `limit` (1 to 100) and the opaque `cursor`. Pass `nextCursor` back as `cursor`
     * until it is null; do not page by moving the dates. A search that would read too much is
     * a 422 `search_too_broad`: narrow the range or add a filter. Each event may carry
     * `suspect` (see `parseSuspect()`), `matchedBy` (`MATCHED_BY`), `network` and `bot` (see
     * `parse()`).
     *
     * `networkKind` is the kind of network (`NETWORK_KINDS`; one the API does not know is a 400
     * `invalid_network_kind`): only identifications classified since network kinds match,
     * older ones have none. `shared` (a bool, like `stepUp`): true finds the identifications
     * whose own address was shared, false the ones counted and not shared; one that was not
     * counted matches neither. Older servers ignore both.
     * Returns `['events' => [...], 'nextCursor' => ?string, 'from' => string, 'to' => string]`.
     */
    public function searchEvents(array $options = []): array
    {
        $params = [];
        foreach (['from', 'to', 'signal', 'kind', 'origin', 'ip', 'account', 'visitorId', 'requestId', 'networkKind', 'cursor'] as $k) {
            if (isset($options[$k]) && is_string($options[$k]) && $options[$k] !== '') {
                $params[$k] = $options[$k];
            }
        }
        foreach (['stepUp', 'shared'] as $k) {
            if (isset($options[$k]) && is_bool($options[$k])) {
                $params[$k] = $options[$k] ? 'true' : 'false';
            }
        }
        if (array_key_exists('limit', $options)) {
            $limit = $options['limit'];
            if (!is_int($limit) || $limit < 1 || $limit > 100) {
                throw new TouchqueConfigException('searchEvents() limit must be 1 to 100');
            }
            $params['limit'] = $limit;
        }
        $raw = $this->http->get('/device-risk/events', $params);
        $next = $raw['nextCursor'] ?? null;
        return [
            'events' => isset($raw['events']) && is_array($raw['events']) ? $raw['events'] : [],
            'nextCursor' => is_string($next) && $next !== '' ? $next : null,
            'from' => is_string($raw['from'] ?? null) ? $raw['from'] : '',
            'to' => is_string($raw['to'] ?? null) ? $raw['to'] : '',
        ];
    }

    /**
     * The trusted identification behind a requestId: the visitor, how sure, what the
     * page showed, the engine's verdict, `network` and `bot` (see `parse()`), `accountDevice`
     * and `suspect` (read them with `parseAccountDevice()` / `parseSuspect()`).
     * `visitor['mark']` is the mark actually applied (see `parse()`).
     */
    public function getEvent(string $requestId): array
    {
        if (!preg_match(self::REQUEST_ID, $requestId)) {
            throw new TouchqueConfigException('getEvent() needs a requestId (dre_...)');
        }
        return $this->http->get('/device-risk/events/' . rawurlencode($requestId));
    }

    /**
     * Reports what a visitor did that your server saw (POST /device-risk/activity):
     * payments, failed sign-ins, probing, SMS codes, wrong codes. Touchque counts it per
     * visitor and per network and answers the abuse codes it raised; for 24 hours the
     * visitor's next identifications and checks carry them (shadow: they decide nothing on
     * their own).
     *
     *     $a = $dr->activity([
     *         'type' => 'payment_attempt', 'requestId' => $_POST['touchque_request_id'] ?? null,
     *         'clientIp' => $_SERVER['REMOTE_ADDR'], 'outcome' => 'declined',
     *         'card' => ['bin' => '411111', 'last4' => '1111'],
     *     ]);
     *     if (in_array('abuse_card_testing', $a['signals'], true)) { stopTakingCards(); }
     *
     * `$activity`: `type` (`ACTIVITY_TYPES`, required), `requestId` (the form field as it
     * came), `visitorId` (tqv_…), `clientIp` (required when neither id is known),
     * `externalUsername`, `outcome` (`ACTIVITY_OUTCOMES`), `card` (`['bin' => 6-8 digits,
     * 'last4' => 4 digits]`), `phone` (otp_sent), `path` (not_found / forbidden).
     *
     * Never send a card number: a card that is not exactly a BIN and the last 4 digits is
     * refused here, before anything is sent.
     *
     * Returns `['recorded' => bool, 'visitorId' => ?string, 'signals' => string[]]`, plus
     * `'pathClass'` (`PATH_CLASSES`) for a path.
     * @throws TouchqueConfigException for a wrong field (nothing is sent).
     */
    public function activity(array $activity): array
    {
        return self::parseActivity($this->http->post('/device-risk/activity', self::activityBody($activity)));
    }

    /** @internal The request body of activity(), validated. */
    public static function activityBody(array $activity): array
    {
        foreach (array_keys($activity) as $key) {
            if (!in_array($key, self::ACTIVITY_FIELDS, true)) {
                throw new TouchqueConfigException("activity() does not know '{$key}'");
            }
        }
        $type = $activity['type'] ?? null;
        if (!is_string($type) || !in_array($type, self::ACTIVITY_TYPES, true)) {
            throw new TouchqueConfigException('activity(): type must be one of ' . implode(', ', self::ACTIVITY_TYPES));
        }
        $body = ['type' => $type];
        foreach (['requestId', 'visitorId', 'clientIp', 'externalUsername', 'phone', 'path'] as $k) {
            $v = $activity[$k] ?? null;
            if ($v === null || $v === '') {
                continue;
            }
            if (!is_string($v)) {
                if ($k === 'requestId') {
                    continue; // the form field as it came: anything but a string is no identification
                }
                throw new TouchqueConfigException("activity(): {$k} must be a string");
            }
            $body[$k] = $v;
        }
        if (!isset($body['requestId']) && !isset($body['visitorId']) && !isset($body['clientIp'])) {
            throw new TouchqueConfigException('activity(): name the visitor: requestId, visitorId or clientIp');
        }
        if (isset($body['externalUsername']) && strlen($body['externalUsername']) > 255) {
            throw new TouchqueConfigException('activity(): externalUsername is at most 255 characters');
        }
        if (isset($body['path']) && strlen($body['path']) > 2048) {
            throw new TouchqueConfigException('activity(): path is at most 2048 characters');
        }
        if (isset($body['phone']) && !preg_match('/^\+?[0-9]{6,15}$/', $body['phone'])) {
            throw new TouchqueConfigException('activity(): phone must be 6 to 15 digits, with an optional leading +');
        }
        $outcome = $activity['outcome'] ?? null;
        if ($outcome !== null) {
            if (!is_string($outcome) || !in_array($outcome, self::ACTIVITY_OUTCOMES, true)) {
                throw new TouchqueConfigException('activity(): outcome must be one of ' . implode(', ', self::ACTIVITY_OUTCOMES));
            }
            $body['outcome'] = $outcome;
        }
        if (array_key_exists('card', $activity) && $activity['card'] !== null) {
            $body['card'] = self::card($activity['card']);
        }
        return $body;
    }

    /** A card as its BIN and last 4 digits only; anything that could be a card number is refused. */
    private static function card($card): array
    {
        $never = 'activity(): never send the card number: card is [\'bin\' => 6 to 8 digits, \'last4\' => 4 digits]';
        if (!is_array($card)) {
            throw new TouchqueConfigException($never);
        }
        $keys = array_keys($card);
        sort($keys);
        if ($keys !== ['bin', 'last4']) {
            throw new TouchqueConfigException($never);
        }
        $bin = $card['bin'];
        $last4 = $card['last4'];
        if (!is_string($bin) || !is_string($last4) || !preg_match('/^[0-9]{6,8}$/', $bin) || !preg_match('/^[0-9]{4}$/', $last4)) {
            throw new TouchqueConfigException($never);
        }
        return ['bin' => $bin, 'last4' => $last4];
    }

    /** Reads an activity answer: `recorded` only when it says exactly true; unknown path classes are dropped. */
    public static function parseActivity($raw): array
    {
        $body = is_array($raw) ? $raw : [];
        $out = [
            'recorded' => ($body['recorded'] ?? null) === true,
            'visitorId' => is_string($body['visitorId'] ?? null) ? $body['visitorId'] : null,
            'signals' => array_values(array_filter(is_array($body['signals'] ?? null) ? $body['signals'] : [], 'is_string')),
        ];
        if (in_array($body['pathClass'] ?? null, self::PATH_CLASSES, true)) {
            $out['pathClass'] = $body['pathClass'];
        }
        return $out;
    }

    /**
     * Checks one visitor request on your server for bots (POST /device-risk/bot-check), also
     * the ones that never run your page's JavaScript: ChatGPT-User, GPTBot, Meta's crawlers,
     * curl, scripts. Send the request's IP and headers; Touchque answers which bot it is,
     * whether that identity is proven, and what it would do. It decides on its own servers
     * with its own data (the operators' published addresses and keys, its own reverse DNS):
     * what it cannot check right now is "cannot tell", never a guess and never a block.
     *
     *     $check = $dr->botCheck(TouchqueDeviceRisk::botCheckRequestFromServer());
     *     if ($check['bot']['identity'] === 'unverified') { ... }   // a spoofed bot name
     *
     * `$request`:
     * - `ip` (required): the visitor's IPv4 or IPv6 address, as your server saw it (an
     *   `::ffff:` IPv4 address goes as the IPv4 one, a `%zone` is dropped).
     * - `headers` (required): the visitor request's headers as `[[name, value], ...]`, in the
     *   order received (`[]` for a request that had none). `[name => value]` is taken too (a
     *   list of values is joined with ", ") and goes with its order unknown. A null value is no
     *   header, and HTTP/2 pseudo-headers (`:path` holds the query string) are left out. Past
     *   100, the rest is left out (more is not a browser), never an error. A name is cut to 128
     *   characters and a value to 4096; when the whole would pass the API's 32 KB, the longest
     *   values are cut further, so every name and the start of every value still go; then
     *   `truncated: true` tells Touchque. A header HTTP does not allow is left out too.
     * - `method` (1 to 16 letters, else left out), `url` (only its host and path leave your
     *   server, never the query string or a user:password@; a host Touchque could not read goes
     *   as the path alone), and only when your edge tells you what the visitor's were,
     *   `httpVersion` (`BOT_CHECK_HTTP_VERSIONS`; "HTTP/1.1" and "h2" are read too, anything
     *   else is left out) and `tls` (`['ciphers' => ..., 'ja4' => ...]`). Never your server's own
     *   protocol: behind a proxy that is the proxy's connection.
     *
     * Authorization, Cookie, Proxy-Authorization, X-Api-Key and Set-Cookie always go with
     * empty values (`BOT_CHECK_BLANKED_HEADERS`): their names stay, for the order. Touchque
     * never logs or stores header values and keeps nothing from a bot check but short-lived,
     * keyed-hash burst counters.
     *
     * Returns `['bot' => [...], 'network' => ?[...], 'suggestion' => ?string, 'rulesVersion' => ?string]`:
     * see `parseBotCheck()`. The check has its own budget per workspace: past it, a 429
     * TouchqueAPIException (`getRetryAfter()`); a request the API refuses is a 400 one
     * (`getErrorCode()`: invalid_ip, headers_required, too_large, invalid_body).
     * @throws TouchqueConfigException for a wrong field (nothing is sent).
     */
    public function botCheck(array $request): array
    {
        return self::parseBotCheck($this->http->post('/device-risk/bot-check', self::botCheckBody($request)));
    }

    /**
     * botCheck()'s request from PHP's `$_SERVER` (the default) or an array shaped like it, such
     * as Laravel's `$request->server->all()`: REMOTE_ADDR, the HTTP_* headers in the order PHP
     * gives them (with CONTENT_TYPE and CONTENT_LENGTH, which CGI names without HTTP_), the
     * method and the host and path (never the query string).
     *
     * PHP does not keep a header name's case, so names come lowercase. Sensitive headers come
     * with empty values (`BOT_CHECK_BLANKED_HEADERS`). Nothing a visitor sent makes botCheck()
     * throw: past 100 headers botCheck() keeps the first 100 and tells Touchque. Behind a proxy
     * or a load balancer REMOTE_ADDR is the proxy's: pass the visitor's address your framework
     * trusts as `$ip` (Laravel: `$request->ip()`, which follows TrustProxies). The SDK never
     * reads X-Forwarded-For itself: anyone can send it. SERVER_PROTOCOL is not sent: behind a
     * proxy it is the proxy's connection, not the visitor's. Add `httpVersion` and `tls`
     * yourself when your edge tells you what the visitor's were.
     */
    public static function botCheckRequestFromServer(?array $server = null, ?string $ip = null): array
    {
        $server = $server ?? $_SERVER;
        $text = static fn (string $key): string => is_string($server[$key] ?? null) ? $server[$key] : '';
        $headers = [];
        foreach ($server as $key => $value) {
            if (!is_string($key) || !is_string($value) || $value === '') {
                continue; // an empty one is mostly a FastCGI config line (HTTP_PROXY ""), not the visitor
            }
            if (strncmp($key, 'HTTP_', 5) === 0) {
                $name = substr($key, 5);
            } elseif (($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') && !isset($server['HTTP_' . $key])) {
                $name = $key;
            } else {
                continue;
            }
            $name = strtolower(str_replace('_', '-', trim($name)));
            if ($name === '') {
                continue;
            }
            $headers[] = [$name, in_array($name, self::BOT_CHECK_BLANKED_HEADERS, true) ? '' : $value];
        }
        $request = ['ip' => $ip ?? $text('REMOTE_ADDR'), 'headers' => $headers];
        if ($text('REQUEST_METHOD') !== '') {
            $request['method'] = $text('REQUEST_METHOD');
        }
        $url = (string)preg_replace('/[?#].*/s', '', $text('REQUEST_URI'));
        if (strncmp($url, '/', 1) === 0) {
            // The Host header as it came, else the name your server answers to.
            $host = $text('HTTP_HOST') !== '' ? $text('HTTP_HOST') : $text('SERVER_NAME');
            $secure = ($text('HTTPS') !== '' && strtolower($text('HTTPS')) !== 'off') || $text('REQUEST_SCHEME') === 'https';
            $url = $host !== '' ? ($secure ? 'https' : 'http') . '://' . $host . $url : $url; // no host: the path alone
        } elseif (!preg_match('#^[a-z][a-z0-9+.\-]*://#i', $url)) {
            $url = ''; // `*` (OPTIONS *): no URL; an absolute target, as a proxy request has, goes as it came
        }
        if ($url !== '') {
            $request['url'] = $url;
        }
        return $request;
    }

    /** @internal The request body of botCheck(): validated, sensitive values emptied, cut to the API's limits. */
    public static function botCheckBody(array $request): array
    {
        foreach (array_keys($request) as $key) {
            if (!in_array($key, self::BOT_CHECK_FIELDS, true)) {
                throw new TouchqueConfigException("botCheck() does not know '{$key}'");
            }
        }
        $ip = is_string($request['ip'] ?? null) ? trim($request['ip']) : '';
        $ip = explode('%', $ip, 2)[0]; // a zone (fe80::1%eth0) means nothing outside your host
        if (preg_match('/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $mapped) && filter_var($mapped[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $ip = $mapped[1]; // how a dual-stack server shows an IPv4 visitor: it goes as the IPv4 address, as Touchque's lists write it
        }
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new TouchqueConfigException("botCheck(): ip is required: the visitor's IPv4 or IPv6 address, as your server saw it");
        }
        $headers = $request['headers'] ?? null;
        if (!is_array($headers)) {
            throw new TouchqueConfigException('botCheck(): headers are required: [[name, value], ...] in the order received');
        }
        // A list is pairs in the order received; a name => value map goes as an object, its order unknown.
        $asMap = $headers !== [] && array_keys($headers) !== range(0, count($headers) - 1);
        $pairs = [];
        $truncated = false;
        foreach ($headers as $key => $header) {
            if ($asMap) {
                $header = [(string)$key, $header];
            } elseif (!is_array($header) || count($header) !== 2 || !array_key_exists(0, $header) || !array_key_exists(1, $header)) {
                throw new TouchqueConfigException('botCheck(): each header is a [name, value] pair');
            }
            [$name, $value] = $header;
            if (!is_string($name) || trim($name) === '') {
                throw new TouchqueConfigException('botCheck(): a header name is a non-empty string');
            }
            $name = trim($name);
            if ($value === null || $name[0] === ':') {
                continue; // no value, no header; an HTTP/2 pseudo-header: method and url carry it, and :path has the query
            }
            $value = self::botCheckValue($name, $value);
            if (!preg_match(self::BOT_CHECK_TOKEN, $name) || strpbrk($value, "\r\n\0") !== false) {
                $truncated = true; // a header HTTP does not allow: the API would refuse the whole check for it
                continue;
            }
            $sent = self::cut($value, self::BOT_CHECK_MAX_VALUE);
            $truncated = $truncated || strlen($name) > self::BOT_CHECK_MAX_NAME || $sent !== $value;
            $pairs[] = [substr($name, 0, self::BOT_CHECK_MAX_NAME), $sent];
        }
        // More is not a browser, and a visitor chooses how many: past 100 the rest is left out, never an error.
        if (count($pairs) > self::BOT_CHECK_MAX_HEADERS) {
            $pairs = array_slice($pairs, 0, self::BOT_CHECK_MAX_HEADERS);
            $truncated = true;
        }
        $body = ['ip' => $ip, 'headers' => self::botCheckHeaders($pairs, $asMap)];

        $method = $request['method'] ?? null;
        if ($method !== null && $method !== '') {
            if (!is_string($method)) {
                throw new TouchqueConfigException('botCheck(): method must be a string');
            }
            if (preg_match(self::BOT_CHECK_METHOD, trim($method))) {
                $body['method'] = trim($method); // anything but 1 to 16 letters is left out
            }
        }
        $url = $request['url'] ?? null;
        if ($url !== null && $url !== '') {
            if (!is_string($url)) {
                throw new TouchqueConfigException('botCheck(): url must be a string');
            }
            $url = self::botCheckUrl(self::utf8($url));
            if ($url !== null) {
                $body['url'] = $url;
            }
        }
        $version = self::httpVersion($request['httpVersion'] ?? null);
        if ($version !== null) {
            $body['httpVersion'] = $version; // anything else is left out: it may be what the visitor sent
        }
        $tls = $request['tls'] ?? null;
        if ($tls !== null) {
            if (!is_array($tls)) {
                throw new TouchqueConfigException("botCheck(): tls is ['ciphers' => string, 'ja4' => string]");
            }
            $sent = [];
            foreach ($tls as $key => $value) {
                if (!in_array($key, ['ciphers', 'ja4'], true)) {
                    throw new TouchqueConfigException("botCheck(): tls does not know '{$key}'");
                }
                if ($value !== null && !is_string($value)) {
                    throw new TouchqueConfigException("botCheck(): tls {$key} must be a string");
                }
                $value = self::utf8(trim((string)$value));
                if ($key === 'ciphers' && $value !== '') {
                    $sent[$key] = self::cut($value, self::BOT_CHECK_MAX_VALUE); // the list the visitor offered can be long
                } elseif ($key === 'ja4' && $value !== '' && strlen($value) <= self::BOT_CHECK_MAX_JA4) {
                    $sent[$key] = $value; // a longer one is not a JA4: left out
                }
            }
            if ($sent !== []) {
                $body['tls'] = $sent;
            }
        }
        return self::fitBotCheck($body, $pairs, $asMap, $truncated);
    }

    /** One header value as sent: empty for a sensitive header, else the value as valid UTF-8. */
    private static function botCheckValue(string $name, $value): string
    {
        if (in_array(strtolower($name), self::BOT_CHECK_BLANKED_HEADERS, true)) {
            return ''; // the name stays, for the order; the value never leaves your server
        }
        if (is_array($value)) {
            foreach ($value as $one) {
                if (!is_string($one) && !is_int($one) && !is_float($one)) {
                    throw new TouchqueConfigException('botCheck(): a header value is a string');
                }
            }
            $value = implode(', ', $value);
        } elseif (is_int($value) || is_float($value)) {
            $value = (string)$value;
        } elseif (!is_string($value)) {
            throw new TouchqueConfigException('botCheck(): a header value is a string');
        }
        return self::utf8($value);
    }

    /**
     * The url's host and path only: the query string, the fragment and any user:password@ never
     * leave your server. A path, or an http(s) URL (ws and wss read as http and https); a host
     * Touchque could not read goes as the path alone; anything else, or one over 4096
     * characters, is null.
     */
    private static function botCheckUrl(string $url): ?string
    {
        $head = (string)preg_replace('/[?#].*/s', '', trim($url));
        if (strncmp($head, '/', 1) === 0) {
            $out = $head;
        } elseif (preg_match('#^(https?|wss?)://([^/]*)(/.*)?$#is', $head, $m)) {
            $scheme = ['ws' => 'http', 'wss' => 'https'][strtolower($m[1])] ?? strtolower($m[1]);
            $authority = substr($m[2], (int)strrpos('@' . $m[2], '@'));
            $path = $m[3] ?? '';
            $out = self::plainHost($authority) ? "{$scheme}://{$authority}{$path}" : ($path !== '' ? $path : '/');
        } else {
            return null;
        }
        return self::cut($out, self::BOT_CHECK_MAX_URL) === $out ? $out : null;
    }

    /**
     * A host Touchque reads as it is: letters, digits, dots, hyphens and underscores, an IPv4
     * address, a port up to 65535. Anything else (the Host header is the visitor's) goes as the
     * path alone, so an odd Host never makes the API refuse the check.
     */
    private static function plainHost(string $authority): bool
    {
        if (!preg_match('/^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?)(?::([0-9]{0,5}))?$/D', $authority, $m)
            || (($m[2] ?? '') !== '' && (int)$m[2] > 65535)) {
            return false;
        }
        $host = rtrim($m[1], '.');
        $labels = explode('.', $host);
        foreach ($labels as $label) {
            if (stripos($label, 'xn--') === 0) {
                return false;
            }
        }
        // A name that ends in a number is read as an IPv4 address: it must be one.
        if (preg_match('/^(?:[0-9]+|0x[0-9a-f]*)$/Di', end($labels))) {
            return (bool)preg_match('/^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/D', $host);
        }
        return true;
    }

    /** The headers as sent, each value cut to at most $bytes bytes (never inside a character): pairs, or an object for a map. */
    private static function botCheckHeaders(array $pairs, bool $asMap, int $bytes = PHP_INT_MAX)
    {
        $out = [];
        foreach ($pairs as [$name, $value]) {
            if (strlen($value) > $bytes) {
                $end = $bytes;
                while ($end > 0 && (ord($value[$end]) & 0xC0) === 0x80) {
                    $end--; // that byte continues the character before it: cut before the character
                }
                $value = substr($value, 0, $end);
            }
            if ($asMap) {
                $out[$name] = $value;
            } else {
                $out[] = [$name, $value];
            }
        }
        return $asMap ? (object)$out : $out;
    }

    /**
     * The body within the API's 32 KB. A visitor can send far more than that in headers: then
     * every value longer than one length (in bytes, never inside a character) is cut to it, the
     * longest length that still fits. Names always fit (100 of 128 characters); only a url or
     * cipher list made long by escaping can crowd them out, so tls goes first, then the url, and
     * the last headers only after that. `truncated` is true when a header was left out or cut.
     */
    private static function fitBotCheck(array $body, array $pairs, bool $asMap, bool $truncated): array
    {
        $build = static function (array $kept, int $bytes, int $drop) use ($body, $pairs, $asMap, $truncated): array {
            $out = ['ip' => $body['ip'], 'headers' => self::botCheckHeaders($kept, $asMap, $bytes)];
            // The contract's order: method, url, httpVersion, tls (1 leaves out tls, 2 also the url), truncated.
            foreach (['method' => 3, 'url' => 2, 'httpVersion' => 3, 'tls' => 1] as $key => $keptBelow) {
                if (isset($body[$key]) && $drop < $keptBelow) {
                    $out[$key] = $body[$key];
                }
            }
            $cut = $truncated || count($kept) < count($pairs);
            foreach ($kept as [, $value]) {
                $cut = $cut || strlen($value) > $bytes;
            }
            if ($cut) {
                $out['truncated'] = true;
            }
            return $out;
        };
        $fits = static fn (array $b): bool => strlen(HttpClient::encode($b)) <= self::BOT_CHECK_MAX_BODY;
        $whole = $build($pairs, PHP_INT_MAX, 0);
        if ($fits($whole)) {
            return $whole;
        }
        $drop = 0;
        while ($drop < 2 && !$fits($build($pairs, 0, $drop))) {
            $drop++;
        }
        $low = 0;
        $high = max(array_map('strlen', array_column($pairs, 1)) ?: [0]) - 1; // the longest value whole does not fit
        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);
            if ($fits($build($pairs, $mid, $drop))) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }
        $body = $build($pairs, max($low, 0), $drop);
        while ($pairs !== [] && !$fits($body)) {
            array_pop($pairs);
            $body = $build($pairs, 0, $drop);
        }
        return $body;
    }

    /** '1.0', '1.1', '2' or '3' from what a server gives ('HTTP/1.1', 'HTTP/2.0', 'h2', 2), else null. */
    private static function httpVersion($version): ?string
    {
        if (!is_string($version) && !is_int($version)) {
            return null;
        }
        $version = strtolower((string)preg_replace('#^HTTP/#i', '', trim((string)$version)));
        return ['1.0' => '1.0', '1.1' => '1.1', '2' => '2', '2.0' => '2', 'h2' => '2', 'h2c' => '2', '3' => '3', '3.0' => '3', 'h3' => '3'][$version] ?? null;
    }

    /** Valid UTF-8 for JSON: bytes that are not UTF-8 are read as Latin-1, as HTTP reads them. */
    private static function utf8(string $s): string
    {
        if (preg_match('//u', $s) === 1) {
            return $s;
        }
        return (string)preg_replace_callback('/[\x80-\xFF]/', static function (array $m): string {
            $byte = ord($m[0]);
            return chr(0xC0 | ($byte >> 6)) . chr(0x80 | ($byte & 0x3F));
        }, $s);
    }

    /** $s (valid UTF-8) cut to at most $max characters, counted as the API counts them (UTF-16 units). */
    private static function cut(string $s, int $max): string
    {
        if (strlen($s) <= $max) {
            return $s; // never more characters than bytes
        }
        preg_match('/^.{0,' . $max . '}/su', $s, $m);
        // A character past U+FFFF (four bytes in UTF-8, led by F0-F7) counts as two.
        $bytes = count_chars($m[0], 0);
        $astral = array_sum(array_slice($bytes, 0xF0, 8));
        if ($astral === 0) {
            return $m[0];
        }
        $chars = strlen($m[0]) - array_sum(array_slice($bytes, 0x80, 64)); // every byte but a continuation byte starts one
        if ($chars + $astral <= $max) {
            return $m[0];
        }
        // The longest prefix that fits: half of $max always does, all $chars do not.
        $low = intdiv($max, 2);
        $high = $chars - 1;
        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);
            preg_match('/^.{0,' . $mid . '}/su', $s, $m);
            if ($mid + array_sum(array_slice(count_chars($m[0], 0), 0xF0, 8)) <= $max) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }
        preg_match('/^.{0,' . $low . '}/su', $s, $m);
        return $m[0];
    }

    /**
     * Reads a bot check answer. Fields and values this version does not know are kept as they
     * came, so a newer server never breaks it; a field missing or of the wrong type reads as
     * null, except `result` and `suggestion`: what it cannot read is "cannot tell", not_detected
     * and allow, never a block.
     *
     * - `bot['result']`: detected (a bot by its own name or a sure sign), suspected (signs point
     *   to software) or not_detected (`BOT_CHECK_RESULTS`).
     * - `bot['category']`: the kind of bot (`BOT_CHECK_CATEGORIES`: ai_assistant for ChatGPT-User,
     *   http_client for curl, headless_browser...), or null. A category this version does not
     *   list comes as it was sent.
     * - `bot['provider']` and `bot['name']`: who runs it and what it is called ("OpenAI",
     *   "ChatGPT-User"), or null.
     * - `bot['identity']`: verified (its operator's signature, published addresses or reverse DNS
     *   proved it); unverified (a spoofed name: it claims a bot whose operator publishes a way to
     *   check, and that check failed); claimed (a name its operator gives no way to check, or one
     *   Touchque cannot check right now); or null (no named bot).
     * - `bot['verifiedBy']`: what proved a verified bot: signature, ip_list, reverse_dns or asn.
     * - `bot['confidence']`: high, medium or low, or null.
     * - `bot['rule']`: the stable id of the rule that answered ("directory.chatgpt_user",
     *   "http_client.curl", "browser.chromium_without_client_hints"), or null.
     * - `bot['reasons']`: every sign seen, each `['code' => ..., 'text' => an English sentence your
     *   fraud team reads]`.
     * - `network`: the visitor address's network, or null: `asn`, `asnOrg`, `countryCode` and
     *   `hosting` (a cloud or hosting network rather than a home or mobile one).
     * - `suggestion`: what Touchque would do, as advice in shadow (Touchque never enforces it):
     *   allow (a verified bot, a declared crawler, assistant or other bot it cannot check, or no
     *   bot), block (a spoofed name) or challenge (an AI agent that only names itself, since it
     *   acts for a person; undeclared automation, such as an HTTP client, a headless browser or a
     *   browser claim that contradicts itself; or a suspected bot).
     * - `rulesVersion`: the version of the rules that answered ("2026.11.25-1").
     */
    public static function parseBotCheck($raw): array
    {
        $body = is_array($raw) ? $raw : [];
        $bot = is_array($body['bot'] ?? null) ? $body['bot'] : [];
        $read = [];
        foreach (['result', 'category', 'provider', 'name', 'identity', 'verifiedBy', 'confidence', 'rule'] as $key) {
            $read[$key] = self::stringOrNull($bot[$key] ?? null);
        }
        $read['result'] = $read['result'] ?? 'not_detected';
        $read['reasons'] = [];
        foreach (is_array($bot['reasons'] ?? null) ? $bot['reasons'] : [] as $reason) {
            if (is_array($reason) && is_string($reason['code'] ?? null)) {
                $read['reasons'][] = ['code' => $reason['code'], 'text' => is_string($reason['text'] ?? null) ? $reason['text'] : ''] + $reason;
            }
        }
        $network = $body['network'] ?? null;
        if (is_array($network)) {
            $network = [
                'asn' => is_int($network['asn'] ?? null) ? $network['asn'] : null,
                'asnOrg' => self::stringOrNull($network['asnOrg'] ?? null),
                'countryCode' => self::stringOrNull($network['countryCode'] ?? null),
                'hosting' => is_bool($network['hosting'] ?? null) ? $network['hosting'] : null,
            ] + $network;
        }
        // Fields a newer server adds come through as they came, after the known ones.
        return [
            'bot' => $read + $bot,
            'network' => is_array($network) ? $network : null,
            'suggestion' => self::stringOrNull($body['suggestion'] ?? null) ?? 'allow',
            'rulesVersion' => self::stringOrNull($body['rulesVersion'] ?? null),
        ] + $body;
    }

    private static function stringOrNull($value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The suspect score of an answer, event or search row (in shadow: it decides nothing
     * yet), or null: `score` 0-100, `band` (low | medium | high | critical), `wouldDo`
     * (allow | number_match | passkey | block: what it would ask for), `mode` ('shadow') and
     * `reasons` (`code`, `points`, `by`: server | site | page | brand, `text`).
     */
    public static function parseSuspect($raw): ?array
    {
        if (!is_array($raw) || !is_int($raw['score'] ?? null)) {
            return null;
        }
        $reasons = [];
        foreach (is_array($raw['reasons'] ?? null) ? $raw['reasons'] : [] as $r) {
            if (!is_array($r) || !is_string($r['code'] ?? null)) {
                continue;
            }
            $reasons[] = [
                'code' => $r['code'],
                'points' => is_int($r['points'] ?? null) ? $r['points'] : 0,
                'by' => in_array($r['by'] ?? null, ['server', 'site', 'page', 'brand'], true) ? $r['by'] : 'server',
                'text' => is_string($r['text'] ?? null) ? $r['text'] : '',
            ];
        }
        $score = max(0, min(100, $raw['score']));
        return [
            'score' => $score,
            'band' => in_array($raw['band'] ?? null, ['low', 'medium', 'high', 'critical'], true) ? $raw['band'] : self::band($score),
            'wouldDo' => in_array($raw['wouldDo'] ?? null, ['allow', 'number_match', 'passkey', 'block'], true) ? $raw['wouldDo'] : 'allow',
            'mode' => 'shadow',
            'reasons' => $reasons,
        ];
    }

    private static function band(int $score): string
    {
        return $score >= 80 ? 'critical' : ($score >= 60 ? 'high' : ($score >= 30 ? 'medium' : 'low'));
    }

    /**
     * Did this account use the device before (once a check names the account), or null:
     * `status` known | likely | new | first, `visitorId` (likely: the account's visitor it
     * looks like) and `since` (known: the account's first identification on it).
     */
    public static function parseAccountDevice($raw): ?array
    {
        if (!is_array($raw) || !in_array($raw['status'] ?? null, ['known', 'likely', 'new', 'first'], true)) {
            return null;
        }
        $out = ['status' => $raw['status']];
        if (is_string($raw['visitorId'] ?? null)) {
            $out['visitorId'] = $raw['visitorId'];
        }
        if (is_string($raw['since'] ?? null)) {
            $out['since'] = $raw['since'];
        }
        return $out;
    }

    /** Reads an answer, failing toward asking: `stepUp` is true unless it says exactly false; junk signals are dropped. */
    public static function parse($raw): array
    {
        $body = is_array($raw) ? $raw : [];
        $signals = [];
        foreach (is_array($body['signals'] ?? null) ? $body['signals'] : [] as $s) {
            if (!is_array($s) || !is_string($s['code'] ?? null)) {
                continue;
            }
            $item = [
                'code' => $s['code'],
                'text' => is_string($s['text'] ?? null) ? $s['text'] : '',
                'strength' => in_array($s['strength'] ?? null, ['passkey', 'none'], true) ? $s['strength'] : 'number_match',
            ];
            if (is_bool($s['enforced'] ?? null)) {
                $item['enforced'] = $s['enforced'];
            }
            if (is_array($s['evidence'] ?? null)) {
                $item['evidence'] = $s['evidence'];
            }
            $signals[] = $item;
        }
        $out = [
            'report' => in_array($body['report'] ?? null, self::REPORTS, true) ? $body['report'] : 'invalid',
            'requestId' => is_string($body['requestId'] ?? null) ? $body['requestId'] : null,
            'visitorId' => is_string($body['visitorId'] ?? null) ? $body['visitorId'] : null,
            'confidence' => is_int($body['confidence'] ?? null) || is_float($body['confidence'] ?? null) ? $body['confidence'] : null,
            // visitor.mark: the mark actually applied to the identification (step_up always, trusted only when the
            // browser matched by its stored key or id, never by traits), else null; visitor.status stays your admin's
            // mark. Absent from older servers.
            'visitor' => self::visitorOf($body['visitor'] ?? null),
            'counts' => is_array($body['counts'] ?? null) ? $body['counts'] : null,
            // "network" is the address as the risk engine saw it (never coordinates), passed through as the API
            // answers it: countryCode, region, city, accuracyKm, timeZone, asn, asnOrg, type (isp | hosting | tor |
            // relay: Apple's iCloud Private Relay, never a VPN | unknown), tor, hosting, hostingProvider, proxy (on a
            // public proxy list in the last 30 days: context, often a home or school line resold to a proxy
            // network; absent on older servers; the proxy list includes IP2Proxy LITE data available from
            // https://lite.ip2location.com), timezoneMismatch and, absent on older servers:
            // - kind (NETWORK_KINDS: residential | mobile_carrier | education | business | public_wifi | hosting |
            //   proxy, a proxy company's own network | vpn, a VPN company's | tor | relay | unknown; new values may
            //   be added in minor versions), kindSource (address | network | mixed | network_open | name, the
            //   operator's name only: shown, never used for a decision) and vpn (a VPN company's own address), all
            //   null for an identification from before them (not classified);
            // - shared (many browsers used the identification's own address on your pages in 24 hours: context
            //   only), sharedVisitors24h and sharedAccounts24h (at least 1, 2, 5, 10, 100 or 1000) and
            //   lookAlikeMatching (false: this computer was recognised only by its own key, cookie or stored id;
            //   true: look-alike matching was allowed), null when not counted or not decided, or when the check
            //   assessed another address than the identification's.
            'network' => is_array($body['network'] ?? null) ? $body['network'] : null,
            // The visitor's counts: the risk engine's and Touchque's identifications.
            'velocity' => is_array($body['velocity'] ?? null) ? $body['velocity'] : null,
            // "bot" is passed through as the API answers it: result (detected | suspected | not_detected), reasons
            // (detected ones first: webdriver, headless, tool_<name> for each tool below, agent_verified; then
            // suspected: pointer_synthetic, input_synthetic, agent_pace, zero_window, headless_window (headless
            // Chrome's default window), emulator (an Android emulator), cdp (the DevTools protocol attached),
            // cdp_input (a press with no pressure: only the DevTools protocol sends it), input_no_focus (a click or
            // key into a page that was not in front), insert_text_bulk (text that arrived whole, no key pressed),
            // scripted_click (a form sent with no click or key), agent_unverified, agent_claimed, and soft_gpu
            // (software graphics) next to another sign) and, on servers since 2026-11-24 (absent on older ones):
            // type (ai_agent: an AI agent or bot by its own identity or its marks on the page, or a pause before
            // every step; automation: a driven browser; script: moved or typed like software in a browser that
            // shows no driver; or null), tools (the automation tools and AI agents whose marks were on the page:
            // selenium, playwright, puppeteer, phantomjs, nightmare, headless_chrome and, since 2026-11-25,
            // claude_agent (the Claude app's browser or Claude in Chrome), comet_agent (Perplexity Comet),
            // genspark_agent, browser_use, stagehand, skyvern), agent (null, or provider, name, category ai_agent |
            // ai_crawler | search_crawler, identity verified | unverified | claimed: a Web Bot Auth signature
            // checked against the provider's published keys, or the user agent only) and input (insert_no_keys,
            // uniform_keys, instant_keys, center_press, agent_pace). New values may be added in minor versions.
            'bot' => is_array($body['bot'] ?? null) ? $body['bot'] : null,
            // Did this account use the device before (null before an account is named); see parseAccountDevice().
            'accountDevice' => self::parseAccountDevice($body['accountDevice'] ?? null),
            // The suspect score, in shadow (null from servers that do not send it); see parseSuspect().
            'suspect' => self::parseSuspect($body['suspect'] ?? null),
            'signals' => $signals,
            'stepUp' => ($body['stepUp'] ?? null) !== false,
            'wouldStepUp' => ($body['wouldStepUp'] ?? null) === true,
            'requires' => in_array($body['requires'] ?? null, ['number_match', 'passkey'], true) ? $body['requires'] : 'none',
            'mode' => ($body['mode'] ?? null) === 'enforce' ? 'enforce' : 'shadow',
            // The engine's state for this check; 'unavailable' when the risk engine could not be reached and the verdict is a safe default.
            'engine' => is_string($body['engine'] ?? null) ? $body['engine'] : null,
        ];
        if (is_string($body['caseCode'] ?? null)) {
            $out['caseCode'] = $body['caseCode'];
        }
        return $out;
    }

    /** The visitor as it came; a `mark` other than `trusted` or `step_up` reads as null (no mark applied). */
    private static function visitorOf($raw): ?array
    {
        if (!is_array($raw)) {
            return null;
        }
        if (array_key_exists('mark', $raw)) {
            $raw['mark'] = in_array($raw['mark'], ['trusted', 'step_up'], true) ? $raw['mark'] : null;
        }
        return $raw;
    }
}
