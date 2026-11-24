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
 */
class TouchqueDeviceRisk
{
    /** The pages a device report may come from. */
    public const EVENTS = ['sign_in', 'sign_up', 'password_reset', 'approval'];
    /** What the page had sent: ok, replayed, or no usable identification. */
    public const REPORTS = ['ok', 'replayed', 'missing', 'unknown', 'expired', 'invalid'];
    /** How a visitor was recognised (an event's `matchedBy`). */
    public const MATCHED_BY = ['key', 'fpc', 'sid', 'traits', 'new'];
    /** What your server saw the visitor do (`activity()`'s `type`). */
    public const ACTIVITY_TYPES = ['payment_attempt', 'login_failed', 'not_found', 'forbidden', 'otp_sent', 'code_failed'];
    /** payment_attempt: what the payment provider answered. */
    public const ACTIVITY_OUTCOMES = ['approved', 'declined', 'error'];
    /** The abuse codes an activity can raise. New codes may be added. */
    public const ACTIVITY_SIGNALS = ['abuse_card_testing', 'abuse_card_shared', 'abuse_login_failures', 'abuse_probing', 'abuse_otp_pumping', 'abuse_code_guessing'];
    /** The class of a not_found / forbidden path. */
    public const PATH_CLASSES = ['admin', 'wordpress', 'secrets', 'source', 'db_admin', 'debug', 'shell', 'other'];

    private const REQUEST_ID = '/^dre_[A-Za-z0-9_-]{22}$/';
    private const ACTIVITY_FIELDS = ['type', 'requestId', 'visitorId', 'clientIp', 'externalUsername', 'outcome', 'card', 'phone', 'path'];

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
     * retention) and any of `signal`, `stepUp`, `kind`, `origin`, `ip` (an address or a
     * CIDR range, never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100)
     * and the opaque `cursor`. Pass `nextCursor` back as `cursor` until it is null; do not
     * page by moving the dates. A search that would read too much is a 422
     * `search_too_broad`: narrow the range or add a filter. Each event may carry
     * `suspect` (see `parseSuspect()`) and `matchedBy` (`MATCHED_BY`).
     * Returns `['events' => [...], 'nextCursor' => ?string, 'from' => string, 'to' => string]`.
     */
    public function searchEvents(array $options = []): array
    {
        $params = [];
        foreach (['from', 'to', 'signal', 'kind', 'origin', 'ip', 'account', 'visitorId', 'requestId', 'cursor'] as $k) {
            if (isset($options[$k]) && is_string($options[$k]) && $options[$k] !== '') {
                $params[$k] = $options[$k];
            }
        }
        if (isset($options['stepUp']) && is_bool($options['stepUp'])) {
            $params['stepUp'] = $options['stepUp'] ? 'true' : 'false';
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
     * page showed, the engine's verdict, `accountDevice` and `suspect` (read them with
     * `parseAccountDevice()` / `parseSuspect()`).
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
            'visitor' => is_array($body['visitor'] ?? null) ? $body['visitor'] : null,
            'counts' => is_array($body['counts'] ?? null) ? $body['counts'] : null,
            // The address (never coordinates), the visitor's counts, one answer to "a bot?" (detected | suspected | not_detected).
            'network' => is_array($body['network'] ?? null) ? $body['network'] : null,
            'velocity' => is_array($body['velocity'] ?? null) ? $body['velocity'] : null,
            // "bot" is passed through as the API answers it: result (detected | suspected | not_detected), reasons
            // (detected ones first, then suspected: webdriver, headless, pointer_synthetic, zero_window, soft_gpu,
            // tool_<name>, agent_verified, input_synthetic, agent_pace, cdp, agent_unverified, agent_claimed) and,
            // on servers since 2026-11-24 (absent on older ones): type (ai_agent: an AI agent or bot by its own
            // identity, or a pause before every step; automation: a driven browser; script: moved or typed like
            // software in a browser that shows no driver; or null), tools (automation tools whose marks were on
            // the page: selenium, playwright, puppeteer, phantomjs, nightmare, headless_chrome), agent (null, or
            // provider, name, category ai_agent | ai_crawler | search_crawler, identity verified | unverified |
            // claimed: a Web Bot Auth signature checked against the provider's published keys, or the user agent
            // only) and input (insert_no_keys, uniform_keys, instant_keys, center_press, agent_pace).
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
}
