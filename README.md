# touchque/device-risk

The official PHP server SDK for **Touchque Device Risk**: a visitor ID for every browser on your
sign-up, password-reset, sign-in or approval page, a risk verdict for the account it is used for, and
the abuse your server sees (card testing, failed sign-ins, probing, SMS pumping, code guessing).

Device Risk is a paid add-on: it answers 409 `device_risk_off` until your workspace turns it on in the
[Touchque dashboard](https://dashboard.touchque.com).

Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
composer require touchque/device-risk
```

## Setup

The same API key and secret as the main Touchque SDK:

```bash
TQ_API_KEY=tq_your_key
TQ_API_SECRET=your_api_secret
```

```php
use Touchque\DeviceRisk\TouchqueDeviceRisk;
use Touchque\DeviceRisk\Config;

$dr = new TouchqueDeviceRisk();                                    // reads the environment
$dr = new TouchqueDeviceRisk(new Config($key, $secret, null, 10000)); // or explicit (timeout in ms)
```

Every call is signed with your API secret: keep it on your server.

## Check a page's identification

The page identifies the browser with `@touchque/device-risk` (the script tag `device.js` fills a
`touchque_request_id` field in your form, or `identify({ siteKey, purpose })` gives a `requestId`). Never
trust the page's copy: check it on your server.

```php
$r = $dr->check($_POST['touchque_request_id'] ?? null, 'sign_up', $email, $_SERVER['REMOTE_ADDR']);
if ($r['stepUp']) {
    askForEmailCode();   // a step-up, never a refusal on it alone
}
```

- Pass the field as it came: missing, empty, made up or expired is still a verdict (`report`: `missing`,
  `unknown`, `expired`, `invalid`; the signal `device_identification_missing`), never an exception.
- `event`: `sign_in` (default), `sign_up`, `password_reset` or `approval` (`TouchqueDeviceRisk::EVENTS`).
- The answer: `report`, `requestId`, `visitorId`, `confidence`, `visitor`, `counts`, `network`,
  `velocity`, `bot`, `accountDevice`, `suspect`, `signals`, `stepUp`, `wouldStepUp`, `requires`, `mode`,
  `engine`, `caseCode`. It fails toward asking: `stepUp` is true unless the API says exactly false.
- `suspect` is the suspect score, in shadow (it decides nothing yet): `score` 0-100, `band`
  (low, medium, high, critical), `wouldDo` (allow, number_match, passkey, block) and `reasons`
  (`code`, `points`, `by`: server, site, page or brand, `text`).
- `accountDevice`: did this account use the device before? `status` known, likely, new or first.

For a sign-in approved on the phone with the main Touchque SDK, pass the same field as
`deviceRiskRequestId` to its `login->request()` or `risk->check()` instead.

### The network

`network` (in `check()`, `getEvent()` and each `searchEvents()` row) is the address as the risk engine saw it, never
coordinates: the place, the operator (`asn`, `asnOrg`), `type` (`isp`, `hosting`, `tor`, `relay` for Apple's iCloud
Private Relay, or `unknown`) and `proxy` (on a public proxy list in the last 30 days: context, often a home or school
line resold to a proxy network; absent on older servers). Newer servers add the fields below; older servers leave
them out:

- `kind`: `residential`, `mobile_carrier`, `education`, `business`, `public_wifi`, `hosting`, `proxy` (a proxy
  company's own network), `vpn` (a VPN company's), `tor`, `relay` or `unknown` (`TouchqueDeviceRisk::NETWORK_KINDS`).
  New values may be added in minor versions: keep a default branch. `kindSource` says where it came from: `address`,
  `network`, `mixed`, `network_open` or `name` (the operator's name only: shown, never used for a decision). `vpn`: a
  VPN company's own address. All three are null for identifications from before them.
- `shared`: many browsers used the identification's own address on your pages in the last 24 hours (a school, an
  office, a café, a mobile operator), with "at least" counts `sharedVisitors24h` and `sharedAccounts24h` (1, 2, 5,
  10, 100 or 1000). Null when not counted, or when a check assessed another address.
- `lookAlikeMatching`: `false` when this computer was recognised only by its own key, cookie or stored id (identical
  computers in use on the address at once, or a school, company or public Wi-Fi network on Touchque's list), `true`
  when look-alike matching was allowed, null when not decided (a phone, a tablet or Safari: never matched by look-alike).

The kind itself adds no points to the suspect score except `vpn` (10) and `proxy` (6, as the proxy list does); `tor`
and `hosting` count as before, and `shared` and `lookAlikeMatching` are context.

Touchque uses the IP2Proxy LITE database for [proxy and VPN detection](https://www.ip2location.com).
This site or product includes IP2Proxy LITE data available from https://lite.ip2location.com.

### Bots and AI agents on the page

`bot` (in `check()`, `getEvent()` and each `searchEvents()` row) sums up what the page showed: `result` (detected,
suspected or not_detected), `reasons`, `type` (`ai_agent`, `automation`, `script` or null), `tools`, `agent` and
`input`. `tools` names the automation tools and AI agents whose marks were on the page: `selenium`, `playwright`,
`puppeteer`, `phantomjs`, `nightmare`, `headless_chrome` and, since 2026-11-25, `claude_agent` (the Claude app's
browser or Claude in Chrome), `comet_agent` (Perplexity Comet), `genspark_agent`, `browser_use`, `stagehand` and
`skyvern`; each also comes as the reason `tool_<name>`. Other reasons include `headless_window` (headless Chrome's
default window) and `emulator` (an Android emulator), since 2026-11-24, and, since 2026-11-25, `cdp_input` (a press
with no pressure: only the DevTools protocol sends it), `input_no_focus` (a click or key into a page that was not in
front), `insert_text_bulk` (text with no key pressed) and `scripted_click` (a form sent with no click or key). Older
servers send none of these. New values may be added in minor versions: keep a default branch.

## Read and search identifications

```php
$event = $dr->getEvent('dre_...');   // the trusted identification, the verdict, accountDevice, suspect
$suspect = TouchqueDeviceRisk::parseSuspect($event['suspect'] ?? null);

$cursor = null;
do {
    $page = $dr->searchEvents(['account' => 'ada@example.com', 'stepUp' => true, 'limit' => 50] + ($cursor ? ['cursor' => $cursor] : []));
    foreach ($page['events'] as $e) { /* requestId, at, visitorId, kind, matchedBy, signals, suspect… */ }
    $cursor = $page['nextCursor'];
} while ($cursor);
```

Filters: `from`, `to` (7 days by default, at most 90), `signal`, `stepUp`, `kind` (the page), `origin`, `ip`
(an address or a CIDR range, never returned), `account`, `visitorId`, `requestId`, `networkKind`, `shared`,
`limit` (1 to 100) and the opaque `cursor`. A search that would read too much is a 422 `search_too_broad`.

`networkKind` is one kind of network (`NETWORK_KINDS`): identifications from before network kinds never match.
`shared` is `true` (the identification's own address was shared) or `false` (counted and not shared): one that was
not counted matches neither. Older servers ignore both.

```php
$page = $dr->searchEvents(['networkKind' => 'vpn', 'shared' => false, 'stepUp' => true]);
```

## Report what your server saw

```php
$a = $dr->activity([
    'type' => 'payment_attempt',
    'requestId' => $_POST['touchque_request_id'] ?? null,
    'clientIp' => $_SERVER['REMOTE_ADDR'],
    'externalUsername' => $email,
    'outcome' => 'declined',                          // what the payment provider answered
    'card' => ['bin' => '411111', 'last4' => '1111'], // never the card number
]);
if (in_array('abuse_card_testing', $a['signals'], true)) {
    stopTakingCards();
}
```

- `type`: `payment_attempt`, `login_failed`, `not_found`, `forbidden` (with `path`), `otp_sent` (with
  `phone`), `code_failed` (a wrong coupon or gift-card code).
- Name the visitor with `requestId`, `visitorId` or `clientIp` (a bot that never runs your page still
  counts on its network).
- The answer: `recorded`, `visitorId`, `signals` (`abuse_card_testing`, `abuse_card_shared`,
  `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`) and, for a path,
  `pathClass`. For 24 hours the visitor's next checks carry those signals and the suspect score weighs them.
- A card is its BIN (6 to 8 digits) and last 4 digits only. Anything else (a card number, a `number`
  or `pan` key) throws `TouchqueConfigException` before anything is sent.

## Bot check

Many bots never run JavaScript, so the page tag never sees them: ChatGPT-User, GPTBot, Meta's crawlers,
curl, scripts. Send one visitor request's IP and headers from your server; Touchque answers which bot it
is, whether that identity is proven, and what it would do. It decides on its own servers with its own
data (the bot operators' published addresses and keys, its own reverse DNS), never a third-party service;
what it cannot check right now is "cannot tell", never a guess and never a block.

```php
// A Laravel middleware
use Touchque\DeviceRisk\Config;
use Touchque\DeviceRisk\Exceptions\TouchqueException;
use Touchque\DeviceRisk\TouchqueDeviceRisk;

public function handle(Request $request, Closure $next)
{
    try {
        $check = (new TouchqueDeviceRisk(new Config(null, null, null, 2000)))->botCheck(
            TouchqueDeviceRisk::botCheckRequestFromServer($request->server->all(), $request->ip())
        );
        if ($check['suggestion'] === 'block') {   // a spoofed bot name: your call, Touchque only advises
            abort(403);
        }
    } catch (TouchqueException $e) {
        // cannot tell: never block on a failed check
    }
    return $next($request);
}
```

- `botCheckRequestFromServer()` reads `$_SERVER` (or Laravel's `$request->server->all()`): the headers in
  the order PHP gives them (names lowercase: PHP does not keep their case), the method and the host and
  path (never the query string). Pass the visitor's address your framework trusts (`$request->ip()`
  follows TrustProxies); the SDK never reads `X-Forwarded-For` itself. It never sends `SERVER_PROTOCOL`:
  behind a proxy that is the proxy's connection, not the visitor's.
- Or build the request yourself: `ip`, `headers` (`[[name, value], ...]` in the order received, `[]` for a
  request that had none; a `[name => value]` map goes with its order unknown), `method` and `url`. Add
  `httpVersion` (`1.0`, `1.1`, `2`, `3`) and `tls` (`['ciphers' => ..., 'ja4' => ...]`) only when your edge
  tells you what the visitor's were.
- Authorization, Cookie, Proxy-Authorization, X-Api-Key and Set-Cookie always go with empty values (their
  names stay, for the order). What a visitor sends never makes the check throw: past 100 headers the rest
  is left out, a name is cut to 128 characters and a value to 4096, the longest are cut further when the
  request would pass 32 KB, and `truncated: true` tells Touchque so. A header HTTP does not allow, a method
  other than 1 to 16 letters or a URL Touchque could not read is left out. Touchque never logs or stores
  header values.
- The answer: `bot` (`result`: detected, suspected or not_detected; `category`; `provider` and `name`, e.g.
  OpenAI and ChatGPT-User; `identity`: verified, unverified (a spoofed name) or claimed (a name that cannot
  be checked); `verifiedBy`; `confidence`; `rule`; `reasons` with `code` and `text`), `network` (`asn`,
  `asnOrg`, `countryCode`, `hosting`), `suggestion` and `rulesVersion`. A value this version does not list
  comes as it was sent.
- `suggestion` is advice in shadow, Touchque never enforces it: `allow` (a verified bot, a declared crawler,
  assistant or other bot it cannot check, or no bot), `block` (a spoofed name) or `challenge` (an AI agent that
  only names itself, since it acts for a person; undeclared automation; or a suspected bot).
- The check has its own budget per workspace: past it, a 429 `TouchqueAPIException` (`getRetryAfter()`).

## Webhooks

Verify Touchque webhooks with the main Touchque SDK, then compare `event` with
`WebhookEvents::DEVICE_RISK_SIGNAL` (a signal that asks for more) or `WebhookEvents::DEVICE_RISK_ALERT`
(an alert rule of the workspace went off).

## Errors

- `TouchqueConfigException`: a wrong argument or configuration (nothing was sent).
- `TouchqueAPIException`: the API answered an error (`getStatus()`, `getErrorCode()`, `getRetryAfter()`,
  `getCaseCode()`); a redirect is an error too.
- `TouchqueFeatureException` (`TouchqueFeatureNotInPlanException`, `TouchqueFeatureReadOnlyException`,
  `TouchqueFeatureOffException`): Device risk is not in your organization's plan, being turned off, or
  switched off on this deployment.
- `TouchqueNetworkException`: the request never reached Touchque.

## Tests

```bash
composer install
composer test
```

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js); the bot
check's run against a small PHP fake of its route (`tests/FakeBotCheckApi.php`).

## License

MIT
