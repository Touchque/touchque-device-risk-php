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

Filters: `from`, `to` (7 days by default, at most 90), `signal`, `stepUp`, `kind`, `origin`, `ip` (an
address or a CIDR range, never returned), `account`, `visitorId`, `requestId`, `limit` (1 to 100) and
the opaque `cursor`. A search that would read too much is a 422 `search_too_broad`.

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

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js).

## License

MIT
