# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-11-24

### Added
- **Touchque Device Risk as its own package.** Device risk leaves the main PHP SDK (`touchque-authenticator/php-sdk` 6.0.0 no longer has `$tq->deviceRisk`): `new TouchqueDeviceRisk(?Config $config = null)` with its own small client (the same API key and secret, `TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL`, the same request signing, timeout and exceptions as the main SDK, in `Touchque\DeviceRisk\Exceptions`).
- `check($requestId, $event, $externalUsername, $clientIp, $deviceRisk)` (`POST /device-risk/check`), `getEvent($requestId)` (`GET /device-risk/events/{requestId}`), `searchEvents([...])` (`GET /device-risk/events`) and `TouchqueDeviceRisk::parse()`, as they were on `$tq->deviceRisk`.
- **`activity([...])`: report what a visitor did that your server saw** (`POST /device-risk/activity`): `type` (`payment_attempt`, `login_failed`, `not_found`, `forbidden`, `otp_sent`, `code_failed`), `requestId`, `visitorId`, `clientIp`, `externalUsername`, `outcome` (`approved`, `declined`, `error`), `card` (`['bin' => 6-8 digits, 'last4' => 4 digits]`), `phone`, `path`. Answers `recorded`, `visitorId`, `signals` (`abuse_card_testing`, `abuse_card_shared`, `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`) and `pathClass`. A card that is not exactly a BIN and the last 4 digits (a card number, a `number` or `pan` key) throws `TouchqueConfigException` before anything is sent.
- `check()` answers carry `suspect` (the suspect score in shadow: `score` 0-100, `band`, `wouldDo`, `mode`, `reasons` with `code`, `points`, `by`, `text`) and `accountDevice` (`status` known, likely, new or first, `visitorId`, `since`); `TouchqueDeviceRisk::parseSuspect()` and `parseAccountDevice()` read them from `getEvent()` answers and `searchEvents()` rows. `MATCHED_BY` lists `fpc` (the first-party cookie).
- `WebhookEvents::DEVICE_RISK_SIGNAL` and `WebhookEvents::DEVICE_RISK_ALERT` (were `Webhook::EVENT_DEVICE_RISK_*` in the main SDK).
- The `bot` array of `check()`, `getEvent()` and each `searchEvents()` item carries `type` (`ai_agent`, `automation`, `script` or null), `tools`, `agent` and `input` on servers since 2026-11-24; the API can return the signal codes `device_input_synthetic` and `device_ai_agent` (a number-matched step-up only, never a block).
