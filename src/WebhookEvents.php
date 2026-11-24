<?php

namespace Touchque\DeviceRisk;

/**
 * The `event` values of Device risk's webhook events. Verify the webhook with the
 * main Touchque SDK (`$tq->webhook`), then compare its `event` with these. Ignore
 * types you do not know.
 */
final class WebhookEvents
{
    /** An identification or a check() raised a signal that asks for more. Never a trait. */
    public const DEVICE_RISK_SIGNAL = 'DEVICE_RISK_SIGNAL';
    /** An alert rule of the workspace went off. */
    public const DEVICE_RISK_ALERT = 'DEVICE_RISK_ALERT';

    private function __construct()
    {
    }
}
