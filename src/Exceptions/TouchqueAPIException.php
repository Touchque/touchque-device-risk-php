<?php

namespace Touchque\DeviceRisk\Exceptions;

/** The API returned an error response (status >= 300). `getCode()` is the
 * HTTP status; `getData()` is the decoded JSON body. */
class TouchqueAPIException extends TouchqueException
{
    /** HTTP status code (e.g. 400, 409, 429). Alias for `getCode()`. */
    public function getStatus(): int
    {
        return $this->getCode();
    }

    /** Machine-readable error code (e.g. "device_risk_off", "card_number_not_allowed"). */
    public function getErrorCode(): ?string
    {
        return $this->getData()['code'] ?? null;
    }

    /** Seconds to wait before retrying (429). */
    public function getRetryAfter(): ?int
    {
        return $this->getData()['retryAfter'] ?? null;
    }

    /**
     * "Why?" case code of a refusal (`K7P-2QX`): your team opens the decision
     * by it in the dashboard. Null for other errors.
     */
    public function getCaseCode(): ?string
    {
        $code = $this->getData()['caseCode'] ?? null;
        return is_string($code) ? $code : null;
    }
}
