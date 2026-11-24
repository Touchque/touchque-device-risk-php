<?php

namespace Touchque\DeviceRisk\Exceptions;

/** `feature_off`: the feature is switched off on this Touchque deployment. */
class TouchqueFeatureOffException extends TouchqueFeatureException
{
    protected const REASON = 'off';
}
