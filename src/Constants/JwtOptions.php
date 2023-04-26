<?php

namespace Xaamin\Jwt\Constants;

class JwtOptions
{
    public const LEEWAY = 0;
    public const TTL = 60;
    public const REFRESH_TTL = 20160;

    public static $requiredClaims = ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'];
}
