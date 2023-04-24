<?php

namespace Xaamin\Jwt\Facades;

use Xaamin\Jwt\Jwt as JwtBase;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \Xaamin\Jwt\Token encode(array $claims)
 * @method static \Xaamin\Jwt\Token decode(string $token)
 * @method static \Xaamin\Jwt\Token refresh(string $token)
 * @method static bool check(string $token)
 * @method static bool checkOrFail(string $token)
 * @method static \Xaamin\Jwt\Jwt with(string|null $secret, string $algorithm = 'HS512', array $keys = [])
 * @method static \Xaamin\Jwt\Jwt setSigner(\Xaamin\Jwt\Contracts\Signer $issuer)
 * @method static \Xaamin\Jwt\Jwt setIssuer(string $issuer)
 * @method static \Xaamin\Jwt\Jwt setLeeway(int $seconds)
 * @method static \Xaamin\Jwt\Jwt setTtl(int|null $minutes)
 * @method static \Xaamin\Jwt\Jwt setRefreshTtl(int|null $minutes)
 * @method static \Xaamin\Jwt\Jwt setRequiredClaims(array $claims)
 */
class Jwt extends Facade
{
    protected static function getFacadeAccessor()
    {
        return JwtBase::class;
    }
}
