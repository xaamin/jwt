<?php

namespace Xaamin\Jwt\Native;

use Xaamin\Jwt\Factory;
use UnexpectedValueException;
use Xaamin\Jwt\Signer\Native;
use Xaamin\Jwt\Jwt as JwtBase;

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
    /**
     * Config values
     *
     * @var array<string,mixed>
     */
    protected static $config;

    /**
     * Create facade instance
     *
     * @return \Xaamin\Jwt\Jwt
     */
    protected static function create()
    {
        $config = static::$config;

        if (empty($config)) {
            throw new UnexpectedValueException('No config provided');
        }

        /** @var string[] */
        $requiredClaims = static::get($config, 'required_claims', []);
        $passphrase = strval(static::get($config, 'passphrase'));
        $algo = strval(static::get($config, 'algorithm'));
        $leeway = intval(static::get($config, 'refresh_ttl'));
        /** @var string|null */
        $issuer = static::get($config, 'issuer');
        /** @var int|null */
        $ttl = static::get($config, 'ttl');
        /** @var int|null */
        $refreshTtl = static::get($config, 'refresh_ttl');
        /** @var array<string,string> */
        $keys = static::get($config, 'keys') ?? [];

        $passphrase = !empty($keys) && !empty($keys['passphrase']) ? $keys['passphrase'] : $passphrase;

        $factory = new Factory();
        $signer = new Native($passphrase, $algo, $keys);

        $jwt = new JwtBase($signer, $factory);

        $jwt->setTtl($ttl);
        $jwt->setLeeway($leeway);
        $jwt->setIssuer($issuer);
        $jwt->setRefreshTtl($refreshTtl);
        $jwt->setRequiredClaims($requiredClaims);

        return $jwt;
    }

    /**
     * Sets the config to use. See the example config file in Config/config.php
     *
     * @param array<string,mixed> $config
     *
     * @return void
     */
    public static function setConfig(array $config)
    {
        static::$config = $config;
        static::$instance = null;
    }

    /**
     * Gets value from array using dot notation
     *
     * @param array<string,mixed> $array
     * @param string $key
     * @param mixed $default
     *
     * @return mixed
     */
    protected static function get(array $array, $key, $default = null)
    {
        foreach (explode('.', $key) as $segment) {
            if (!is_array($array) || !array_key_exists($segment, $array)) {
                return $default;
            }

            $array = $array[$segment];
        }

        return $array;
    }
}
