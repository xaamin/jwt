<?php

namespace Xaamin\Jwt\Native;

use Xaamin\Jwt\Factory;
use UnexpectedValueException;
use Xaamin\Jwt\Signer\Native;
use Xaamin\Jwt\Jwt as JwtBase;

/**
 * @method static \Xaamin\Jwt\Token encode(array $claims)
 * @method static \Xaamin\Jwt\Token decode(string $token)
 * @method static bool check(string $token)
 * @method static bool checkOrFail(string $token)
 * @method static JwtBase setLeeway(int $seconds)
 * @method static JwtBase setTtl(int|null $minutes)
 * @method static JwtBase setRefreshTtl(int|null $minutes)
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

        $passphrase = strval(static::get($config, 'passphrase'));
        $algo = strval(static::get($config, 'algorithm'));
        $ttl = intval(static::get($config, 'ttl'));
        /** @var int|null */
        $refreshTtl = static::get($config, 'refresh_ttl');
        /** @var array<string,string> */
        $keys = static::get($config, 'keys') ?? [];

        $factory = new Factory();
        $signer = new Native($passphrase, $algo, $keys);

        $jwt = new JwtBase($signer, $factory);

        $jwt->setTtl($ttl);
        $jwt->setRefreshTtl($refreshTtl);

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
