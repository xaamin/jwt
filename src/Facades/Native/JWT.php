<?php 
namespace Xaamin\JWT\Facades\Native;

use Xaamin\JWT\JWT;
use Xaamin\JWT\Factory;
use Xaamin\JWT\Signer\Native;
use Xaamin\JWT\Validation\PayloadValidation;
use UnexpectedValueException;

class JWT extends Facade 
{	
    /**
     * Config values
     * 
     * @var array
     */
    protected static $config;

    /**
     * Create facade instance
     * 
     * @return \Xaamin
     */
    protected static function create()
    {
        if(!$config = static::$config)
        {
            throw new UnexpectedValueException("You must provide config details in order to use JWT");
        }

        $secret = static::getConfigValue('jwt.secret');
        $algo = static::getConfigValue('jwt.algorithm');
        $keys = static::getConfigValue('jwt.keys');

        $payloadValidation = new PayloadValidation;        
        $factory = new Factory($payloadValidation);            
        $signer = new Native($secret, $algo, $keys);

        return new JWT($signer, $factory);
    }

    /**
     * Sets the config to use. See the example config file in Config/config.php
     * 
     * @param array $config
     */
    public static function setConfig(array $config)
    {
        static::$config = $config;
    }

    /**
     * Gets value from array using dot notation
     * 
     * @param  array    $array
     * @param  string   $key
     * @param  mixed    $default 
     * @return mixed
     */
    protected static function getConfigValue(array $array, $key, $default = null)
    {
        foreach (explode('.', $key) as $segment)
        {
            if ( ! is_array($array) or ! array_key_exists($segment, $array))
            {
                return (is_callable($default) and ! is_string($default)) ? call_user_func($default) : $default;
            }

            $array = $array[$segment];
        }

        return $array;
    }
}