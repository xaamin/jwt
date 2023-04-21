<?php

namespace Xaamin\Jwt\Native;

abstract class Facade
{
    /**
    * Jwt instance
    *
    * @var \Xaamin\Jwt\Native\Jwt|null
    */
    protected static $instance;

    /**
    * Returns the implementation registered with the Facade.
    *
    * @return \Xaamin\Jwt\Native\Jwt
    */
    public static function instance()
    {
        if (static::$instance === null) {
            /** @var callable */
            $callable = [get_called_class(), 'create'];

            /** @var \Xaamin\Jwt\Native\Jwt */
            $instance = forward_static_call_array($callable, func_get_args());

            static::$instance = $instance;
        }

        return static::$instance;
    }

    /**
    * Handle dynamic, static calls to the object.
    *
    * @param string $method
    * @param array<mixed> $args
    * @return mixed
    */
    public static function __callStatic($method, $args)
    {
        $instance = static::instance();

        switch (count($args)) {
            case 0:
                return $instance->$method();

            case 1:
                return $instance->$method($args[0]);

            case 2:
                return $instance->$method($args[0], $args[1]);

            case 3:
                return $instance->$method($args[0], $args[1], $args[2]);

            case 4:
                return $instance->$method($args[0], $args[1], $args[2], $args[3]);

            default:
                /** @var callable */
                $callable = [$instance, $method];

                return call_user_func_array($callable, $args);
        }
    }
}
