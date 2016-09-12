<?php 
namespace Xaamin\JWT\Facades\Native;

abstract class Facade {

	/**
	 * JWTI instance
	 *
	 * @var \Xaamin\JWT\JWT
	 */
	protected static $instance;

	/**
	 * Returns the implementation registered with the Facade.
	 *
	 * @return \Xaamin\JWT\JWT
	 */
	public static function instance()
	{
		if (!static::$instance)
		{
			static::$instance = forward_static_call_array(
				array(get_called_class(), 'create'),
				func_get_args()
			);
		}

		return static::$instance;
	}

	/**
	 * Handle dynamic, static calls to the object.
	 *
	 * @param  string  $method
	 * @param  array   $args
	 * @return mixed
	 */
	public static function __callStatic($method, $args)
	{
		$instance = static::instance();

		switch (count($args))
		{
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
				return call_user_func_array(array($instance, $method), $args);
		}
	}

}