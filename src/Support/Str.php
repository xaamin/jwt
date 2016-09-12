<?php
namespace Xaamin\JWT\Support;

class Str 
{
	/**
	 * Make quick random string 
	 * 
	 * @param  integer $length
	 * @return string
	 */
	public static function random($length = 16)
	{
		$pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        $string = str_shuffle(str_repeat($pool, $length));

        if (function_exists('mb_substr')) {
            return mb_substr($string, 0, $length, 'UTF-8');
        } 

        return substr($string, 0, $length);
	}
}