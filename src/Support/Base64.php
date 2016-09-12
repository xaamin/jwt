<?php
namespace Xaamin\JWT\Support;

class Base64
{
    /**
     * Encodes string to Base64
     * 
     * @param  string $value
     * 
     * @return string
     */
    public static function encode($value)
    {
        $B64 = base64_encode($value);
        $B64 = str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), $B64);

        return $B64;
    }

    /**
     * Decodes a string from Base64
     * 
     * @param  string $B64
     * @return string
     */
    public static function decode($B64)
    {
        $B64 = str_replace(array('-', '_'), array('+', '/'), $B64);

        return base64_decode($B64);
    }
}