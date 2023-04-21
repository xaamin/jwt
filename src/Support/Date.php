<?php

namespace Xaamin\Jwt\Support;

use DateTime;
use DateTimeZone;
use Xaamin\Jwt\Constants\JwtTtl;

class Date
{
    /**
     * Time tolerance
     *
     * @var int
     */
    public static $leeway = JwtTtl::LEEWAY;

    /**
     * Get the date instance for the current time.
     *
     * @return DateTime
     */
    public static function now()
    {
        return new DateTime('now', new DateTimeZone('UTC'));
    }

    /**
     * Get the Carbon instance for the timestamp.
     *
     * @param int $timestamp
     *
     * @return DateTime
     */
    public static function timestamp($timestamp)
    {
        return new DateTime("@{$timestamp}", new DateTimeZone('UTC'));
    }

    /**
     * Checks if a timestamp is in the past.
     *
     * @param int $timestamp
     *
     * @return bool
     */
    public static function isPast($timestamp)
    {
        $leeway = static::$leeway;

        $timestamp = static::timestamp($timestamp)->getTimestamp();
        $current = static::now()->modify("-{$leeway} seconds")->getTimestamp();

        return $timestamp < $current;
    }

    /**
     * Checks if a timestamp is in the future.
     *
     * @param int $timestamp
     *
     * @return bool
     */
    public static function isFuture($timestamp)
    {
        $leeway = static::$leeway;
        $timestamp = static::timestamp($timestamp)->getTimestamp();
        $current = static::now()->modify("+{$leeway} seconds")->getTimestamp();

        return $timestamp > $current;
    }
}
