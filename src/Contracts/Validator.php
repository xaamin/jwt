<?php

namespace Xaamin\Jwt\Contracts;

interface Validator
{
    /**
     * Helper function to return a boolean.
     *
     * @param string $value
     *
     * @return bool
     */
    public function isValid($value);

    /**
     * Perform some checks on the value.
     *
     * @param mixed $value
     *
     * @return void
     */
    public function check($value);
}
