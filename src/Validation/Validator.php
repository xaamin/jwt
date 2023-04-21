<?php

namespace Xaamin\Jwt\Validation;

use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Contracts\Validator as ValidatorContract;

abstract class Validator implements ValidatorContract
{
    /**
     * {@inheritDoc}
     */
    public function isValid($value)
    {
        try {
            $this->check($value);
        } catch (JwtException $e) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    abstract public function check($value);
}
