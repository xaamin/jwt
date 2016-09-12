<?php
namespace Xaamin\JWT\Validation;

use Xaamin\JWT\JWTException;
use Xaamin\JWT\Contracts\Validator as ValidatorContract;

abstract class Validator implements ValidatorContract
{
	/**
	 * {@inheritDoc}
	 */
	public function isValid($value)
	{
		try {
            $this->check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
	}

	/**
	 * {@inheritDoc}
	 */
	abstract public function check($value);
}