<?php
namespace Xaamin\JWT\Validation;

use Xaamin\JWT\Support\Base64;
use Xaamin\JWT\Exceptions\JWTException;
use Xaamin\JWT\Exceptions\TokenInvalidException;

class TokenValidation extends Validator
{
	/**
     * Check the structure of the token.
     *
     * @param  string  $value
     *
     * @return void
     */
    public function check($value)
    {
        $parts = explode('.', $value);

        $this->validateStructure($parts, $value);

        $this->validateParts($parts);
    }

    /**
     * Validates token structure
     * 
     * @param  string   $parts
     * @param  string   $token
     * 
     * @throws \Xaamin\JWT\Exceptions\TokenInvalidException
     * 
     * @return bool
     */
    protected function validateStructure($parts, $token)
    {
        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of parts');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token) {
            throw new TokenInvalidException('Malformed token');
        }

        return true;
    }

    /**
     * Validates that token has 3 parts and is valid
     * 
     * @param  array  $parts
     *
     * @throws \Xaamin\JWT\Exceptions\JWTException
     *
     * @return bool
     */
    protected function validateParts($parts)
    {
        list($headerB64, $payloadB64, $cryptoB64) = $parts;

        $header = json_decode(Base64::decode($headerB64));
        $payload = json_decode(Base64::decode($payloadB64));

        if (!$header) {
            throw new JWTException('Invalid header segment encoding');
        }

        if (!$payload) {
            throw new JWTException('Invalid payload segment encoding');
        }

        return true;
    }
}