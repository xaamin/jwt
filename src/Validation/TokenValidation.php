<?php

namespace Xaamin\Jwt\Validation;

use Xaamin\Jwt\Support\Base64;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenInvalidException;

class TokenValidation extends Validator
{
    /**
     * Check the structure of the token.
     *
     * @param string $value
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
     * @param string[] $parts
     * @param string   $token
     *
     * @throws TokenInvalidException
     *
     * @return bool
     */
    protected function validateStructure(array $parts, $token)
    {
        if (count($parts) !== 3) {
            throw new TokenInvalidException('Wrong number of parts for token');
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
     * @param string[] $parts
     *
     * @throws JwtException
     *
     * @return bool
     */
    protected function validateParts($parts)
    {
        list($headerB64, $payloadB64, $cryptoB64) = $parts;

        $header = json_decode(Base64::decode($headerB64));
        $payload = json_decode(Base64::decode($payloadB64));

        if (!$header) {
            throw new JwtException('Invalid header segment encoding');
        }

        if (!$payload) {
            throw new JwtException('Invalid payload segment encoding');
        }

        if (!$cryptoB64) {
            throw new JwtException('Invalid encrypted segment encoding');
        }

        return true;
    }
}
