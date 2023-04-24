<?php

namespace Xaamin\Jwt\Validation;

use Xaamin\Jwt\Support\Date;
use Xaamin\Jwt\Constants\JwtTtl;
use Xaamin\Jwt\Exceptions\TokenExpiredException;
use Xaamin\Jwt\Exceptions\TokenInvalidException;
use Xaamin\Jwt\Exceptions\TokenBeforeValidException;

class PayloadValidation extends Validator
{
    /**
     * @var string[]
     */
    protected $requiredClaims = ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'];

    /**
     * @var int
     */
    protected $refreshTtl = JwtTtl::REFRESH_TTL;

    /**
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     * Run the validations on the payload array.
     *
     * @param array<string,mixed> $value
     * @param array<string>|array<void> $except
     *
     * @return void
     */
    public function check($value, array $except = [])
    {
        $this->validateStructure($value);

        if (!$this->refreshFlow) {
            $this->validateTimestamps($value, $except);
        } else {
            $this->validateRefresh($value);
        }
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param array<string,mixed> $payload
     *
     * @throws TokenInvalidException
     *
     * @return bool
     */
    protected function validateStructure(array $payload)
    {
        if (count(array_diff($this->requiredClaims, array_keys($payload))) !== 0) {
            throw new TokenInvalidException('Jwt payload does not contain the required claims');
        }

        return true;
    }

    /**
     * Validate the payload timestamps.
     *
     * @param array<string,mixed> $payload
     * @param array<string>|array<void> $except
     *
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     * @throws TokenBeforeValidException
     *
     * @return bool
     */
    protected function validateTimestamps(array $payload, array $except = [])
    {
        if (!in_array('nbf', $except) && isset($payload['nbf']) && Date::isFuture(intval($payload['nbf']))) {
            throw new TokenBeforeValidException('Not Before (nbf) timestamp cannot be in the future');
        }

        if (!in_array('iat', $except) && isset($payload['iat']) && Date::isFuture(intval($payload['iat']))) {
            throw new TokenBeforeValidException('Issued At (iat) timestamp cannot be in the future');
        }

        if (!in_array('exp', $except) && isset($payload['exp']) && Date::isPast(intval($payload['exp']))) {
            throw new TokenExpiredException('Token has expired');
        }

        return true;
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param array<string,mixed> $payload
     *
     * @throws TokenExpiredException
     *
     * @return bool
     */
    protected function validateRefresh(array $payload)
    {
        if ($this->refreshTtl === null) {
            return true;
        }

        if (isset($payload['iat']) && Date::isPast(intval($payload['iat']) + $this->refreshTtl * 60)) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed');
        }

        return true;
    }

    /**
     * Sets the required claims.
     *
     * @param array<string> $claims
     *
     * @return PayloadValidation
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param int $ttl
     *
     * @return PayloadValidation
     */
    public function setRefreshTtl($ttl)
    {
        $this->refreshTtl = $ttl;

        return $this;
    }

    /**
     * Set the refresh flow flag.
     *
     * @param bool $refreshFlow
     *
     * @return PayloadValidation
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
