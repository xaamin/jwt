<?php

namespace Xaamin\Jwt;

use Countable;
use ArrayAccess;
use Xaamin\Jwt\Constants\JwtTtl;
use Xaamin\Jwt\Exceptions\PayloadException;
use Xaamin\Jwt\Validation\PayloadValidation;

/**
 * @implements ArrayAccess<string,mixed>
 */
class Payload implements Countable, ArrayAccess
{
    /**
     * Claims in payload
     *
     * @var array<string,mixed>
     */
    protected $claims;

    /**
     * Payload validator
     *
     * @var PayloadValidation
     */
    protected $validator;

    /**
     * Constructor
     *
     * @param array<string,mixed> $claims
     * @param boolean $refreshFlow
     * @param int|null $refreshTtl
     * @param PayloadValidation|null $validator
     */
    public function __construct(
        array $claims,
        $refreshFlow = false,
        $refreshTtl = JwtTtl::REFRESH_TTL,
        PayloadValidation $validator = null
    ) {
        $this->validator = $validator ?: new PayloadValidation();

        $refreshTtl && $this->validator->setRefreshTtl($refreshTtl);

        $this->validator->setRefreshFlow($refreshFlow);

        $this->claims = $claims;
    }

    /**
     * Check against validations
     *
     * @param array<string>|array<void> $except
     *
     * @return Payload
     */
    public function check(array $except = [])
    {
        $this->validator->check($this->claims, $except);

        return $this;
    }

    /**
     * Get the payload.
     *
     * @param string|string[]|null $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        if ($claim) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return isset($this->claims[$claim]) ? $this->claims[$claim] : null;
        }

        return $this->toArray();
    }

    /**
     * Determine whether the payload has the claim.
     *
     * @param string $claim
     *
     * @return bool
     */
    public function has($claim)
    {
        return isset($this->claims[$claim]);
    }

    /**
     * Get the array of claims.
     *
     * @return array<string,mixed>
     */
    public function toArray()
    {
        return $this->claims;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array<string,mixed>
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     *
     * @param int $options
     *
     * @return string
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES)
    {
        /** @var string */
        $decoded = json_encode($this->jsonSerialize(), $options);

        return $decoded;
    }

    /**
     * Sets the required claims.
     *
     * @param string[] $claims
     *
     * @return Payload
     */
    public function setRequiredClaims(array $claims)
    {
        $this->validator->setRequiredClaims($claims);

        return $this;
    }

    /**
     * Get the payload as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson();
    }
    /**
     * Determine if an item exists at an offset.
     *
     * @param string $key
     *
     * @return bool
     */
    public function offsetExists($key): bool
    {
        return $this->has($key);
    }

    /**
     * Get an item at a given offset.
     *
     * @param string $key
     *
     * @return mixed
     */
    public function offsetGet($key): mixed
    {
        return $this->get($key);
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param string $key
     * @param mixed  $value
     *
     * @throws PayloadException
     */
    public function offsetSet($key, $value): void
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param string $key
     *
     * @throws PayloadException
     *
     * @return void
     */
    public function offsetUnset($key): void
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->toArray());
    }

    /**
     * Invoke the Payload as a callable function.
     *
     * @param string|string[]|null $claim
     *
     * @return mixed
     */
    public function __invoke($claim = null)
    {
        return $this->get($claim);
    }
}
