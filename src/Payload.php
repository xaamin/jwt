<?php
namespace Xaamin\JWT;

use Countable;
use ArrayAccess;
use Xaamin\JWT\Validation\PayloadValidation;

class Payload implements Countable, ArrayAccess
{
    /**
     * Claims in payload
     * 
     * @var array
     */
	protected $claims;

    /**
     * Constructor
     * 
     * @param array             $claims
     * @param PayloadValidation $validation
     * @param boolean           $refreshFlow
     */
	public function __construct(array $claims, PayloadValidation $validation, $refreshFlow = false)
	{
        $validation = $validation ? : new PayloadValidation;

		$validation->setRefreshFlow($refreshFlow)->check($claims);

		$this->claims = $claims;
	}

    /**
     * Get the payload.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        $claim = value($claim);

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
     * @return bool
     */
    public function has($claim)
    {
        return isset($this->claims[$claim]);
    }

    /**
     * Get the array of claims.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->claims;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     *
     * @param  int  $options
     *
     * @return string
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES)
    {
        return json_encode($this->jsonSerialize(), $options);
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
     * @param  mixed  $key
     *
     * @return bool
     */
    public function offsetExists($key)
    {
        return $this->has($key);
    }

    /**
     * Get an item at a given offset.
     *
     * @param  mixed  $key
     *
     * @return mixed
     */
    public function offsetGet($key)
    {
        return $this->get($key);
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     *
     * @throws \Xaamin\JWT\Exceptions\PayloadException
     */
    public function offsetSet($key, $value)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param  string  $key
     *
     * @throws \Xaamin\JWT\Exceptions\PayloadException
     *
     * @return void
     */
    public function offsetUnset($key)
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims.
     *
     * @return int
     */
    public function count()
    {
        return count($this->toArray());
    }

    /**
     * Invoke the Payload as a callable function.
     *
     * @param  mixed  $claim
     *
     * @return mixed
     */
    public function __invoke($claim = null)
    {
        return $this->get($claim);
    }
}