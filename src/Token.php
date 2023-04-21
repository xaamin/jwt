<?php

namespace Xaamin\Jwt;

use Xaamin\Jwt\Support\Base64;
use Xaamin\Jwt\Validation\TokenValidation;

class Token
{
    /**
     * Header array
     *
     * @var array<string,mixed>
     */
    protected $header;

    /**
     * Payload
     *
     * @var Payload
     */
    protected $payload;

    /**
     * Header as base64
     *
     * @var string
     */
    protected $headerBase64;

    /**
     * Payload as base64
     *
     * @var string
     */
    protected $payloadBase64;

    /**
     * Signature
     *
     * @var string
     */
    protected $signature;

    /**
     * Jwt Token
     *
     * @var string
     */
    protected $value;

    /**
     * Constructor
     *
     * @param string $value
     * @param TokenValidation|null $validator
     */
    public function __construct($value, TokenValidation $validator = null)
    {
        $this->value = $value;

        $validator = $validator ?: new TokenValidation();

        $validator->check($value);

        $this->setInternalAttributes(explode('.', $value));
    }

    /**
     * Set token segments
     *
     * @param string[] $segments
     *
     * @return void
     */
    protected function setInternalAttributes(array $segments)
    {
        list($this->headerBase64, $this->payloadBase64, $signatureBase64) = $segments;

        /** @var array<string,mixed> */
        $header = json_decode(Base64::decode($this->headerBase64), true);
        /** @var array<string,mixed> */
        $payload = json_decode(Base64::decode($this->payloadBase64), true);

        $this->header = $header;
        $this->payload = new Payload($payload);
        $this->signature = Base64::decode($signatureBase64);
    }

    /**
     * Returns header base 64 encoded
     *
     * @return string
     */
    public function getHeaderBase64()
    {
        return $this->headerBase64;
    }

    /**
     * Returns payload base 64 encoded
     *
     * @return string
     */
    public function getPayloadBase64()
    {
        return $this->payloadBase64;
    }

    /**
     * Returns header
     *
     * @return array<string,mixed>
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Returns payload
     *
     * @return array<string,mixed>
     */
    public function getPayload()
    {
        return $this->payload->toArray();
    }

    /**
     * Returns the signature
     *
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Get the token.
     *
     * @return string
     */
    public function get()
    {
        return $this->value;
    }

    /**
     * String representation of the token
     *
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    }

    /**
     * Getter for payload claims
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        return $this->payload->get($name);
    }
}
