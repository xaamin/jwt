<?php
namespace Xaamin\JWT;

use Xaamin\JWT\Support\Base64;
use Xaamin\JWT\Validation\TokenValidation;

class Token
{
	/**
	 * Header array
	 * 
	 * @var array
	 */
	protected $header;

	/**
	 * Payload
	 * 
	 * @var array
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
	 * JWT Token
	 * 
	 * @var string
	 */
	protected $value;

	/**
	 * Constructor
	 * 
	 * @param string $value
	 */
	public function __construct($value)
	{
		$this->value = $value;
		
		(new TokenValidation())->check($value);

		$this->setInternalAttributes(explode('.', $value));
	}
	
	/**
	 * Set token segments
	 * 
	 * @param array $segments
	 */
	protected function setInternalAttributes(array $segments)
	{
		list($this->headerBase64, $this->payloadBase64, $signatureBase64) = $segments;

        $this->header = json_decode(Base64::decode($this->headerBase64), true);
        $this->payload = json_decode(Base64::decode($this->payloadBase64), true);
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
	 * @return array
	 */
	public function getHeader()
	{
		return $this->header;
	}

	/**
	 * Returns payload
	 * 
	 * @return array
	 */
	public function getPayload()
	{
		return $this->payload;
	}

	/**
	 * Returns the signature
	 * 
	 * @return string
	 */
	public function getSignature()
	{
		return $this->signature;;
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
}