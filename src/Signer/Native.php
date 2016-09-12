<?php
namespace Xaamin\JWT\Signer;

use Xaamin\JWT\Exceptions\JWTException;
use Xaamin\JWT\Contracts\Signer as SignerContract;

class Native implements SignerContract
{
    /**
     * Secret used by Symmetric algorithms
     * 
     * @var string
     */
	protected $secret;

    /**
     * Algorithm used for signing
     * 
     * @var string
     */
	protected $algorithm;

    /**
     * Keys used by Asymmetric algorithms
     * 
     * @var array
     */
    protected $keys;

    /**
     * Constructor
     * 
     * @param string $secret
     * @param string $algorithm
     * @param array  $keys
     */
	public function __construct($secret, $algorithm = 'HS512', array $keys = [])
	{
		$this->secret = $secret;
		$this->algorithm = $algorithm;
        $this->keys = $keys;
	}

    /**
     * {@inheritDoc}
     */
	public function verify($signature, $value)
    {
        switch ($this->algorithm) {
            case'HS256':
            case'HS384':
            case'HS512':
                return $this->sign($value, $this->secret, $this->algorithm) === $signature;

            case 'RS256':
                return (boolean) openssl_verify($value, $signature, $this->keys['public'], OPENSSL_ALGO_SHA256);

            case 'RS384':
                return (boolean) openssl_verify($value, $signature, $this->keys['public'], OPENSSL_ALGO_SHA384);

            case 'RS512':
                return (boolean) openssl_verify($value, $signature, $this->keys['public'], OPENSSL_ALGO_SHA512);

            default:
                throw new JWTException("Unsupported or invalid signing algorithm.");
        }
    }

    /**
     * {@inheritDoc}
     */
    public function sign($value)
    {
        switch ($this->algorithm) {

            case 'HS256':
                return hash_hmac('sha256', $value, $this->secret, true);

            case 'HS384':
                return hash_hmac('sha384', $value, $this->secret, true);

            case 'HS512':
                return hash_hmac('sha512', $value, $this->secret, true);

            case 'RS256':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA256);
            case 'RS384':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA384);
            case 'RS512':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA512);

            default:
                throw new JWTException("Unsupported or invalid signing algorithm.");
        }
    }

    /**
     * Sign using RSA
     * 
     * @param  string $input
     * @param  string $algo
     * 
     * @return string
     */
    private function generateRSA($input, $algo)
    {
        if (!openssl_sign($input, $signature, $this->keys['private'], $algo)) {
            throw new JWTException("Unable to sign data using RSA.");
        }

        return $signature;
    }

    /**
     * {@inheritDoc}
     */
    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function getSecret()
    {
        return $this->secret;
    }
}