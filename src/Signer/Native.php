<?php

namespace Xaamin\Jwt\Signer;

use InvalidArgumentException;
use UnexpectedValueException;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Contracts\Signer as SignerContract;

class Native implements SignerContract
{
    /**
     * Secret used by Symmetric algorithms
     *
     * @var string|null
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
     * @var array{private:string,public:string}|array<void>
     */
    protected $keys = [];

    /**
     * Constructor
     *
     * @param string|null $secret
     * @param string $algorithm
     * @param array{private:string,public:string}|array<void> $keys
     */
    public function __construct($secret = null, $algorithm = 'HS512', array $keys = [])
    {
        $this->secret = $secret;
        $this->algorithm = $algorithm;

        $keys = array_filter($keys);

        if (count($keys)) {
            // @phpstan-ignore-next-line
            $this->setKeys($keys);
        }
    }

    /**
     * Set the keys
     *
     * @param array{private?:string,public?:string} $keys
     *
     * @return void
     */
    protected function setKeys(array $keys)
    {
        $length = count($keys);

        if ($length > 0 && (empty($keys['private']) || empty($keys['public']))) {
            throw new UnexpectedValueException(
                'You must provide both public and private keys for RS signing algorithm.'
            );
        }

        if ($length === 0) {
            return;
        }

        $this->keys = [
            'private' => $this->getKeyContent($keys['private']),
            'public' => $this->getKeyContent($keys['public'])
        ];
    }

    /**
     * Get the key content as string, reads from file if required
     *
     * @param string $content
     *
     * @return string
     */
    protected function getKeyContent($content)
    {
        $file = strval(str_replace("\0", '', $content));

        if (file_exists($file)) {
            if (!is_readable($file)) {
                throw new UnexpectedValueException('The file provided is not readable.');
            }

            /** @var string */
            $content = file_get_contents($content);
        }

        return $content;
    }

    /**
     * {@inheritDoc}
     */
    public function verify($signature, $value)
    {
        switch ($this->algorithm) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return $this->sign($value) === $signature;

            case 'RS256':
                $pubKeyId = $this->getPublicKeyId();

                return openssl_verify($value, $signature, $pubKeyId, OPENSSL_ALGO_SHA256) !== false;

            case 'RS384':
                $pubKeyId = $this->getPublicKeyId();

                return openssl_verify($value, $signature, $pubKeyId, OPENSSL_ALGO_SHA384) !== false;

            case 'RS512':
                $pubKeyId = $this->getPublicKeyId();

                return openssl_verify($value, $signature, $pubKeyId, OPENSSL_ALGO_SHA512) !== false;

            default:
                throw new JwtException("Unsupported or invalid signing algorithm.");
        }
    }

    /**
     * Get the public key id
     *
     * @throws JwtException
     *
     * @return \OpenSSLAsymmetricKey
     */
    protected function getPublicKeyId()
    {
        if (empty($this->keys['public'])) {
            throw new JwtException('Public key not provided');
        }

        /** @var \OpenSSLAsymmetricKey|false */
        $pubKeyId = false;

        try {
            $pubKeyId = openssl_pkey_get_public(strval($this->keys['public']));

            if (!$pubKeyId) {
                throw new JwtException("Unable to parse your public key.");
            }
        } finally {
            if (function_exists('openssl_free_key') && $pubKeyId !== false) {
                @openssl_free_key($pubKeyId);
            }
        }

        return $pubKeyId;
    }

    /**
     * {@inheritDoc}
     */
    public function sign($value)
    {
        switch ($this->algorithm) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                if (!$this->secret) {
                    throw new InvalidArgumentException('Passphrase not provided');
                }
                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
                if (empty(array_filter($this->keys))) {
                    throw new InvalidArgumentException('Keys not provided');
                }
                break;
            default:
                break;
        }

        switch ($this->algorithm) {
            case 'HS256':
                return hash_hmac('sha256', $value, strval($this->secret), true);
            case 'HS384':
                return hash_hmac('sha384', $value, strval($this->secret), true);
            case 'HS512':
                return hash_hmac('sha512', $value, strval($this->secret), true);
            case 'RS256':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA256);
            case 'RS384':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA384);
            case 'RS512':
                return $this->generateRSA($value, OPENSSL_ALGO_SHA512);

            default:
                throw new JwtException('Unsupported or invalid signing algorithm.');
        }
    }

    /**
     * Sign using RSA
     *
     * @param string $value
     * @param int $algorithm
     *
     * @throws JwtException
     *
     * @return string
     */
    private function generateRSA($value, $algorithm)
    {
        if (empty($this->keys['private'])) {
            throw new JwtException('Private key not provided');
        }

        /** @var \OpenSSLAsymmetricKey|false */
        $privateKey = null;
        $signature = null;

        try {
            $privateKey = openssl_get_privatekey(strval($this->keys['private']), $this->secret);

            if (!$privateKey) {
                throw new JwtException('Unable to parse your private key.');
            }

            openssl_sign($value, $signature, $privateKey, $algorithm);

            if (!$signature) {
                throw new JwtException('Unable to sign data using RSA.');
            }
        } finally {
            if (function_exists('openssl_free_key') && $privateKey !== false) {
                @openssl_free_key($privateKey);
            }
        }

        return $signature;
    }

    /**
     * {@inheritDoc}
     */
    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;

        return $this;
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
