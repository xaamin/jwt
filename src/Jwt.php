<?php

namespace Xaamin\Jwt;

use RuntimeException;
use Xaamin\Jwt\Token;
use Xaamin\Jwt\Support\Date;
use Xaamin\Jwt\Signer\Native;
use Xaamin\Jwt\Support\Base64;
use Xaamin\Jwt\Constants\JwtTtl;
use Xaamin\Jwt\Contracts\Signer;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenInvalidException;
use Xaamin\Jwt\Exceptions\TokenInvalidSignatureException;

class Jwt
{
    /**
     * Signer implementation
     *
     * @var Signer|null
     */
    protected $signer;

    /**
     * Claim factory
     *
     * @var Factory
     */
    protected $factory;

    /**
     * Custom refresh TTL
     *
     * @var int|null
     */
    protected $refreshTtl = JwtTtl::REFRESH_TTL;

    /**
     * Constructor
     *
     * @param Signer|null  $signer
     * @param Factory|null $factory
     */
    public function __construct(Signer $signer = null, Factory $factory = null)
    {
        $this->signer = $signer;
        $this->factory = $factory ?: new Factory();
    }

     /**
      * Constructor
      *
      * @param string                                          $secret
      * @param string                                          $algorithm
      * @param array{private:string,public:string}|array<void> $keys
      *
      * @return Jwt
      */
    public function with($secret, $algorithm = 'HS512', array $keys = [])
    {
        $this->signer = new Native($secret, $algorithm, $keys);

        return $this;
    }

    /**
     * Generate new token
     *
     * @param Payload $payload
     *
     * @throws RuntimeException
     *
     * @return Token
     */
    private function generateNewToken(Payload $payload)
    {
        if (!$this->signer) {
            throw new RuntimeException('No signer provided');
        }

        $header = [
            'typ' => 'Jwt',
            'alg' => $this->signer->getAlgorithm()
        ];

        /** @var string */
        $headerB64 = json_encode($header);

        $segments = [
            Base64::encode($headerB64),
            Base64::encode($payload->toJson())
        ];

        $signature = $this->signer->sign(implode('.', $segments));

        $segments[] = Base64::encode($signature);

        return new Token(implode('.', $segments));
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param array <string,mixed> $claims
     *
     * @return Token
     */
    public function encode(array $claims)
    {
        $payload = $this->factory->addClaims($claims)->make();

        return $this->generateNewToken($payload);
    }

    /**
     * Decodes a token
     *
     * @param string $jwt
     *
     * @throws RuntimeException
     *
     * @return Token
     */
    public function decode($jwt)
    {
        if (!$this->signer) {
            throw new RuntimeException('No signer provided');
        }

        $jwt = $this->parse($jwt);

        $token = new Token($jwt);

        $headerB64 = $token->getHeaderBase64();
        $payloadB64 = $token->getPayloadBase64();
        $header = $token->getHeader();

        if (empty($header['alg'])) {
            throw new JwtException('Empty algorithm');
        }

        if (!$this->signer->verify($token->getSignature(), "{$headerB64}.{$payloadB64}")) {
            throw new TokenInvalidSignatureException('Signature verification failed');
        }

        return $token;
    }

    /**
     * Refresh token
     *
     * @param string $jwt
     *
     * @return Token
     */
    public function refresh($jwt)
    {
        $claims = $this->decode($jwt)->getPayload();

        $payload = (new Payload($claims, true, $this->refreshTtl))->check();

        /** @var array<string,mixed> */
        $payload = $payload->get();

        $payload = $this->factory->addClaims($payload)->make();

        return $this->generateNewToken($payload);
    }

    /**
     * Validates token validity
     *
     * @param string $jwt
     *
     * @return boolean
     */
    public function check($jwt)
    {
        try {
            $this->checkOrFail($jwt);
        } catch (JwtException $e) {
            return false;
        }

        return true;
    }

    /**
     * Validates token validity
     *
     * @param string $jwt
     *
     * @throws JwtException
     *
     * @return Payload
     */
    public function checkOrFail($jwt)
    {
        $claims = $this->decode($jwt)->getPayload();

        return (new Payload($claims))->check();
    }

    /**
     * Set new Signer strategy
     *
     * @param Signer $signer
     *
     * @return Jwt
     */
    public function setSigner(Signer $signer)
    {
        $this->signer = $signer;

        return $this;
    }

    /**
     * Set the token ttl
     *
     * @param int $seconds
     *
     * @return Jwt
     */
    public function setLeeway($seconds)
    {
        Date::$leeway = $seconds;

        return $this;
    }

    /**
     * Set the token ttl
     *
     * @param int|null $minutes
     *
     * @return Jwt
     */
    public function setTtl($minutes)
    {
        $this->factory->setTtl($minutes);

        return $this;
    }

    /**
     * Set the token ttl
     *
     * @param int|null $minutes
     *
     * @return Jwt
     */
    public function setRefreshTtl($minutes)
    {
        $this->refreshTtl = $minutes;

        return $this;
    }

    /**
     * Sets the issuer.
     *
     * @param string|null $issuer
     *
     * @return Jwt
     */
    public function setIssuer($issuer)
    {
        $this->factory->setIssuer($issuer);

        return $this;
    }

    /**
     * Sets the required claims.
     *
     * @param array<string> $claims
     *
     * @return Jwt
     */
    public function setRequiredClaims(array $claims)
    {
        $this->factory->setRequiredClaims($claims);

        return $this;
    }

    /**
     * Parse token from header
     *
     * @param  string $token
     * @return string
     */
    protected function parse($token)
    {
        $parts = explode(' ', $token);
        $jwt = trim(array_pop($parts));

        if (!$jwt) {
            throw new TokenInvalidException('Missing authentication token');
        }

        return $jwt;
    }

    /**
     * Magic method call on claims facory
     *
     * @param string       $method
     * @param array<mixed> $parameters
     *
     * @throws RuntimeException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        $callable = [$this->factory, $method];

        if (is_callable($callable)) {
            return call_user_func_array($callable, $parameters);
        }

        throw new RuntimeException("Method {$method} not found or not callable.");
    }
}
