<?php
namespace Xaamin\JWT;

use Xaamin\JWT\Token;
use Xaamin\JWT\Support\Str;
use Xaamin\JWT\Support\Date;
use Xaamin\JWT\Signer\Native;
use Xaamin\JWT\Support\Base64;
use Xaamin\JWT\Contracts\Signer;
use Xaamin\JWT\Exceptions\JWTException;
use Xaamin\JWT\Validation\TokenValidation;
use Xaamin\JWT\Exceptions\TokenInvalidException;

class JWT
{
    /**
     * Signer implementation
     * 
     * @var \Xaamin\JWT\Contracts\Signer
     */
    protected $signer;

    /**
     * Claim factory
     * 
     * @var \Xaamin\JWT\Factory
     */
    protected $factory;

    /**
     * Constructor
     * 
     * @param \Xaamin\JWT\Contracts\Signer  $signer
     * @param \Xaamin\JWT\Factory           $factory
     */
    public function __construct(Signer $signer, Factory $factory)
    {
        $this->signer = $signer;
        $this->factory = $factory;
    }

    /**
     * Generate new JWT token
     * 
     * @param  \Xaamin\JWT\Payload $payload
     * 
     * @return \Xaamin\JWT\Token
     */
    private function generateNewToken(Payload $payload)
    {
        $header = [
                'typ' => 'JWT', 
                'alg' => $this->signer->getAlgorithm()
            ];

        $segments = [
            Base64::encode(json_encode($header), JSON_UNESCAPED_SLASHES),
            Base64::encode($payload->toJson(), JSON_UNESCAPED_SLASHES)
        ];

        $signature = $this->signer->sign(implode('.', $segments));

        $segments[] = Base64::encode($signature);

        return new Token(implode('.', $segments));
    }

    /**
     * Encode a Payload and return the Token.
     * 
     * @param  array  $claims 
     * 
     * @return \Xaamin\JWT\Token
     */
    public function encode(array $claims)
    {
        $payload = $this->factory->addClaims($claims)->make();

        return $this->generateNewToken($payload);
    }

    /**
     * Decodes a JWT token
     * 
     * @param  string $jwt
     * 
     * @return \Xaamin\JWT\Token
     */
    public function decode($jwt)
    {
        $token = new Token($jwt);

        $headerB64 = $token->getHeaderBase64();
        $payloadB64 = $token->getPayloadBase64();
        $header = $token->getHeader();

        if (empty($header['alg'])) {
            throw new JWTException('Empty algorithm');
        }

        if (!$this->signer->verify($token->getSignature(), "$headerB64.$payloadB64")) {
            throw new TokenInvalidException('Signature verification failed');
        }

        return $token;
    }

    /**
     * Refresh JWT token
     * 
     * @param  string   $jwt
     * 
     * @return \Xaamin\JWT\Token
     */
    public function refresh($jwt)
    {
        $claims = $this->decode($jwt)->getPayload();

        $payload = new Payload($claims, $this->factory->getPayloadValidator(), true);

        $payload = $this->factory->addClaims($claims)->make();

        return $this->generateNewToken($payload);
    }

    /**
     * Set new Signer strategy
     * 
     * @param \Xaamin\JWT\Contracts\Signer $signer
     *
     * @return void
     */
    public function setSigner(Signer $signer)
    {
        $this->signer = $signer;
    }

    /**
     * Magic method call on claims facory
     * 
     * @param  string   $method
     * @param  array    $parameters
     * 
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        return call_user_func_array([$this->factory, $method], $parameters);
    }
}