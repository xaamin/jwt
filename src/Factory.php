<?php
namespace Xaamin\JWT;

use Xaamin\JWT\Payload;
use Xaamin\JWT\Support\Str;
use Xaamin\JWT\Support\Date;
use Xaamin\JWT\Validation\PayloadValidation;

class Factory
{
    /**
     * @var int
     */
    protected $ttl = 60;

    /**
     * @var array
     */
    protected $defaultClaims = ['iss', 'iat', 'exp', 'nbf', 'jti'];

    /**
     * @var array
     */
    protected $claims = [];

    /**
     * Custom claims.
     *
     * @var array
     */
    protected $customClaims = [];

    /**
     * Payload validator
     *
     * @var \Xaamin\JWT\Validation\PayloadValidation
     */
    protected $validation;

    /**
     * Constructor
     *
     * @param \Xaamin\JWT\Validation\PayloadValidation $validation
     */
    public function __construct(PayloadValidation $validation)
    {
        $this->validation = $validation;
    }

    /**
     * Create the Payload instance.
     *
     * @return \Xaamin\JWT\Payload
     */
    public function make()
    {
        $claims = $this->buildClaims();

        return new Payload($claims, $this->validation);
    }

    /**
     * Add an array of claims to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function addClaims(array $claims)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload.
     *
     * @param  string  $name
     * @param  mixed  $value
     *
     * @return $this
     */
    public function addClaim($name, $value)
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function addCustomClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * Alias to set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function claims(array $customClaims)
    {
        return $this->addCustomClaims($customClaims);
    }
    /**
     * Get the custom claims.
     *
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->customClaims;
    }

    /**
     * Build the default claims.
     *
     * @return array
     */
    protected function buildClaims()
    {
        // Remove the exp claim if it exists and the ttl is null
        if ($this->ttl === null && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // Add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->$claim());
        }

        // Add custom claims on top, allowing them to overwrite defaults
        $this->addClaims($this->getCustomClaims());

        return $this->claims;
    }

    /**
     * Sets the required claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Get the Issuer (iss) claim.
     *
     * @return string
     */
    public function iss()
    {
        $issuer = 'http';
        $https = isset($_SERVER['HTTPS']) ? $_SERVER['HTTPS'] : 'off';

        if (strtolower($https) != 'off') {
            $issuer .= "s";
        }

        $issuer .= '://' . (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');

        if (isset($_SERVER['SERVER_PORT']) and $_SERVER['SERVER_PORT'] != '80' and $_SERVER['SERVER_PORT'] != '443') {
            $issuer .= ':' .$_SERVER['SERVER_PORT'];
        }

        $issuer .= isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';

        return $issuer;
    }

    /**
     * Get the Issued At (iat) claim.
     *
     * @return int
     */
    public function iat()
    {
        return Date::now()->getTimestamp();
    }

    /**
     * Get the Expiration (exp) claim.
     *
     * @return int
     */
    public function exp()
    {
        return Date::now()->addMinutes($this->ttl)->getTimestamp();
    }

    /**
     * Get the Not Before (nbf) claim.
     *
     * @return int
     */
    public function nbf()
    {
        return Date::now()->getTimestamp();
    }

    /**
     * Get a unique id (jti) for the token.
     *
     * @return string
     */
    protected function jti()
    {
        return md5(sprintf('%s.%s', json_encode($this->claims), Str::random(32)));
    }

    /**
     * Set the token ttl (in minutes).
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     *
     * @return int
     */
    public function getTTL()
    {
        return $this->ttl;
    }

    /**
     * Set the default claims to be added to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Get the default claims.
     *
     * @return array
     */
    public function getDefaultClaims()
    {
        return $this->defaultClaims;
    }

    /**
     * Returns the Payload Validator instance
     *
     * @return \Xaamin\JWT\Validation\PayloadValidation
     */
    public function getPayloadValidator()
    {
        return $this->validation;
    }

    /**
     * Magically add a claim.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @return $this
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}