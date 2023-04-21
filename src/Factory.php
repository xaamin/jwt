<?php

namespace Xaamin\Jwt;

use Xaamin\Jwt\Payload;
use Xaamin\Jwt\Support\Str;
use Xaamin\Jwt\Support\Date;
use Xaamin\Jwt\Constants\JwtTtl;

class Factory
{
    /**
     * @var int
     */
    protected $ttl = JwtTtl::TTL;

    /**
     * The issuer
     *
     * @var string
     */
    protected $issuer = null;

    /**
     * @var string[]
     */
    protected $defaultClaims = ['iss', 'iat', 'exp', 'nbf', 'jti'];

    /**
     * @var array<string,mixed>
     */
    protected $claims = [];

    /**
     * Array of claims to ignore
     *
     * @var array<string>
     */
    protected $except = [];

    /**
     * Custom claims.
     *
     * @var array<string,mixed>
     */
    protected $customClaims = [];

    /**
     * Required claims.
     *
     * @var string[]
     */
    protected $requiredClaims = [];

    /**
     * Create the Payload instance.
     *
     * @return Payload
     */
    public function make()
    {
        $claims = $this->buildClaims();

        return (new Payload($claims, false))->check($this->except);
    }

    /**
     * Add an array of claims to the Payload.
     *
     * @param array<string,mixed> $claims
     *
     * @return Factory
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
     * @param string $name
     * @param mixed  $value
     *
     * @return Factory
     */
    public function addClaim($name, $value)
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Set the custom claims.
     *
     * @param array<string,mixed> $customClaims
     *
     * @return Factory
     */
    public function addCustomClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * Alias to set the custom claims.
     *
     * @param array<string,mixed> $customClaims
     *
     * @return Factory
     */
    public function claims(array $customClaims)
    {
        return $this->addCustomClaims($customClaims);
    }
    /**
     * Get the custom claims.
     *
     * @return array<string,mixed>
     */
    public function getCustomClaims()
    {
        return $this->customClaims;
    }

    /**
     * Build the default claims.
     *
     * @return array<string,mixed>
     */
    protected function buildClaims()
    {
        $this->except = [];

        // Remove the exp claim if it exists and the ttl is null
        if ($this->ttl === null && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // Add the default claims
        foreach ($this->defaultClaims as $claim) {
            if (!isset($this->claims[$claim])) {
                $this->addClaim($claim, $this->$claim());
            } elseif (in_array($claim, ['iat', 'nbf', 'exp'])) {
                $this->except[] = $claim;
            }
        }

        // Add custom claims on top, allowing them to overwrite defaults
        $this->addClaims($this->getCustomClaims());

        return $this->claims;
    }

    /**
     * Sets the required claims.
     *
     * @param string[] $claims
     *
     * @return Factory
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Sets the issuer.
     *
     * @param string $issuer
     *
     * @return Factory
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;

        return $this;
    }

    /**
     * Get the Issuer (iss) claim.
     *
     * @return string
     */
    public function iss()
    {
        if ($this->issuer) {
            return $this->issuer;
        }

        $issuer = 'http';

        $https = isset($_SERVER['HTTPS']) ? $_SERVER['HTTPS'] : 'off';
        $host = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
        $hasCustomPort = isset($_SERVER['SERVER_PORT'])
            && $_SERVER['SERVER_PORT'] != '80'
            && $_SERVER['SERVER_PORT'] != '443';

        if (strtolower($https) != 'off') {
            $issuer .= "s";
        }

        $issuer .= '://' . $host;

        if ($hasCustomPort) {
            $issuer .= ':' . $_SERVER['SERVER_PORT'];
        }

        $issuer .= isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';

        return trim($issuer, '/');
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
        return Date::now()->modify("+{$this->ttl} minutes")->getTimestamp();
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
     * @param int $ttl
     *
     * @return Factory
     */
    public function setTtl($ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     *
     * @return int
     */
    public function getTtl()
    {
        return $this->ttl;
    }

    /**
     * Set the default claims to be added to the Payload.
     *
     * @param string[] $claims
     *
     * @return Factory
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Get the default claims.
     *
     * @return string[]
     */
    public function getDefaultClaims()
    {
        return $this->defaultClaims;
    }

    /**
     * Magically add a claim.
     *
     * @param string       $method
     * @param array<mixed> $parameters
     *
     * @return Factory
     */
    public function __call($method, $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
