<?php

namespace Xaamin\Jwt\Contracts;

interface Signer
{
    /**
     * Verifies that signature is unadulterated
     *
     * @param string $signature
     * @param string $value Original string
     *
     * @return boolean
     */
    public function verify($signature, $value);

    /**
     * Sign given value
     *
     * @param string $value
     *
     * @return string
     */
    public function sign($value);

    /**
     * Set new algorithm
     *
     * @param string $algorithm
     *
     * @return Signer
     */
    public function setAlgorithm($algorithm);

    /**
     * Get algorithm used for sign
     *
     * @return string
     */
    public function getAlgorithm();

    /**
     * Returns the secret used for signing
     *
     * @return string|null
     */
    public function getSecret();
}
