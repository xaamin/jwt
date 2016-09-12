<?php
namespace Xaamin\JWT\Contracts;

interface Signer
{
	/**
	 * Verifies that signature is unadulterated
	 * 
	 * @param  string $signature
	 * @param  string $value     Original string
	 * 
	 * @return boolean
	 */
    public function verify($signature, $value);

    /**
     * Sign given value
     * 
     * @param  string $value
     * 
     * @return string
     */
    public function sign($value);

    /**
     * Set new algorithm
     * 
     * @param string $algorithm
     */
    public function setAlgorithm($algorithm);

    /**
     * Get algorithm used for sign
     * 
     * @return string
     */
    public function getAlgorithm();

    /**
     * [getSecret description]
     * 
     * @return string
     */
    public function getSecret();
}