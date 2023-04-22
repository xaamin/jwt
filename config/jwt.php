<?php

return [
   	/**
     * Specify the hashing algorithm that will be used to sign the token.
     *
     * Symmetric Algorithms:
     *  	HS256, HS384 & HS512 will use 'secret'.
     *
     * Asymmetric Algorithms:
     * 		RS256, RS384 & RS512 will use 'keys'
     */
	'algorithm' => 'HS512',

   	/**
     * It will be used to sign your tokens, used for Symmetric algorithms.
   	 */
    'secret' => null,

    /**
     * When checking nbf, iat or expiration times, we want to provide some extra leeway time
     * to account for clock skew expressed in seconds.
     */
    'leeway' => 0,

    /**
     * Specify the length of time (in minutes) that the token will be valid for.
     * Defaults to 1 hour.
     *
     * You can also set this to null, to yield a never expiring token.
     */
    'ttl' => 60,

    /**
     * Refresh time to live
     *
     * I.E. The user can refresh their token within a 2 week window of
     * the original token being created until they must re-authenticate.
     * Defaults to 2 weeks.
     *
     * You can also set this to null, to yield an infinite refresh time.
     */
    'refresh_ttl' => 20160,

    /**
     * For asymmetric algorithm use the following public & private keys.
     */
    'keys' => [
        /**
         * Path or string of your public key.
         */
        'public' => null,

        /**
         * Path or string of your private key.
         */
        'private' => null,

        /*
         * The passphrase for your private key. Can be null if none set.
         */
        'passphrase' => null,
    ],

    /**
     * Specify the required claims that must exist in any token.
     *
     * A TokenInvalidException will be thrown if any of these claims are not
     * present in the payload.
     */
    'required_claims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],
];
