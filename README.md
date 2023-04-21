# PHP Jwt Tokens with RSA Support

PHP Implementation of JSON Web token with RSA.

## Supported algorithms:
	RSA (Public Key/Private Key pair)

	RS256 - RSA using SHA-256 hash algorithm
	RS384 - RSA using SHA-384 hash algorithm
	RS512 - RSA using SHA-512 hash algorithm

	HMAC algorithms:

	HS256 - HMAC using SHA-256 hash algorithm (default)
	HS384 - HMAC using SHA-384 hash algorithm
	HS512 - HMAC using SHA-512 hash algorithm

## Install

With composer

```
composer require xaamin/jwt
````

# How to use with RSA public/private key

Set configuration in **/config/config.php**.

```
    'algorithm' => 'RS512',

    'passphrase' => 'your-passphrase',

    'keys' => [
        'public' => '/keys/public_key.pem',
        'private' => '/keys/private_key.pem',
    ],
```


```php
	$payload = [
        'sub'   => 1,
        'user' => 'Xaamin'
    ];

	// Generate token
	$token = Jwt::encode($payload);

	// Verify the token
	try{
		$token = Jwt::decode($token->get());

	    var_dump($token);
	} catch (Exception $e) {
		echo $e->getMessage();
	}
```

## How to use with HMAC

Set configuration in **src/Config/config.php**

```
    'algorithm' => 'HS512',

    'passphrase' => 'your-super-secret'
```

```php
    use Xaamin\Jwt\Facades\Native\Jwt;

	$payload = [
        'sub'   => 1,
        'username' => 'xaamin'
    ];

	// Generate token
	$token = Jwt::encode($payload);

	// Verify the token
	try{
		$token = Jwt::decode($token->get());
	} catch (Exception $e) {
		echo $e->getMessage();
	}
```
