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

## Installation

Install the latest version with composer

```
composer require xaamin/jwt
````

### Copy the config (Lumen only)

Copy the `config` file from `vendor/xaamin/jwt/config/jwt.php` to `config` folder of your Lumen application.

Register your config by adding the following in the `bootstrap/app.php` before middleware declaration.

```php
$app->configure('jwt');
```
### Bootstrap file changes (Lumen only)

Add the following snippet to the `bootstrap/app.php` file under the providers section as follows:

```php
// Uncomment this line
$app->register(App\Providers\AuthServiceProvider::class);

// Add this line
$app->register(Xaamin\Jwt\JwtServiceProvider::class);
```

### Generate secret key for HM algorithms

To generate a key for you:

```bash
php artisan jwt:secret
```

This will update your `.env` file with something like `JWT_SECRET=foobar`

It is the key that will be used to sign your tokens. How that happens exactly will depend on the algorithm that you choose to use.


### Generate RSA keys for RS algorithms

To generate a key for you:

```bash
php artisan jwt:keys
```

This will create 2 files (`jwt-private.key` and `jwt-public.key`) on your storage path and they are ready to use with no passphrase.

Those are the keys that will be used to sign your tokens. How that happens exactly will depend on the algorithm that you choose to use.



## How to use with HMAC

Set configuration in **src/Config/config.php**

```
    'algorithm' => 'HS512',

    'secret' => 'your-super-secret'
```

```php
    // Laravel or Lumen
    // use Xaamin\Jwt\\Jwt;
    // use Xaamin\Jwt\Facades\Native\Jwt;

    // Framework agnostic
    // use Xaamin\Jwt\Native\Jwt;

	$payload = [
        'sub'   => '7de9e1d8-d52b-4031-8c21-e627527b47f5',
        'usr' => 'Xaamin'
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


# How to use with RSA public/private key

Set configuration in **/config/config.php**.

```
    'algorithm' => 'RS512',

    'keys' => [
        'public' => '/keys/public_key.pem',
        'private' => '/keys/private_key.pem',
        'passphrase' => 'your-passphrase',
    ],
```


```php
	$payload = [
        'sub'   => '7de9e1d8-d52b-4031-8c21-e627527b47f5',
        'usr' => 'Xaamin'
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
``
