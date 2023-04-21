<?php

use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Factory;
use Xaamin\Jwt\Support\Str;
use Xaamin\Jwt\Signer\Native;

require __DIR__ . '/../vendor/autoload.php';

$config = require __DIR__ . '/../config/jwt.php';

$passphrase = Str::random(32);
$algo = $config['algorithm'];
$keys = $config['keys'];

$factory = new Factory();
$signer = new Native($passphrase, $algo, $keys);

$jwt = new Jwt($signer, $factory);

$token = $jwt->encode([
    'sub' => 'a7db35aa-4169-412d-b8c1-de6aef0c6cc6'
]);

print_r($token->get());
print_r("\n");
print_r($jwt->check($token->get()) ? 'valid' : 'invalid');
print_r("\n");
print_r($jwt->decode($token->get()));
print_r("\n");

echo "\n\n###########################################\n\n";

$jwt = (new Jwt())
    // One day
    ->setTtl(1440)
    ->setRefreshTtl(1440 * 4)
    // Use with to specify the signer information
    ->with($passphrase)
    // Custom issuer
    ->setIssuer('https://itnovado.com');

$token = $jwt->encode([
    'sub' => '6caafa75-5bb1-454b-bacf-874b7e9158ea'
]);

print_r($token->get());
print_r("\n");
print_r($jwt->check($token->get()) ? 'valid' : 'invalid');
print_r("\n");
print_r($jwt->decode($token->get()));
print_r("\n");

echo "\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n\n";

$keys = [
    'private' => file_get_contents(__DIR__ . '/keys/private_key.pem'),
    'public' => file_get_contents(__DIR__ . '/keys/public_key.pem')
];

$jwt = (new Jwt())
    // One day
    ->setTtl(1440)
    // Use with to specify the signer information
    ->with($passphrase = null, $lago = 'RS512', $keys)
    // Custom issuer
    ->setIssuer('https://itnovado.com');

$token = $jwt->encode([
    'sub' => '6caafa75-5bb1-454b-bacf-874b7e9158ea'
]);

print_r($token->get());
print_r("\n");
print_r($jwt->check($token->get()) ? 'valid' : 'invalid');
print_r("\n");
print_r($jwt->decode($token->get()));
print_r("\n");
