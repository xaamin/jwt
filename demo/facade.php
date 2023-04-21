<?php

use Xaamin\Jwt\Native\Jwt;
use Xaamin\Jwt\Support\Str;

require __DIR__ . '/../vendor/autoload.php';

$config = require __DIR__ . '/../config/jwt.php';

$config['passprhase'] = Str::random(32);

Jwt::setConfig($config);

$token = Jwt::encode([
    'sub' => 'a7db35aa-4169-412d-b8c1-de6aef0c6cc6',
]);

print_r($token->get());
print_r("\n");
print_r(Jwt::check($token->get()) ? 'valid' : 'invalid');
print_r("\n");
print_r(Jwt::decode($token->get()));
print_r("\n");
