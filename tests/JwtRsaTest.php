<?php

use Xaamin\Jwt\Token;
use Xaamin\Jwt\Native\Jwt;
use PHPUnit\Framework\TestCase;
use Xaamin\Jwt\Constants\JwtTtl;

class JwtRsaTest extends TestCase
{
    /** @var array<string,mixed> */
    protected $config = [];

    public function setUp(): void
    {
        $config = require __DIR__ . '/../config/jwt.php';

        $keys = [
            'private' => __DIR__ . '/../demo/keys/private_key.pem',
            'public' => __DIR__ . '/../demo/keys/public_key.pem'
        ];

        $config['algorithm'] = 'RS256';
        $config['keys'] = $keys;

        Jwt::setConfig($config);
        Jwt::setLeeway(JwtTtl::LEEWAY);

        $this->config = $config;
    }

    public function testCreateTokenWithRsaSuccessfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenWithRsa256Successfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenWithRsa384Successfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenWithRsa512Successfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }
}
