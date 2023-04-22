<?php

use Xaamin\Jwt\Token;
use Xaamin\Jwt\Native\Jwt;
use Xaamin\Jwt\Support\Str;
use PHPUnit\Framework\TestCase;
use Xaamin\Jwt\Constants\JwtTtl;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenExpiredException;
use Xaamin\Jwt\Exceptions\TokenInvalidException;
use Xaamin\Jwt\Exceptions\TokenBeforeValidException;
use Xaamin\Jwt\Exceptions\TokenInvalidSignatureException;

class JwtRefreshTest extends TestCase
{
    /** @var array<string,mixed> */
    protected $config = [];

    public function setUp(): void
    {
        $config = require __DIR__ . '/../config/jwt.php';

        $config['passphrase'] = Str::random(32);

        Jwt::setConfig($config);
        Jwt::setLeeway(JwtTtl::LEEWAY);

        $this->config = $config;
    }

    public function testRefreshTokenSuccessfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);

        $refreshed = Jwt::refresh($token);

        $this->assertInstanceOf(Token::class, $refreshed);
    }

    public function testRefreshExpiredTokenSuccessfully(): void
    {
        $token = Jwt::encode([
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'exp' => time() - 10 // Time in the past
        ]);

        $this->assertInstanceOf(Token::class, $token);

        $refreshed = Jwt::refresh($token);

        $this->assertInstanceOf(Token::class, $refreshed);
    }

    public function testRefreshTokenAfterGracePeriodFails(): void
    {
        Jwt::setRefreshTtl(1);

        $token = Jwt::encode([
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'iat' => time() - 70 // Time in the past
        ]);

        $this->assertInstanceOf(Token::class, $token);

        $this->expectException(TokenExpiredException::class);

        Jwt::refresh($token);
    }
}
