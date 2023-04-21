<?php

use Xaamin\Jwt\Token;
use Xaamin\Jwt\Native\Jwt;
use Xaamin\Jwt\Support\Str;
use PHPUnit\Framework\TestCase;
use Xaamin\Jwt\Constants\JwtTtl;

class JwtHmTest extends TestCase
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

    public function testCreateTokenSuccessfully(): void
    {
        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenHs256Successfully(): void
    {
        Jwt::setConfig(['algorithm' => 'HS256'] + $this->config);

        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenHs384Successfully(): void
    {
        Jwt::setConfig(['algorithm' => 'HS384'] + $this->config);

        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }

    public function testCreateTokenHs512Successfully(): void
    {
        Jwt::setConfig(['algorithm' => 'HS512'] + $this->config);

        $token = Jwt::encode(['sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190']);

        $this->assertInstanceOf(Token::class, $token);
    }
}
