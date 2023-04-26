<?php

use Xaamin\Jwt\Token;
use Xaamin\Jwt\Native\Jwt;
use Xaamin\Jwt\Support\Str;
use PHPUnit\Framework\TestCase;
use Xaamin\Jwt\Constants\JwtOptions;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenExpiredException;
use Xaamin\Jwt\Exceptions\TokenInvalidException;
use Xaamin\Jwt\Exceptions\TokenBeforeValidException;
use Xaamin\Jwt\Exceptions\TokenInvalidSignatureException;

class JwtTest extends TestCase
{
    /** @var array<string,mixed> */
    protected $config = [];

    public function setUp(): void
    {
        $config = require __DIR__ . '/../config/jwt.php';

        $config['passphrase'] = Str::random(32);

        Jwt::setConfig($config);
        Jwt::setLeeway(JwtOptions::LEEWAY);

        $this->config = $config;
    }

    public function testUrlSafeCharacters(): void
    {
        $encoded = Jwt::encode([
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'f?'
        ]);

        $this->assertEquals('f?', Jwt::decode($encoded)->m); // @phpstan-ignore-line
    }

    public function testValidToken(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc'
        ];
        $encoded = Jwt::encode($payload);
        $decoded = Jwt::decode($encoded);

        $this->assertInstanceOf(Token::class, $encoded);
        $this->assertInstanceOf(Token::class, $decoded);

        $this->assertSame($decoded->sub, '543f7a76-d7ff-4f23-80d3-d719ff4fe190'); // @phpstan-ignore-line
        $this->assertSame($decoded->m, 'abc'); // @phpstan-ignore-line
    }

    public function testValidTokenWithLeeway(): void
    {
        Jwt::setLeeway(60);

        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'exp' => time() - 20
        ];

        $encoded = Jwt::encode($payload);
        $decoded = Jwt::decode($encoded);

        $this->assertInstanceOf(Token::class, $encoded);
        $this->assertInstanceOf(Token::class, $decoded);

        $this->assertSame($decoded->sub, '543f7a76-d7ff-4f23-80d3-d719ff4fe190'); // @phpstan-ignore-line
        $this->assertSame($decoded->m, 'abc'); // @phpstan-ignore-line
    }

    public function testValidTokenWithNbf(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'exp' => time() + 20, // Time in the future
            'nbf' => time() - 20
        ];

        $encoded = Jwt::encode($payload);
        $decoded = Jwt::decode($encoded);

        $this->assertSame($decoded->sub, '543f7a76-d7ff-4f23-80d3-d719ff4fe190'); // @phpstan-ignore-line
        $this->assertSame($decoded->m, 'abc'); // @phpstan-ignore-line
    }

    public function testValidTokenWithNbfLeeway(): void
    {
        Jwt::setLeeway(60);

        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'nbf'     => time() + 20, // Not before in near (leeway) future
        ];
        $encoded = Jwt::encode($payload);
        $decoded = Jwt::decode($encoded);

        $this->assertSame($decoded->sub, '543f7a76-d7ff-4f23-80d3-d719ff4fe190'); // @phpstan-ignore-line
        $this->assertSame($decoded->m, 'abc'); // @phpstan-ignore-line
    }

    public function testValidTokenWithIatLeeway(): void
    {
        Jwt::setLeeway(60);

        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'iat' => time() + 20, // Issued in near (leeway) future
        ];
        $encoded = Jwt::encode($payload);
        $decoded = Jwt::decode($encoded);

        $this->assertSame($decoded->sub, '543f7a76-d7ff-4f23-80d3-d719ff4fe190'); // @phpstan-ignore-line
        $this->assertSame($decoded->m, 'abc'); // @phpstan-ignore-line
    }

    public function testAdditionalClaims(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $encoded = Jwt::encode($payload);

        $this->assertEquals(Jwt::decode($encoded)->m, 'abc'); // @phpstan-ignore-line
    }


    public function testMalformedJsonThrowsException(): void
    {
        $this->expectException(TokenInvalidException::class);

        Jwt::decode('This is not valid json web token string');
    }

    public function testExpiredToken(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'exp' => time() - 20 // Time in the past
        ];

        $encoded = Jwt::encode($payload);

        $this->expectException(TokenExpiredException::class);

        Jwt::checkOrFail($encoded);
    }

    public function testBeforeValidTokenWithNbf(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'nbf' => time() + 20, // Time in the future
        ];

        $encoded = Jwt::encode($payload);

        $this->expectException(TokenBeforeValidException::class);

        Jwt::checkOrFail($encoded);
    }

    public function testBeforeValidTokenWithIat(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'iat' => time() + 20, // Time in the future
        ];

        $encoded = Jwt::encode($payload);

        $this->expectException(TokenBeforeValidException::class);

        Jwt::checkOrFail($encoded);
    }

    public function testInvalidTokenCreationWithNbfLeeway(): void
    {
        Jwt::setLeeway(60);

        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'nbf' => time() + 65,  // Not before too far in future
        ];


        $encoded = Jwt::encode($payload);

        $this->expectException(TokenBeforeValidException::class);

        Jwt::checkOrFail($encoded);
    }

    public function testInvalidTokenWithIatLeeway(): void
    {
        Jwt::setLeeway(60);

        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
            'iat' => time() + 65, // Issued too far in future
        ];

        $encoded = Jwt::encode($payload);

        $this->expectException(TokenBeforeValidException::class);

        Jwt::checkOrFail($encoded);
    }

    public function testInvalidToken(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc'
        ];

        $encoded = Jwt::encode($payload);

        $config = $this->config;

        $config['passphrase'] = Str::random(32);

        Jwt::setConfig($config);

        $this->expectException(TokenInvalidSignatureException::class);

        Jwt::decode($encoded);
    }

    public function testNullPassphraseFails(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $config = $this->config;

        $config['passphrase'] = null;

        Jwt::setConfig($config);

        $this->expectException(InvalidArgumentException::class);

        Jwt::encode($payload);
    }

    public function testEmptyPassphraseFails(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $config = $this->config;

        $config['passphrase'] = null;

        Jwt::setConfig($config);

        $this->expectException(InvalidArgumentException::class);

        Jwt::encode($payload);
    }

    public function testNoneAlgorithm(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $config = $this->config;

        $config['algorithm'] = 'none';

        Jwt::setConfig($config);

        $this->expectException(JwtException::class);

        Jwt::encode($payload);
    }

    public function testIncorrectAlgorithm(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $config = $this->config;

        $config['algorithm'] = 'RS256';

        Jwt::setConfig($config);

        $this->expectException(InvalidArgumentException::class);

        Jwt::encode($payload);
    }

    public function testEmptyAlgorithm(): void
    {
        $payload = [
            'sub' => '543f7a76-d7ff-4f23-80d3-d719ff4fe190',
            'm' => 'abc',
        ];

        $config = $this->config;

        $config['algorithm'] = '';

        Jwt::setConfig($config);

        $this->expectException(JwtException::class);

        Jwt::encode($payload);
    }

    public function testInvalidSegmentCount(): void
    {
        $this->expectException(TokenInvalidException::class);

        Jwt::decode('brokenheader.brokenbody');
    }

    public function testInvalidSignatureEncoding(): void
    {
        $token = 'eyJ0eXAiOiJKd3QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1NDNmN2E3Ni1kN2ZmLTRmMjMtODBkMy1kNzE5ZmY0ZmUxOTAiLCJtIjoiYWJjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdCIsImlhdCI6MTY4MjAzNDY4MywiZXhwIjoxNjgyMDM4MjgzLCJuYmYiOjE2ODIwMzQ2ODMsImp0aSI6ImRkMmJhMWQ3ODFkMTE3NWZiNWZjYjk5ZjE5YjAxZmE5In0.LOfA6fAiYY7KU89DBHizNNFAE60Bs3yMSAKkF6cjxIDbL8ug0r1NiNMFZTLhBggHMq3usC_GPNqgQGAGiTgGGA';

        $this->expectException(TokenInvalidSignatureException::class);

        Jwt::decode($token);
    }
}
