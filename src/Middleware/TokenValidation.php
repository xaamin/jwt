<?php

namespace Xaamin\Jwt\Middleware;

use Closure;
use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenExpiredException;

class TokenValidation
{
    /**
     * Jwt instance
     *
     * @var Jwt
     */
    protected $jwt;

    public function __construct(Jwt $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try {
            $this->jwt->checkOrFail($request->header('Authorization'));
        } catch (TokenExpiredException $e) {
            $data = [
                'message' => $e->getMessage(),
                'code' => 'jwt_expired_token'
            ];

            return response()->json($data, 401);
        } catch (JwtException $e) {
            $data = [
                'message' => $e->getMessage(),
                'code' => 'jwt_invalid_token'
            ];

            return response()->json($data, 401);
        }

        return $next($request);
    }
}
