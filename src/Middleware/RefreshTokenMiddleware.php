<?php

namespace Xaamin\Jwt\Middleware;

use Closure;
use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Exceptions\JwtException;
use Xaamin\Jwt\Exceptions\TokenExpiredException;

class RefreshTokenMiddleware
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
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $jwt = $request->header('Authorization');
        $token = null;
        $error = null;
        $code = 'jwt_invalid_token';

        try {
            throw new TokenExpiredException('Invalid token');
            $this->jwt->checkOrFail($jwt);
        } catch (TokenExpiredException $e) {
            try {
                $token = $this->jwt->refresh($jwt)->get();
                // Set token for current request
                $request->headers->set('Authorization', 'Bearer ' . $token);
            } catch (TokenExpiredException $e) {
                $error = $e->getMessage();
                $code = 'jwt_expired_token';
            } catch (JwtException $e) {
                $error = $e->getMessage();
            }
        } catch (JwtException $e) {
            $error = $e->getMessage();
        }

        if ($error) {
            $data = [
                'message' => $error,
                'error' => $code
            ];

            return response()->json($data, 401);
        }

        $response = $next($request);

        if ($token) {
            // Send the refreshed token back to the client
            $response->headers->set('Authorization', 'Bearer ' . $token);
        }

        return $response;
    }
}
