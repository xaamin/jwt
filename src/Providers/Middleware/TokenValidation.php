<?php
namespace Xaamin\JWT\Providers\Middleware;

use Closure;
use Xaamin\JWT\JWT;
use Xaamin\JWT\Exceptions\JWTException;

class TokenValidation
{
    protected $jwt;

    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try {
            $this->jwt->checkOrFail($request->header('Authorization'));
        } catch (JWTException $e) {
            $data = [
                    'success' => false,
                    'message' => 'Unauthorized'
                ];

            return response()->json($data, 401);
        }

        return $next($request);
    }
}
