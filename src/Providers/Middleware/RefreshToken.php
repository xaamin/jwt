<?php
namespace Xaamin\JWT\Providers\Middleware;

use Closure;
use Config;
use Xaamin\JWT\Exceptions\JWTException;
use Xaamin\JWT\Exceptions\TokenExpiredException;

class RefreshToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $jwt = $request->header('Authorization');
        $token = null;

        try {
            $this->jwt->checkOrFail($jwt);
        } catch (TokenExpiredException $e) {
            $token = $this->jwt->refresh($jwt);
        } catch (JWTException $e) {
            $data = [
                    'success' => false,
                    'message' => 'Unauthorized'
                ];

            return response()->json($data, 401);
        }

        $response = $next($request);

        // send the refreshed token back to the client
        $response->headers->set('Authorization', 'Bearer '.$token);
        return $response;
    }
}
