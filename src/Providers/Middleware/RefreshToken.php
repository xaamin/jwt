<?php
namespace Xaamin\JWT\Providers\Middleware;

use Closure;
use Config;
use Xaamin\JWT\JWT;
use Xaamin\JWT\Exceptions\JWTException;
use Xaamin\JWT\Exceptions\TokenExpiredException;

class RefreshToken
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
        $jwt = $request->header('Authorization');
        $token = '';
        $error = '';
        $code = 50;

        try {
            $this->jwt->checkOrFail($jwt);
        } catch (TokenExpiredException $e) {
            try {
                $this->jwt->setTTL(Config::get('jwt.long_ttl'), Config::get('jwt.ttl'));

                $token = $this->jwt->refresh($jwt)->get();
                // Set token for current request to pass jwt.auth middleware
                $request->headers->set('Authorization', 'Bearer ' . $token);
            } catch (TokenExpiredException $e) {
                $error = $e->getMessage();
                $code = 51;
            } catch (JWTException $e) {
                $error = $e->getMessage();
            }
        } catch (JWTException $e) {
            $error = $e->getMessage();
        }

        if ($error) {
            $data = [
                'success' => false,
                'message' => $error,
                'error' => $code
            ];

            return response()->json($data, 401);
        }

        $response = $next($request);

        // Send the refreshed token back to the client
        $response->headers->set('Authorization', 'Bearer ' . $token);
        return $response;
    }
}
