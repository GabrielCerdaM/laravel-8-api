<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Tymon\JWTAuth\Facades\JWTFactory;
use JWTAuth;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
	{
		$credentials = request(['email', 'password']);
        
		if (!$token = auth()->attempt($credentials)) {
			return response()->json(['error' => 'Unauthorized'], 401);
		}

		$user = auth()->user()->only(['id', 'email']);

        $payload = JWTFactory::sub($user['id'])
        ->user($user)
        ->make();

        $token = JWTAuth::encode($payload);

        return response()->json(
			[
				'token' => $this->respondWithToken($token->get())
			]
		);
	}

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}