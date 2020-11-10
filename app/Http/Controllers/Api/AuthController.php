<?php

namespace App\Http\Controllers\Api;

use Carbon\Carbon;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum')->except('login');
    }
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
            'device_name' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
        $token = $user->createToken($request->device_name);

        $user['access_token'] = $token->plainTextToken;
        $user['expire_at'] = Carbon::parse($token->accessToken->created_at)->addMonth(12);


        return response()->json($user);
    }

    public function user()
    {
        return response()->json(auth()->user());
    }

    public function currentAccessToken()
    {
        return response()->json(auth()->user()->currentAccessToken());
    }
    public function accessTokens()
    {
        return response()->json(auth()->user()->tokens);
    }

    public function logout()
    {
        // Revoke a specific token...
        // auth()->user()->tokens()->where('id', $id)->delete();
        if (request('for_all_device')) {
            auth()->user()->tokens()->delete();
        } else {
            request()->user()->currentAccessToken()->delete();
        }
        return response()->json('', 204);
    }
}
