# Laravel Sanctum

## Installation

```bash
composer require laravel/sanctum
```

## Publish

```bash
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
```

## Create sanctum table in database

```bash
php artisan migrate
```

Sanctum to authenticate an SPA, you should add Sanctum's middleware to your `api` middleware group within your `app/Http/Kernel.php`

```php
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;

'api' => [
    EnsureFrontendRequestsAreStateful::class,
    'throttle:60,1',
    \Illuminate\Routing\Middleware\SubstituteBindings::class,
],
```

## How to use Sanctum

```php
# app/Models/User.php

use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;
}
```

```php
# app/Controllers/Api/AuthContoller.php


use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
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
        $user['access_token'] = $user->createToken($request->device_name)->plainTextToken;

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

```

```php
# routes/api.php

Route::post('login', [AuthController::class, 'login']);
Route::get('user', [AuthController::class, 'user']);
Route::get('user/token', [AuthController::class, 'currentAccessToken']);
Route::get('user/tokens', [AuthController::class, 'accessTokens']);
Route::post('logout', [AuthController::class, 'logout']);
```

## Issuing API Tokens

Sanctum allows you to issue API tokens / personal access tokens that may be used to authenticate API requests. When making requests using API tokens, the token should be included in the `Authorization` header as a `Bearer` token.

```javascript
const access_token = "..your token..";
axios.get("https://localhost:8000/api/user", {
    headers: {
        Authorization: `Bearer ${access_token}`,
    },
});
```

## Testing

While testing, the `Sanctum::actingAs` method may be used to authenticate a user and specify which abilities are granted to their token:

```php

use App\Models\User;
use Laravel\Sanctum\Sanctum;

public function test_task_list_can_be_retrieved()
{
    Sanctum::actingAs(
        User::factory()->create(),
        ['view-tasks']
    );

    $response = $this->get('/api/task');

    $response->assertOk();
}
```
