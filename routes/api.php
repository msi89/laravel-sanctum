<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:api')->get('/user', function (Request $request) {
//     return $request->user();
// });
Route::post('login', [AuthController::class, 'login']);
Route::get('user', [AuthController::class, 'user']);
Route::get('user/token', [AuthController::class, 'currentAccessToken']);
Route::get('user/tokens', [AuthController::class, 'accessTokens']);
Route::post('logout', [AuthController::class, 'logout']);
