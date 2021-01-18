<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     *  This method allows users to issue accessToken if
     *  credentials are correct
     *
     *  @param Request $request
     *  @return string
     */
    public function login(Request $request) {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $request->email)->first();

        if(!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect'],
            ]);
        }

        return $user->createToken($user->name . '-device')->plainTextToken;
    }

    /**
     * Register user
     *
     * @param Request $request
     * @return JsonResponse
     * */
    public function register(Request $request) {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required|password_confirmation',
            'phone' => 'required|digits:10'
        ]);

        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'phone' => $request->phone
        ]);

        if($user->save()) {
            return response()->json($user); // 200, request success 404 => resource not found
        }

        return response()->json(['message' => 'Something went wrong'], 500); //500 - internal server error
    }

    /**
     * Logout user
     *
     * @param Request $request
     * @return JsonResponse
     * */
    public function logout(Request $request) {
        if(Auth::check()) {
            $user = $request->user();
            $user->tokens()->delete();
        }
        return response()->json(true, 200);
    }

}
