<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     *  This method allows users to issue accessToken if
     *  credentials are corrent
     *
     *  @param Requesrt $request
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
    public function register() {

    }

}
