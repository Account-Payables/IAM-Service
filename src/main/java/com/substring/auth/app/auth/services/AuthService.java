package com.substring.auth.app.auth.services;

import com.substring.auth.app.auth.payload.TokenResponse;
import com.substring.auth.app.auth.payload.UserDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
    TokenResponse login(String email, String password, HttpServletRequest request, HttpServletResponse response);
    TokenResponse refreshTokens(String refreshToken, HttpServletRequest request, HttpServletResponse response);
    void logout(String refreshToken, HttpServletResponse response);
    void logoutAll(String currentRefreshToken, HttpServletResponse response);
}
