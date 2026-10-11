package com.substring.auth.app.auth.payload;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @Size(max = 300, message = "Email must not exceed 300 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(max = 128, message = "Password must not exceed 128 characters")
        String password
) {}
