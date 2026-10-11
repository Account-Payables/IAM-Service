package com.substring.auth.app.extension;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.shared.exceptions.LoginBlockedException;
import jakarta.servlet.http.HttpServletRequest;

public interface LoginValidator {
    void validate(User user, HttpServletRequest request) throws LoginBlockedException;
}
