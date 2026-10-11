package com.substring.auth.app.extension;

import com.substring.auth.app.auth.entities.User;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

public interface PostLoginHook {
    Map<String, Object> onLoginSuccess(User user, HttpServletRequest request);
}
