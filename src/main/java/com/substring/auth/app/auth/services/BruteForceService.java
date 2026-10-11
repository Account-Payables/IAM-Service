package com.substring.auth.app.auth.services;

import com.substring.auth.app.auth.entities.User;
import jakarta.servlet.http.HttpServletRequest;

public interface BruteForceService {
    void recordFailedAttempt(User user, HttpServletRequest request);
    boolean isLocked(User user);
    void resetAttempts(User user);
}
