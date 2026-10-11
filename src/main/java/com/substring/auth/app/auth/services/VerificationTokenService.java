package com.substring.auth.app.auth.services;

public interface VerificationTokenService {
    void createAndSendEmailVerification(String userEmail);
    void verifyEmail(String rawToken);
    void createAndSendPasswordReset(String email);
    void resetPassword(String rawToken, String newPassword);
    void changePassword(String userId, String currentPassword, String newPassword);
}
