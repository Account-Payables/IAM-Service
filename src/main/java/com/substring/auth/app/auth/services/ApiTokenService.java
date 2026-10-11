package com.substring.auth.app.auth.services;

import com.substring.auth.app.auth.entities.ApiToken;
import com.substring.auth.app.auth.entities.User;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ApiTokenService {
    ApiTokenCreateResult create(UUID userId, String name, List<String> scopes, Instant expiresAt);
    List<ApiToken> listByUser(UUID userId);
    void revoke(UUID tokenId, UUID requestingUserId);
    User authenticate(String rawToken);

    /** Authenticates and returns both the user and the token's declared scopes. */
    AuthResult authenticateWithScopes(String rawToken);

    record ApiTokenCreateResult(ApiToken token, String fullToken) {}
    record AuthResult(User user, List<String> scopes) {}
}
