package com.substring.auth.app.extension;

import com.substring.auth.app.auth.entities.User;

import java.util.Map;

public interface TokenClaimsProvider {
    Map<String, Object> getAdditionalClaims(User user);
}
