package com.substring.auth.app.core.context;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class AuthContext {

    private AuthContext() {}

    public static boolean isAuthenticated() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    public static String getCurrentUserEmail() {
        Authentication auth = getAuthentication();
        // Principal is the email (set in JwtAuthenticationFilter)
        return auth.getName();
    }

    public static UUID getCurrentUserId() {
        Authentication auth = getAuthentication();
        Object details = auth.getDetails();
        if (details instanceof Map<?,?> map && map.get("userId") != null) {
            return UUID.fromString(map.get("userId").toString());
        }
        // Fallback: parse from credentials
        Object creds = auth.getCredentials();
        if (creds instanceof String userId) {
            return UUID.fromString(userId);
        }
        throw new IllegalStateException("Cannot extract userId from SecurityContext");
    }

    public static boolean hasPermission(String permission) {
        Authentication auth = getAuthentication();
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();

        // Check for wildcard
        boolean hasWildcard = authorities.stream()
                .anyMatch(a -> "PERMISSION_*".equals(a.getAuthority()));
        if (hasWildcard) return true;

        return authorities.stream()
                .anyMatch(a -> ("PERMISSION_" + permission).equals(a.getAuthority()));
    }

    public static boolean hasRole(String role) {
        Authentication auth = getAuthentication();
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(role) || a.getAuthority().equals("ROLE_" + role));
    }

    public static String getCurrentOrgId() {
        Authentication auth = getAuthentication();
        Object details = auth.getDetails();
        if (details instanceof Map<?,?> map) {
            Object orgId = map.get("orgId");
            return orgId != null ? orgId.toString() : null;
        }
        return null;
    }

    public static String getTokenType() {
        Authentication auth = getAuthentication();
        Object details = auth.getDetails();
        if (details instanceof Map<?,?> map) {
            Object tokenSource = map.get("tokenSource");
            return tokenSource != null ? tokenSource.toString() : "JWT";
        }
        return "JWT";
    }

    private static Authentication getAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user in SecurityContext");
        }
        return auth;
    }
}
