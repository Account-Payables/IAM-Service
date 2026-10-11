package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.Role;
import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.extension.TokenClaimsProvider;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
@Getter
@Setter
public class JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;
    private final TokenClaimsProvider tokenClaimsProvider;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer,
            TokenClaimsProvider tokenClaimsProvider) {
        if (secret == null || secret.length() < 64)
            throw new IllegalArgumentException("JWT secret must be at least 64 characters");
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
        this.tokenClaimsProvider = tokenClaimsProvider;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() :
                user.getRoles().stream().map(Role::getName).toList();
        List<String> permissions = user.getPermissionNames();

        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("roles", roles);
        claims.put("permissions", permissions);
        claims.put("typ", "access");
        claims.put("token_source", "JWT");

        // Merge project-specific claims from extension hook
        Map<String, Object> extraClaims = tokenClaimsProvider.getAdditionalClaims(user);
        claims.putAll(extraClaims);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds)))
                .claims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    public boolean isAccessToken(String token) {
        return "access".equals(parse(token).getPayload().get("typ"));
    }

    public boolean isRefreshToken(String token) {
        return "refresh".equals(parse(token).getPayload().get("typ"));
    }

    public UUID getUserId(String token) {
        return UUID.fromString(parse(token).getPayload().getSubject());
    }

    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        return (List<String>) parse(token).getPayload().get("roles");
    }

    @SuppressWarnings("unchecked")
    public List<String> getPermissions(String token) {
        return (List<String>) parse(token).getPayload().get("permissions");
    }

    public String getEmail(String token) {
        return (String) parse(token).getPayload().get("email");
    }

    public String getTokenSource(String token) {
        Object source = parse(token).getPayload().get("token_source");
        return source != null ? source.toString() : "JWT";
    }
}
