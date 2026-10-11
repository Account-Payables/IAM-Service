package com.substring.auth.app.auth.controllers;

import com.substring.auth.app.auth.entities.ApiToken;
import com.substring.auth.app.auth.services.ApiTokenService;
import com.substring.auth.app.core.context.AuthContext;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/api-tokens")
@RequiredArgsConstructor
public class ApiTokenController {

    private final ApiTokenService apiTokenService;

    @PostMapping
    public ResponseEntity<Map<String, Object>> createToken(@Valid @RequestBody CreateTokenRequest request) {
        UUID userId = AuthContext.getCurrentUserId();
        var result = apiTokenService.create(userId, request.getName(), request.getScopes(), request.getExpiresAt());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "id", result.token().getId(),
                "name", result.token().getName(),
                "tokenPrefix", result.token().getTokenPrefix(),
                "fullToken", result.fullToken(),
                "scopes", result.token().getScopes() != null ? result.token().getScopes() : List.of(),
                "expiresAt", result.token().getExpiresAt() != null ? result.token().getExpiresAt() : "never",
                "createdAt", result.token().getCreatedAt(),
                "warning", "Save this token now. It will never be shown again."
        ));
    }

    @GetMapping
    public ResponseEntity<List<ApiToken>> listTokens() {
        UUID userId = AuthContext.getCurrentUserId();
        List<ApiToken> tokens = apiTokenService.listByUser(userId);
        return ResponseEntity.ok(tokens);
    }

    @DeleteMapping("/{tokenId}")
    public ResponseEntity<Void> revokeToken(@PathVariable UUID tokenId) {
        UUID userId = AuthContext.getCurrentUserId();
        apiTokenService.revoke(tokenId, userId);
        return ResponseEntity.noContent().build();
    }

    @Getter @Setter
    public static class CreateTokenRequest {
        @NotBlank
        @Size(max = 200)
        private String name;
        private List<String> scopes;
        private Instant expiresAt;
    }
}
