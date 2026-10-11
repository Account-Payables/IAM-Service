package com.substring.auth.app.core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.app.dtos.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final AuthCoreProperties properties;
    private final ObjectMapper objectMapper;

    /**
     * When behind a trusted reverse proxy (nginx/load balancer), set this to true via
     * auth.security.trust-proxy=true so the first IP in X-Forwarded-For is used.
     * Leave false (default) for direct deployments — uses getRemoteAddr() only,
     * which cannot be spoofed.
     */
    @Value("${auth.security.trust-proxy:false}")
    private boolean trustProxy;

    // key = "IP:path" → [requestCount, windowStartEpochSeconds]
    private final ConcurrentHashMap<String, long[]> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();
        String method = request.getMethod();

        if (!"POST".equalsIgnoreCase(method)) {
            filterChain.doFilter(request, response);
            return;
        }

        int limit = getLimit(uri);
        if (limit <= 0) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = resolveClientIp(request);
        String key = ip + ":" + uri;
        long nowSeconds = Instant.now().getEpochSecond();
        long windowSeconds = 60;

        buckets.compute(key, (k, v) -> {
            if (v == null || nowSeconds - v[1] >= windowSeconds) {
                return new long[]{1, nowSeconds};
            }
            v[0]++;
            return v;
        });

        long[] bucket = buckets.get(key);
        if (bucket[0] > limit) {
            long retryAfter = bucket[1] + windowSeconds - nowSeconds;
            response.setStatus(429);
            response.setContentType("application/json");
            response.setHeader("Retry-After", String.valueOf(Math.max(retryAfter, 1)));
            var error = ApiError.of(429, "Too Many Requests",
                    "Rate limit exceeded. Please try again later.", uri, true);
            response.getWriter().write(objectMapper.writeValueAsString(error));
            return;
        }

        filterChain.doFilter(request, response);
    }

    private int getLimit(String uri) {
        AuthCoreProperties.RateLimit rl = properties.getSecurity().getRateLimit();
        if (uri.endsWith("/login")) return rl.getLoginRpm();
        if (uri.endsWith("/register")) return rl.getRegisterRpm();
        if (uri.endsWith("/forgot-password")) return rl.getForgotPasswordRpm();
        if (uri.endsWith("/resend-verification")) return rl.getResendVerificationRpm();
        return 0;
    }

    /**
     * Resolves the real client IP.
     *
     * trustProxy=false (default, direct deploy): uses getRemoteAddr() — cannot be spoofed.
     * trustProxy=true (behind nginx/LB): trusts the FIRST IP in X-Forwarded-For, which
     *   nginx sets to the actual client IP. Do NOT enable unless nginx strips/overwrites
     *   X-Forwarded-For before forwarding — otherwise attackers can still inject fake IPs.
     */
    private String resolveClientIp(HttpServletRequest request) {
        if (trustProxy) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String first = xff.split(",")[0].trim();
                if (!first.isEmpty()) return first;
            }
        }
        return request.getRemoteAddr();
    }
}
