package com.substring.auth.app.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.app.core.config.ApiTokenAuthFilter;
import com.substring.auth.app.core.config.RateLimitFilter;
import com.substring.auth.app.core.config.SecurityHeadersFilter;
import com.substring.auth.app.dtos.ApiError;
import io.jsonwebtoken.lang.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ApiTokenAuthFilter apiTokenAuthFilter;
    private final RateLimitFilter rateLimitFilter;
    private final SecurityHeadersFilter securityHeadersFilter;
    private final AuthenticationSuccessHandler successHandler;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          ApiTokenAuthFilter apiTokenAuthFilter,
                          RateLimitFilter rateLimitFilter,
                          SecurityHeadersFilter securityHeadersFilter,
                          AuthenticationSuccessHandler successHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.apiTokenAuthFilter = apiTokenAuthFilter;
        this.rateLimitFilter = rateLimitFilter;
        this.securityHeadersFilter = securityHeadersFilter;
        this.successHandler = successHandler;
    }

    private static final String[] PUBLIC_URLS = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/verify-email",
            "/api/v1/auth/resend-verification",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/v3/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_URLS).permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2.successHandler(successHandler))
            .logout(AbstractHttpConfigurer::disable)
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint((request, response, e) -> {
                        response.setStatus(401);
                        response.setContentType("application/json");
                        String message = e.getMessage();
                        String error = (String) request.getAttribute("error");
                        if (error != null) message = error;
                        var apiError = ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized",
                                message, request.getRequestURI(), true);
                        response.getWriter().write(new ObjectMapper().writeValueAsString(apiError));
                    })
                    .accessDeniedHandler((request, response, e) -> {
                        response.setStatus(403);
                        response.setContentType("application/json");
                        var apiError = ApiError.of(HttpStatus.FORBIDDEN.value(), "Forbidden",
                                e.getMessage(), request.getRequestURI(), true);
                        response.getWriter().write(new ObjectMapper().writeValueAsString(apiError));
                    }))
            // Filter chain order: SecurityHeaders → RateLimit → ApiToken → JWT → SpringSecurity
            .addFilterBefore(securityHeadersFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(apiTokenAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(@Value("${app.cors.front-end-url}") String corsUrls) {
        String[] urls = corsUrls.trim().split(",");
        var config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(urls));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"));
        config.setAllowedHeaders(List.of(
                "Authorization", "Content-Type", "X-API-Key",
                "X-Refresh-Token", "Idempotency-Key", "traceparent"));
        config.setAllowCredentials(true);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
