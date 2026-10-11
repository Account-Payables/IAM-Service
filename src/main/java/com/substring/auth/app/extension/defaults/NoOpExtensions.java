package com.substring.auth.app.extension.defaults;

import com.substring.auth.app.extension.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
public class NoOpExtensions {

    @Bean
    @ConditionalOnMissingBean(LoginValidator.class)
    public LoginValidator defaultLoginValidator() {
        return (user, request) -> {};
    }

    @Bean
    @ConditionalOnMissingBean(PostLoginHook.class)
    public PostLoginHook defaultPostLoginHook() {
        return (user, request) -> Map.of();
    }

    @Bean
    @ConditionalOnMissingBean(TokenClaimsProvider.class)
    public TokenClaimsProvider defaultTokenClaimsProvider() {
        return user -> Map.of();
    }

    @Bean
    @ConditionalOnMissingBean(UserEnrichmentHook.class)
    public UserEnrichmentHook defaultUserEnrichmentHook() {
        return user -> Map.of();
    }

    @Bean
    @ConditionalOnMissingBean(RegistrationHook.class)
    public RegistrationHook defaultRegistrationHook() {
        return (user, source) -> {};
    }
}
