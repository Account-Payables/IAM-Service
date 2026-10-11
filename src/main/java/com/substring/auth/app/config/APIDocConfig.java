package com.substring.auth.app.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "IAM Service — Auth Backend",
                description = "Generic authentication and authorization service that can be plugged into any application.",
                version = "1.0",
                summary = "Provides JWT auth, OAuth2 social login, role/permission management, API tokens, brute-force protection, and more."



        )
        ,
        security = {
                @SecurityRequirement(
                        name="bearerAuth"
                )
        }


)

@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer", //Authorization: Bearer htokenaswga,
        bearerFormat = "JWT"

)
public class APIDocConfig {


}
