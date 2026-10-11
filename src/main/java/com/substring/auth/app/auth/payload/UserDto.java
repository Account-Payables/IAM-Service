package com.substring.auth.app.auth.payload;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.substring.auth.app.auth.entities.Provider;
import com.substring.auth.app.auth.entities.UserStatus;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private UUID id;
    private String email;
    private String name;

    @JsonIgnore
    private String password;

    private String image;
    private UserStatus status;
    private boolean emailVerified;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant lastLoginAt;
    private Provider provider;

    @Builder.Default
    private Set<RoleDto> roles = new HashSet<>();
}
