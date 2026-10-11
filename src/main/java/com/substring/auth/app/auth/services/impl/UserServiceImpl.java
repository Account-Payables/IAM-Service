package com.substring.auth.app.auth.services.impl;

import com.substring.auth.app.auth.entities.*;
import com.substring.auth.app.auth.payload.UserDto;
import com.substring.auth.app.auth.repositories.RoleRepository;
import com.substring.auth.app.auth.repositories.UserRepository;
import com.substring.auth.app.auth.services.UserService;
import com.substring.auth.app.core.config.AuthCoreProperties;
import com.substring.auth.app.events.RoleAssignedEvent;
import com.substring.auth.app.events.RoleRemovedEvent;
import com.substring.auth.app.events.UserStatusChangedEvent;
import com.substring.auth.app.exceptions.ResourceNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthCoreProperties properties;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank())
            throw new IllegalArgumentException("Email is required");
        if (userRepository.existsByEmail(userDto.getEmail()))
            throw new IllegalArgumentException("An account with this email already exists");

        validatePasswordComplexity(userDto.getPassword());

        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);

        // Status: PENDING_VERIFICATION if email verification is required, else ACTIVE
        UserStatus initialStatus = properties.getEmailVerification().isRequired()
                ? UserStatus.PENDING_VERIFICATION
                : UserStatus.ACTIVE;
        user.setStatus(initialStatus);

        // Assign default role from config
        String defaultRoleName = properties.getDefaultRole();
        roleRepository.findByName(defaultRoleName).ifPresent(role -> user.getRoles().add(role));

        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uId = UUID.fromString(userId);
        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (userDto.getName() != null) user.setName(userDto.getName());
        if (userDto.getImage() != null) user.setImage(userDto.getImage());
        if (userDto.getProvider() != null) user.setProvider(userDto.getProvider());

        // Fix: always BCrypt encode when updating password
        if (userDto.getPassword() != null && !userDto.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        user.setUpdatedAt(Instant.now());
        return modelMapper.map(userRepository.save(user), UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uId = UUID.fromString(userId);
        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        // Soft delete
        user.setStatus(UserStatus.DELETED);
        user.setDeletedAt(Instant.now());
        userRepository.save(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public Page<UserDto> getAllUsers(Pageable pageable) {
        return userRepository.findByStatusNot(UserStatus.DELETED, pageable)
                .map(u -> modelMapper.map(u, UserDto.class));
    }

    @Override
    @Transactional
    public UserDto changeStatus(String userId, UserStatus newStatus) {
        UUID uId = UUID.fromString(userId);
        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        UserStatus previous = user.getStatus();
        user.setStatus(newStatus);
        if (newStatus == UserStatus.ACTIVE) {
            user.setLoginAttempts(0);
            user.setLockedUntil(null);
        }
        User saved = userRepository.save(user);

        eventPublisher.publishEvent(new UserStatusChangedEvent(
                this, uId, user.getEmail(), previous, newStatus, null
        ));

        return modelMapper.map(saved, UserDto.class);
    }

    @Override
    @Transactional
    public void assignRole(String userId, String roleId) {
        UUID uId = UUID.fromString(userId);
        UUID rId = UUID.fromString(roleId);

        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        Role role = roleRepository.findById(rId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        user.getRoles().add(role);
        userRepository.save(user);

        eventPublisher.publishEvent(new RoleAssignedEvent(
                this, uId, user.getEmail(), role.getName(), null, null
        ));
    }

    private void validatePasswordComplexity(String password) {
        if (password == null) return;
        AuthCoreProperties.Password cfg = properties.getPassword();
        int min = cfg.getMinLength();
        int max = cfg.getMaxLength();
        if (password.length() < min || password.length() > max)
            throw new IllegalArgumentException(
                    "Password must be between " + min + " and " + max + " characters");
        if (cfg.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase))
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        if (cfg.isRequireDigit() && password.chars().noneMatch(Character::isDigit))
            throw new IllegalArgumentException("Password must contain at least one digit");
        if (cfg.isRequireSpecialChar() && password.chars().noneMatch(c -> "!@#$%^&*()_+-=[]{}|;':\",./<>?".indexOf(c) >= 0))
            throw new IllegalArgumentException("Password must contain at least one special character");
    }

    @Override
    @Transactional
    public void removeRole(String userId, String roleId) {
        UUID uId = UUID.fromString(userId);
        UUID rId = UUID.fromString(roleId);

        User user = userRepository.findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        Role role = roleRepository.findById(rId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        user.getRoles().removeIf(r -> r.getId().equals(rId));
        userRepository.save(user);

        eventPublisher.publishEvent(new RoleRemovedEvent(
                this, uId, user.getEmail(), role.getName(), null, null
        ));
    }
}
