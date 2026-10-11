package com.substring.auth.app.auth.controllers;

import com.substring.auth.app.auth.payload.UserDto;
import com.substring.auth.app.auth.services.UserService;
import com.substring.auth.app.core.context.AuthContext;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Page<UserDto>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        size = Math.min(size, 100); // cap at 100
        return ResponseEntity.ok(userService.getAllUsers(PageRequest.of(page, size, Sort.by("createdAt").descending())));
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getMe() {
        return ResponseEntity.ok(userService.getUserById(AuthContext.getCurrentUserId().toString()));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID userId) {
        enforceOwnerOrAdmin(userId);
        return ResponseEntity.ok(userService.getUserById(userId.toString()));
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(@RequestBody UserDto userDto, @PathVariable UUID userId) {
        enforceOwnerOrAdmin(userId);
        return ResponseEntity.ok(userService.updateUser(userDto, userId.toString()));
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID userId) {
        userService.deleteUser(userId.toString());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{userId}/status")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<UserDto> changeUserStatus(@PathVariable UUID userId,
                                                     @RequestBody StatusChangeRequest request) {
        return ResponseEntity.ok(userService.changeStatus(userId.toString(), request.getStatus()));
    }

    @PostMapping("/{userId}/roles")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> assignRole(@PathVariable UUID userId, @RequestBody RoleAssignRequest request) {
        userService.assignRole(userId.toString(), request.getRoleId().toString());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> removeRole(@PathVariable UUID userId, @PathVariable UUID roleId) {
        userService.removeRole(userId.toString(), roleId.toString());
        return ResponseEntity.noContent().build();
    }

    // IDOR protection: only the owner or admin can access
    private void enforceOwnerOrAdmin(UUID targetUserId) {
        UUID currentUserId = AuthContext.getCurrentUserId();
        boolean isAdmin = AuthContext.hasRole("SUPER_ADMIN");
        if (!isAdmin && !currentUserId.equals(targetUserId)) {
            throw new AccessDeniedException("You cannot access another user's data");
        }
    }

    // Inner request classes
    @Getter @Setter
    public static class StatusChangeRequest {
        private com.substring.auth.app.auth.entities.UserStatus status;
    }

    @Getter @Setter
    public static class RoleAssignRequest {
        private UUID roleId;
    }
}
