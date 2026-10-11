package com.substring.auth.app.auth.services;

import com.substring.auth.app.auth.entities.UserStatus;
import com.substring.auth.app.auth.payload.UserDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserService {
    UserDto createUser(UserDto userDto);
    UserDto getUserByEmail(String email);
    UserDto updateUser(UserDto userDto, String userId);
    void deleteUser(String userId);
    UserDto getUserById(String userId);
    Page<UserDto> getAllUsers(Pageable pageable);
    UserDto changeStatus(String userId, UserStatus newStatus);
    void assignRole(String userId, String roleId);
    void removeRole(String userId, String roleId);
}
