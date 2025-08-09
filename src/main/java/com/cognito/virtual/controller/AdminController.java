package com.cognito.virtual.controller;

import com.cognito.virtual.dto.*;
import com.cognito.virtual.entity.*;
import com.cognito.virtual.mapper.FunctionsMapper;
import com.cognito.virtual.mapper.RoleDTO;
import com.cognito.virtual.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final FunctionsMapper utilsMapper;

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserInfo>>> getAllUsers() {
        List<UserEntity> users = userRepository.findAll();

        List<UserInfo> userInfos = users.stream()
                .map(this::buildUserInfo)
                .collect(toList());

        return ResponseEntity.ok(
                ApiResponse.success("Usuarios obtenidos exitosamente", userInfos));
    }

    @PostMapping("/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> assignRoleToUser(
            @PathVariable Long userId,
            @PathVariable Long roleId) {

        Optional<UserEntity> userOpt = userRepository.findById(userId);
        Optional<RoleEntity> roleOpt = roleRepository.findById(roleId);

        if (userOpt.isEmpty() || roleOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Usuario o rol no encontrado"));
        }

        if (!userOpt.get().getRoles().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("El usuario ya tiene asignado un rol"));
        }

        UserEntity user = userOpt.get();
        RoleEntity role = roleOpt.get();

        user.getRoles().add(role);
        userRepository.save(user);

        return ResponseEntity.ok(
                ApiResponse.success("Rol asignado exitosamente"));
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> removeRoleFromUser(
            @PathVariable Long userId,
            @PathVariable Long roleId) {

        Optional<UserEntity> userOpt = userRepository.findById(userId);
        Optional<RoleEntity> roleOpt = roleRepository.findById(roleId);

        if (userOpt.isEmpty() || roleOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Usuario o rol no encontrado"));
        }

        UserEntity user = userOpt.get();
        RoleEntity role = roleOpt.get();

        user.getRoles().remove(role);
        userRepository.save(user);

        return ResponseEntity.ok(
                ApiResponse.success("Rol removido exitosamente"));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<RoleDTO>>> getAllRoles() {
        List<RoleDTO> roles = roleRepository.findAll().stream()
                .map(utilsMapper::mapToDTO)
                .toList();
        return ResponseEntity.ok(
                ApiResponse.success("Roles obtenidos exitosamente", roles));
    }

    @PostMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<RoleEntity>> createRole(
            @RequestBody RoleEntity role) {

        if (roleRepository.existsByName(role.getName())) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("El rol ya existe"));
        }

        RoleEntity savedRole = roleRepository.save(role);
        return ResponseEntity.ok(
                ApiResponse.success("Rol creado exitosamente", savedRole));
    }

    private UserInfo buildUserInfo(UserEntity user) {
        Set<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toSet());

        Set<String> permissions = user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(PermissionEntity::getName)
                .collect(Collectors.toSet());

        return UserInfo.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .emailVerified(user.getEmailVerified())
                .phoneVerified(user.getPhoneVerified())
                .roles(roles)
                .permissions(permissions)
                .build();
    }
}