package com.cognito.virtual.config;

import com.cognito.virtual.entity.*;
import com.cognito.virtual.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

@Component
@RequiredArgsConstructor
public class DataInitializer implements org.springframework.boot.CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;

    @Override
    public void run(String... args) throws Exception {
        initializePermissions();
        initializeRoles();
        initializeAdminUser();
    }

    private void initializePermissions() {
        if (permissionRepository.count() == 0) {
            String[] permissions = {"READ", "WRITE", "DELETE", "ADMIN"};

            for (String permissionName : permissions) {
                PermissionEntity permission = PermissionEntity.builder()
                        .name(permissionName)
                        .description("Permiso para " + permissionName.toLowerCase())
                        .build();
                permissionRepository.save(permission);
            }

            log.info("Permisos iniciales creados");
        }
    }

    private void initializeRoles() {
        if (roleRepository.count() == 0) {
            // Crear rol USER
            PermissionEntity readPermission = permissionRepository.findByName("READ").get();

            RoleEntity userRole = RoleEntity.builder()
                    .name("USER")
                    .description("Usuario básico")
                    .permissions(Set.of(readPermission))
                    .build();
            roleRepository.save(userRole);

            // Crear rol ADMIN
            Set<PermissionEntity> allPermissions = new HashSet<>(permissionRepository.findAll());

            RoleEntity adminRole = RoleEntity.builder()
                    .name("ADMIN")
                    .description("Administrador del sistema")
                    .permissions(allPermissions)
                    .build();
            roleRepository.save(adminRole);

            log.info("Roles iniciales creados");
        }
    }

    private void initializeAdminUser() {
        if (!userRepository.existsByUsername("admin")) {
            RoleEntity adminRole = roleRepository.findByName("ADMIN").get();

            UserEntity adminUser = UserEntity.builder()
                    .username("admin")
                    .email("admin@cognito.com")
                    .password(org.mindrot.jbcrypt.BCrypt.hashpw("admin123", org.mindrot.jbcrypt.BCrypt.gensalt()))
                    .firstName("Admin")
                    .lastName("User")
                    .status(UserStatus.CONFIRMED)
                    .emailVerified(true)
                    .roles(Set.of(adminRole))
                    .build();

            userRepository.save(adminUser);
            log.info("Usuario administrador creado: admin/admin123");
        }
    }
}