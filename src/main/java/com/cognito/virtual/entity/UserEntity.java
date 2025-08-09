package com.cognito.virtual.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
@lombok.Builder
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, nullable = false)
    private String username;
    @Column(unique = true, nullable = false)
    private String email;
    @Column(nullable = false)
    private String password;
    @Column(name = "first_name")
    private String firstName;
    @Column(name = "last_name")
    private String lastName;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    private UserStatus status = UserStatus.UNCONFIRMED;

    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "phone_verified")
    private Boolean phoneVerified = false;

    @Column(name = "created_at")
    @lombok.Builder.Default
    private java.time.LocalDateTime createdAt = java.time.LocalDateTime.now();

    @Column(name = "updated_at")
    private java.time.LocalDateTime updatedAt;

    @Column(name = "last_login")
    private java.time.LocalDateTime lastLogin;

    @Column(name = "confirmation_code")
    private String confirmationCode;

    @Column(name = "reset_token")
    private String resetToken;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @lombok.Builder.Default
    //@JsonManagedReference
    private java.util.Set<RoleEntity> roles = new java.util.HashSet<>();

    @OneToMany(mappedBy = "user", cascade =
            CascadeType.ALL, fetch = FetchType.LAZY)
    @lombok.Builder.Default
    private java.util.Set<RefreshTokenEntity> refreshTokens = new java.util.HashSet<>();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = java.time.LocalDateTime.now();
    }
} 