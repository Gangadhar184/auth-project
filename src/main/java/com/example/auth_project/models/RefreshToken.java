package com.example.auth_project.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_token_hash", columnList = "tokenHash"),
        @Index(name = "idx_refresh_token_user", columnList = "user_id"),
        @Index(name = "idx_refresh_token_expiry", columnList = "expiryDate")
})
@Getter
@Setter(AccessLevel.PACKAGE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RefreshToken {

    @Id
    @UuidGenerator
    @Column(updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, name = "token_hash", length = 100)
    private String tokenHash;

    @Column(nullable = false, name = "expiry_date")
    private Instant expiryDate;

    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    public void revoke() {
        this.revoked = true;
    }
}
