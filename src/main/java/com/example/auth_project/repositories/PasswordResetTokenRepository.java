package com.example.auth_project.repositories;

import com.example.auth_project.models.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    Optional<PasswordResetToken>
    findByTokenHashAndUsedFalseAndExpiryDateAfter(String tokenHash, Instant now);

    @Query("""
        SELECT prt
        FROM PasswordResetToken prt
        JOIN FETCH prt.user
        WHERE prt.tokenHash = :tokenHash
          AND prt.used = false
          AND prt.expiryDate > :now
    """)
    Optional<PasswordResetToken> findValidTokenWithUser(
            @Param("tokenHash") String tokenHash,
            @Param("now") Instant now
    );

    @Modifying
    @Query("""
        DELETE FROM PasswordResetToken prt 
        WHERE prt.expiryDate < :now OR prt.used = true
    """)
    void deleteAllExpiredOrUsed(@Param("now") Instant now);

    void deleteByUserId(UUID userId);
}
