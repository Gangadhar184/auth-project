package com.example.auth_project.repositories;

import com.example.auth_project.models.User;
import com.example.auth_project.models.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    Optional<VerificationToken> findByTokenHash(String tokenHash);

    Optional<VerificationToken> findByTokenHashAndUsedFalseAndExpiryDateAfter(String tokenHash, Instant now);

    @Query("""
        SELECT vt 
        FROM VerificationToken vt 
        JOIN FETCH vt.user 
        WHERE vt.tokenHash = :tokenHash
    """)
    Optional<VerificationToken> findByTokenHashWithUser(@Param("tokenHash") String tokenHash);

    // Fetch only valid token with user
    @Query("""
        SELECT vt 
        FROM VerificationToken vt 
        JOIN FETCH vt.user 
        WHERE vt.tokenHash = :tokenHash
          AND vt.used = false
          AND vt.expiryDate > :now
    """)
    Optional<VerificationToken> findValidTokenWithUser(
            @Param("tokenHash") String tokenHash,
            @Param("now") Instant now
    );

    List<VerificationToken> findByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM VerificationToken vt WHERE vt.expiryDate < :now")
    void deleteAllExpired(@Param("now") Instant now);

    void deleteByUserId(User userId);
}
