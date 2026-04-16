package com.example.auth_project.repositories;


import com.example.auth_project.models.RefreshToken;
import com.example.auth_project.models.User;
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
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user WHERE rt.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashWithUser(@Param("tokenHash") String tokenHash);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user.id = :userId")
    void revokeAllByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now AND rt.revoked = true")
    void deleteExpiredAndRevoked(@Param("now") Instant now);

    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.id = :userId")
    void deleteAllByUserId(@Param("userId") UUID userId);
}