package com.example.auth_project.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Setter
@RequiredArgsConstructor
public class JwtService {

    private final RSAKey rsaKey;

    @Value("${app.security.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    public String generateToken(String email, UUID userId) {
        try {
            Instant now = Instant.now();
            Instant expiration = now.plusMillis(accessTokenExpiration);

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(email)
                    .issuer("auth-project")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("uid", userId.toString())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .type(JOSEObjectType.JWT)
                            .build(),
                    claims
            );

            JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            log.error("Failed to generate JWT", e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    public Optional<String> extractEmail(String token) {
        return extractClaim(token, claims -> claims.getSubject());
    }

    public Optional<UUID> extractUserId(String token) {
        return extractClaim(token, claims -> {
            String uid = (String) claims.getClaim("uid");
            return uid != null ? UUID.fromString(uid) : null;
        });
    }

    public boolean isTokenValid(String token, String email) {
        return extractEmail(token)
                .map(e -> e.equals(email) && !isTokenExpired(token))
                .orElse(false);
    }

    public Optional<Date> getExpirationDate(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    public Optional<String> extractJti(String token) {
        return extractClaim(token, claims -> claims.getJWTID());
    }

    private boolean isTokenExpired(String token) {
        return getExpirationDate(token)
                .map(exp -> exp.before(new Date()))
                .orElse(true);
    }

    private <T> Optional<T> extractClaim(String token, java.util.function.Function<JWTClaimsSet, T> claimsResolver) {
        return extractAllClaims(token).map(claimsResolver);
    }

    private Optional<JWTClaimsSet> extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            if (!signedJWT.verify(verifier)) {
                return Optional.empty();
            }

            return Optional.of(signedJWT.getJWTClaimsSet());
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }
}
