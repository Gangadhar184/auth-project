package com.example.auth_project.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistService {
    private final RedisService redisService;
    private final JwtService jwtService;

    public void blacklistToken(String token) {
        try {
            Optional<String> jtiOpt = jwtService.extractJti(token);
            Optional<Date> expOpt = jwtService.getExpirationDate(token);

            if (jtiOpt.isPresent() && expOpt.isPresent()) {

                long ttlSeconds = Duration
                        .between(Instant.now(), expOpt.get().toInstant())
                        .getSeconds();

                if (ttlSeconds > 0) {
                    redisService.blacklistJti(jtiOpt.get(), ttlSeconds);
                    log.info("Token blacklisted: {}", jtiOpt.get());
                }
            }
        } catch (Exception e) {
            log.error("Failed to blacklist token", e);
        }
    }


    public boolean isBlacklisted(String token) {
        try {
            return jwtService.extractJti(token)
                    .map(redisService::isJtiBlacklisted)
                    .orElse(false);
        } catch (Exception e) {
            return false;
        }
    }

}
