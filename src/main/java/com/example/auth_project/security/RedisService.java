package com.example.auth_project.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

    private final StringRedisTemplate redisTemplate;

    private static final String LOGIN_ATTEMPTS_KEY = "login:attempt:%s:%S";
    private static final String FORGOT_PASSWORD_KEY = "forgot:password:%s";
    private static final String BRUTE_FORCE_KEY = "brute:force:%s";
    // Token Keys
    private static final String TOKEN_BLACKLIST_KEY = "blacklist:%s";  // jti
    private static final String VERIFICATION_TOKEN_KEY = "verify:%s";  // token
    private static final String PASSWORD_RESET_KEY = "reset:%s";

    public boolean isLoginAllowed(String ip, String email) {
        String key = String.format(LOGIN_ATTEMPTS_KEY, ip, email);
        Long attempts = redisTemplate.opsForValue().increment(key);
        if(attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(5));
        }
        return attempts <= 5;
    }
    public void resetLoginAttempts(String ip, String email) {
        String key = String.format(LOGIN_ATTEMPTS_KEY, ip, email);
        redisTemplate.delete(key);
    }
    public boolean isForgotPasswordAllowed(String email) {
        String key = String.format(FORGOT_PASSWORD_KEY, email);
        Long attempts = redisTemplate.opsForValue().increment(key);
        if (attempts == 1) {
            redisTemplate.expire(key, Duration.ofHours(1));
        }
        return attempts <= 3;
    }
    public void recordFailedLogin(String email) {
        String key = String.format(BRUTE_FORCE_KEY, email);
        Long failures = redisTemplate.opsForValue().increment(key);
        if (failures == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(30));
        }
        log.warn("Failed login attempt {} for user: {}", failures, email);
    }
    public int getFailedAttempts(String email) {
        String key = String.format(BRUTE_FORCE_KEY, email);
        String value = redisTemplate.opsForValue().get(key);
        return value != null ? Integer.parseInt(value) : 0;
    }
    public void clearFailedAttempts(String email) {
        String key = String.format(BRUTE_FORCE_KEY, email);
        redisTemplate.delete(key);
    }
    public void lockAccount(String email, Duration duration) {
        String key = String.format(BRUTE_FORCE_KEY, email);
        redisTemplate.opsForValue().set(key, "LOCKED", duration);
    }

    public boolean isAccountLocked(String email) {
        String key = String.format(BRUTE_FORCE_KEY, email);
        String value = redisTemplate.opsForValue().get(key);
        return "LOCKED".equals(value);
    }

    // Token Blacklist
    public void blacklistToken(String jti, Instant expiration) {
        String key = String.format(TOKEN_BLACKLIST_KEY, jti);
        long ttl = Duration.between(Instant.now(), expiration).getSeconds();
        if (ttl > 0) {
            redisTemplate.opsForValue().set(key, "revoked", ttl, TimeUnit.SECONDS);
        }
    }

    public boolean isBlacklisted(String token) {
        try {
            // Extract JTI from token (simplified - in production use JwtService)
            return false; // Implementation depends on token structure
        } catch (Exception e) {
            return false;
        }
    }

    public void blacklistJti(String jti, long expirationSeconds) {
        String key = String.format(TOKEN_BLACKLIST_KEY, jti);
        redisTemplate.opsForValue().set(key, "revoked", expirationSeconds, TimeUnit.SECONDS);
    }

    public boolean isJtiBlacklisted(String jti) {
        String key = String.format(TOKEN_BLACKLIST_KEY, jti);
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // Verification Token Cache
    public void cacheVerificationToken(String token, String userId, Duration ttl) {
        String key = String.format(VERIFICATION_TOKEN_KEY, token);
        redisTemplate.opsForValue().set(key, userId, ttl);
    }

    public String getCachedVerificationUser(String token) {
        String key = String.format(VERIFICATION_TOKEN_KEY, token);
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteVerificationToken(String token) {
        String key = String.format(VERIFICATION_TOKEN_KEY, token);
        redisTemplate.delete(key);
    }

    // Password Reset Token Cache
    public void cachePasswordResetToken(String token, String userId, Duration ttl) {
        String key = String.format(PASSWORD_RESET_KEY, token);
        redisTemplate.opsForValue().set(key, userId, ttl);
    }

    public String getCachedPasswordResetUser(String token) {
        String key = String.format(PASSWORD_RESET_KEY, token);
        return redisTemplate.opsForValue().get(key);
    }

    public void deletePasswordResetToken(String token) {
        String key = String.format(PASSWORD_RESET_KEY, token);
        redisTemplate.delete(key);
    }

}
