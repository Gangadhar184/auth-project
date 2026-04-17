package com.example.auth_project.security;

import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Slf4j
@Configuration
public class JwtConfig {

    @Value("${app.security.jwt.key-store-path}")
    private String keyStorePath;

    @Value("${app.security.jwt.key-store-password}")
    private String keyStorePassword;

    @Value("${app.security.jwt.key-alias}")
    private String keyAlias;

    @Value("${app.security.jwt.kid}")
    private String kid;

    @Bean
    public KeyPair keyPair() {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] password = keyStorePassword.toCharArray();

            InputStream is;
            if (keyStorePath.startsWith("classpath:")) {
                is = getClass().getResourceAsStream(keyStorePath.replace("classpath:", ""));
            } else if (keyStorePath.startsWith("file:")) {
                is = new java.io.FileInputStream(keyStorePath.replace("file:", ""));
            } else {
                throw new IllegalArgumentException("Invalid keystore path");
            }
            keyStore.load(is, password);

            KeyStore.PasswordProtection keyProtection = new KeyStore.PasswordProtection(password);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(keyAlias, keyProtection);

            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            Certificate cert = keyStore.getCertificate(keyAlias);
            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            log.error("Failed to load JWT key pair", e);
            throw new RuntimeException("Could not load JWT signing keys", e);
        }
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(kid)
                .build();
    }

    @Bean
    public ImmutableJWKSet<SecurityContext> jwkSet(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
}
