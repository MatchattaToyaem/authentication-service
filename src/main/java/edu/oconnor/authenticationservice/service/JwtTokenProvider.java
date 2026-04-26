package edu.oconnor.authenticationservice.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Handles signing and verification of platform-issued JWTs,
 * plus generation and hashing of opaque refresh tokens.
 */
public class JwtTokenProvider {

    private final NimbusJwtEncoder encoder;
    private final NimbusJwtDecoder decoder;
    private final Duration accessTokenExpiry;
    private final Duration refreshTokenExpiry;

    public JwtTokenProvider(String base64Secret, Duration accessTokenExpiry, Duration refreshTokenExpiry) {
        byte[] secret = Base64.getDecoder().decode(base64Secret);

        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secret)
                .algorithm(JWSAlgorithm.HS256)
                .build();
        this.encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));

        SecretKeySpec key = new SecretKeySpec(secret, "HmacSHA256");
        this.decoder = NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        this.accessTokenExpiry = accessTokenExpiry;
        this.refreshTokenExpiry = refreshTokenExpiry;
    }

    /** Create a signed access JWT with the given user claims. */
    public String createAccessToken(String subject, String email, String name, List<String> roles) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject(subject)
                .issuer("oconnor-platform")
                .issuedAt(now)
                .expiresAt(now.plus(accessTokenExpiry))
                .claim("email", email != null ? email : "");
        if (name != null) {
            claims.claim("name", name);
        }
        if (roles != null && !roles.isEmpty()) {
            claims.claim("roles", roles);
        }

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    /** Decode and verify a platform-issued access JWT. */
    public Jwt decodeAccessToken(String token) {
        return decoder.decode(token);
    }

    /** Generate a cryptographically random opaque refresh token. */
    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    public long getAccessTokenExpirySeconds() {
        return accessTokenExpiry.toSeconds();
    }

    public Duration getRefreshTokenExpiry() {
        return refreshTokenExpiry;
    }

    /** SHA-256 hash a token for safe storage. */
    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
