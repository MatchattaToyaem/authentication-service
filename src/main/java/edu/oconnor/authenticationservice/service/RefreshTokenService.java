package edu.oconnor.authenticationservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Manages refresh-token lifecycle: creation, validation, rotation, and revocation.
 * Tokens are stored as SHA-256 hashes; the plaintext is only returned to the client.
 */
@Slf4j
public class RefreshTokenService {

    private final JdbcTemplate jdbcTemplate;
    private final JwtTokenProvider tokenProvider;

    public RefreshTokenService(JdbcTemplate jdbcTemplate, JwtTokenProvider tokenProvider) {
        this.jdbcTemplate = jdbcTemplate;
        this.tokenProvider = tokenProvider;
    }

    /** Create a new refresh token, store its hash, and return the plaintext token. */
    public String createAndStore(String userId, String userEmail, String userName, List<String> roles) {
        String token = tokenProvider.createRefreshToken();
        String hash = JwtTokenProvider.hashToken(token);
        Instant expiresAt = Instant.now().plus(tokenProvider.getRefreshTokenExpiry());
        String rolesStr = (roles != null && !roles.isEmpty()) ? String.join(",", roles) : "";

        jdbcTemplate.update(
                "INSERT INTO refresh_tokens (token_hash, user_id, user_email, user_name, user_roles, expires_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?)",
                hash, userId, userEmail, userName, rolesStr, Timestamp.from(expiresAt));

        log.debug("Stored refresh token for user {}", userEmail);
        return token;
    }

    /** Parse the stored roles string back into a list. */
    public static List<String> parseRoles(String rolesStr) {
        if (rolesStr == null || rolesStr.isBlank()) return List.of();
        return Arrays.asList(rolesStr.split(","));
    }

    /**
     * Validate the plaintext refresh token: look up its hash, check it is
     * not revoked and not expired. Returns the stored row if valid.
     */
    public Optional<Map<String, Object>> validate(String token) {
        String hash = JwtTokenProvider.hashToken(token);

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT * FROM refresh_tokens "
                        + "WHERE token_hash = ? AND revoked = FALSE AND expires_at > CURRENT_TIMESTAMP",
                hash);

        return rows.stream().findFirst();
    }

    /** Revoke a single refresh token (token rotation). */
    public void revoke(String token) {
        String hash = JwtTokenProvider.hashToken(token);
        jdbcTemplate.update(
                "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP "
                        + "WHERE token_hash = ?",
                hash);
    }

    /** Revoke all refresh tokens for a user (logout-everywhere). */
    public void revokeAllForUser(String userId) {
        jdbcTemplate.update(
                "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = CURRENT_TIMESTAMP "
                        + "WHERE user_id = ? AND revoked = FALSE",
                userId);
    }
}
