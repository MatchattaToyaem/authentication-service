package edu.oconnor.authenticationservice.controller;

import edu.oconnor.authenticationservice.model.RefreshTokenRequest;
import edu.oconnor.authenticationservice.model.TokenExchangeRequest;
import edu.oconnor.authenticationservice.model.TokenResponse;
import edu.oconnor.authenticationservice.service.AzureGraphService;
import edu.oconnor.authenticationservice.service.JwtTokenProvider;
import edu.oconnor.authenticationservice.service.RefreshTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Token exchange and refresh endpoints.
 *
 * POST /api/auth/token   — exchange an Azure AD token for platform tokens
 * POST /api/auth/refresh — use a refresh token to obtain new platform tokens
 * POST /api/auth/logout  — revoke a refresh token
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtDecoder azureJwtDecoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final AzureGraphService azureGraphService;

    public AuthController(@Qualifier("azureJwtDecoder") JwtDecoder azureJwtDecoder,
                          JwtTokenProvider tokenProvider,
                          RefreshTokenService refreshTokenService,
                          AzureGraphService azureGraphService) {
        this.azureJwtDecoder = azureJwtDecoder;
        this.tokenProvider = tokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.azureGraphService = azureGraphService;
    }

    /** Exchange a valid Azure AD access token for platform access + refresh tokens. */
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> exchangeToken(@RequestBody TokenExchangeRequest request) {
        try {
            Jwt azureJwt = azureJwtDecoder.decode(request.azureToken());

            String userId = azureJwt.getSubject();
            String oid = azureJwt.getClaimAsString("oid");
            String email = azureJwt.getClaimAsString("preferred_username");
            String name = azureJwt.getClaimAsString("name");
            List<String> roles = azureGraphService.getRolesForUser(oid);

            String accessToken = tokenProvider.createAccessToken(userId, email, name, roles);
            String refreshToken = refreshTokenService.createAndStore(userId, email, name, roles);

            log.info("Token exchanged for user: {}", email);
            return ResponseEntity.ok(
                    new TokenResponse(accessToken, refreshToken, tokenProvider.getAccessTokenExpirySeconds()));

        } catch (JwtException e) {
            log.warn("Token exchange failed: invalid Azure AD token — {}", e.getMessage());
            return ResponseEntity.status(401).build();
        }
    }

    /** Use a refresh token to obtain a new access + refresh token pair (token rotation). */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        return refreshTokenService.validate(request.refreshToken())
                .map(row -> {
                    // Rotate: revoke old, issue new
                    refreshTokenService.revoke(request.refreshToken());

                    String userId = (String) row.get("user_id");
                    String email = (String) row.get("user_email");
                    String name = (String) row.get("user_name");
                    List<String> roles = RefreshTokenService.parseRoles((String) row.get("user_roles"));

                    String accessToken = tokenProvider.createAccessToken(userId, email, name, roles);
                    String newRefreshToken = refreshTokenService.createAndStore(userId, email, name, roles);

                    log.info("Token refreshed for user: {}", email);
                    return ResponseEntity.ok(
                            new TokenResponse(accessToken, newRefreshToken, tokenProvider.getAccessTokenExpirySeconds()));
                })
                .orElseGet(() -> {
                    log.warn("Refresh token invalid or expired");
                    return ResponseEntity.status(401).build();
                });
    }

    /** Revoke a refresh token (client-initiated logout). */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenRequest request) {
        refreshTokenService.revoke(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
