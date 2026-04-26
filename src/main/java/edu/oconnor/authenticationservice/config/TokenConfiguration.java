package edu.oconnor.authenticationservice.config;

import edu.oconnor.authenticationservice.service.AzureGraphService;
import edu.oconnor.authenticationservice.service.JwtTokenProvider;
import edu.oconnor.authenticationservice.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;

import java.time.Duration;

/**
 * Configuration for the platform token exchange flow.
 * Creates JwtTokenProvider (for signing tokens) and RefreshTokenService.
 * JWT decoding is handled by shared-security's PlatformJwtAutoConfiguration.
 */
@Configuration
public class TokenConfiguration {

    @Bean("azureJwtDecoder")
    public JwtDecoder azureJwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }

    @Bean
    public JwtTokenProvider jwtTokenProvider(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.access-token-expiry:900}") long accessExpirySec,
            @Value("${app.jwt.refresh-token-expiry:604800}") long refreshExpirySec) {
        return new JwtTokenProvider(secret,
                Duration.ofSeconds(accessExpirySec),
                Duration.ofSeconds(refreshExpirySec));
    }

    @Bean
    public RefreshTokenService refreshTokenService(JdbcTemplate jdbcTemplate,
                                                   JwtTokenProvider tokenProvider) {
        return new RefreshTokenService(jdbcTemplate, tokenProvider);
    }

    @Bean
    public AzureGraphService azureGraphService(
            @Value("${azure.tenant-id}") String tenantId,
            @Value("${azure.client-id}") String clientId,
            @Value("${azure.client-secret}") String clientSecret) {
        return new AzureGraphService(tenantId, clientId, clientSecret);
    }
}
