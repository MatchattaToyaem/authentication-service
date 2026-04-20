package edu.oconnor.authenticationservice.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/")
    public String home() {
        return "This is a public page. <a href='/oauth2/authorization/microsoft'>Login with Microsoft</a>";
    }

    @GetMapping("/secure-data")
    public String getSecureData(@AuthenticationPrincipal Jwt jwt) {
        // Extract claims from the Azure AD token
        String name = jwt.getClaimAsString("name");
        String preferredUsername = jwt.getClaimAsString("preferred_username");

        return String.format("Hello %s! Your token is valid. Your email is %s", name, preferredUsername);
    }

}
