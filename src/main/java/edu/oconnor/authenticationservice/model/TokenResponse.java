package edu.oconnor.authenticationservice.model;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn) {}
