package com.example.demo.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;

@Configuration
public class KeycloakJwtDecoder {

    @Bean
    public JwtDecoder jwtDecoder(RestTemplateBuilder builder) throws IOException {

        return NimbusJwtDecoder.withJwkSetUri("https://dev-2.newlogin.net/realms/newlogin/protocol/openid-connect/certs")
                .build();
}
}
