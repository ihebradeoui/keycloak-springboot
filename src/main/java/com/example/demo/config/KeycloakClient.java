package com.example.demo.config;

import org.keycloak.admin.client.Keycloak;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class KeycloakClient {

    Keycloak keycloak = Keycloak.getInstance(
            "https://xxxxxxxxxxxxx/",
            "master",
            "xxxxxx",
            "xxxxxxxx",
            "api",
            "xxxxxxxxxxx");

    @Bean
    public Keycloak getKeycloak() {
        return keycloak;
    }

}
