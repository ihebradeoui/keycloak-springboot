package com.example.demo.controller;

import com.example.demo.service.KeycloakService;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Objects;

@RestController
@RequestMapping("/demo")
public class DemoController {
    @Autowired
    KeycloakService keycloakService;
    @GetMapping("/hello")
    @PreAuthorize("hasRole('ADMIN')")
    public String getDemo() {
        return "Hello World!";
    }

    @GetMapping("/feed")
//  @PreAuthorize("hasRole('ADMIN')")
    public String getDemo(@AuthenticationPrincipal Jwt jwt) {
        if(Objects.nonNull(jwt))
            return "getting recommendations based on your shoe size which is "+jwt.getClaim("shoeSize");
        return "getting default feed because you are not authenticated";
    }
    @GetMapping("/users")
    public List<UserRepresentation> getUsers() {
        return keycloakService.getUsers();
    }

    @PutMapping("/users/TermsAndConditions")
    public void acceptTermsAndConditions() {
        keycloakService.setAcceptTermsandConditionsForAllUsers();
    }

}
