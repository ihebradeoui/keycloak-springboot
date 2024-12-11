package com.example.demo.service;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class KeycloakService {
    @Autowired
    Keycloak keycloak;
    public List<UserRepresentation> getUsers() {
        return keycloak.realm("newlogin").users().list();
    }
    public void setAcceptTermsandConditionsForAllUsers()
    {
        keycloak.realm("newlogin").users().list().forEach(userRepresentation -> {
            userRepresentation.getRequiredActions().add("TERMS_AND_CONDITIONS");
            keycloak.realm("newlogin").users().get(userRepresentation.getId()).update(userRepresentation);
        });
    }
}
