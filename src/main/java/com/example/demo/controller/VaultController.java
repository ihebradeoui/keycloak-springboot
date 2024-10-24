package com.example.demo.controller;

import com.example.demo.config.vault.VaultConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/vault")
public class VaultController {
    @Autowired
    private VaultConfiguration vaultConfiguration;
    @GetMapping()
    public String getVault() {
        return vaultConfiguration.getPassword()+"yoo";
    }
}
