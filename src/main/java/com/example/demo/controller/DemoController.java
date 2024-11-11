package com.example.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
@RequestMapping("/demo")
public class DemoController {
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
}
