package com.example.demo.config;

import com.example.demo.config.acl.CustomAclService;
import com.example.demo.config.acl.CustomPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http , @Autowired JwtAuthConverter jwtAccessTokenConverter) throws Exception {
        http.authorizeHttpRequests(
                authorizationManagerRequestMatcherRegistry ->
                    authorizationManagerRequestMatcherRegistry.anyRequest()
                            .authenticated()
                )
                .sessionManagement(
                        sessionManagement -> sessionManagement
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAccessTokenConverter)));



        return http.build();
    }

    @Bean
    public MethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler(CustomAclService aclService) {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        CustomPermissionEvaluator permissionEvaluator = new CustomPermissionEvaluator(aclService);
        expressionHandler.setPermissionEvaluator(permissionEvaluator);
        return expressionHandler;
    }

}

