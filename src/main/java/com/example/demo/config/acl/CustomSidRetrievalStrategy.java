package com.example.demo.config.acl;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

@Component
public class CustomSidRetrievalStrategy implements SidRetrievalStrategy {

    private final RoleHierarchy roleHierarchy = new NullRoleHierarchy();

    @Override
    public List<Sid> getSids(Authentication authentication) {
        List<Sid> sids = new java.util.ArrayList<>();
        Collection<? extends GrantedAuthority> authorities = this.roleHierarchy
                .getReachableGrantedAuthorities(authentication.getAuthorities());
        sids.add(new PrincipalSid(authentication));
        for (String company : ((Jwt)authentication.getCredentials()).getClaimAsStringList("companies")) {
            authorities.forEach(authority -> sids.add(new PrincipalSid(authority + company)));
        }
        System.out.println("getSids "+sids);
        return sids;
    }
}
