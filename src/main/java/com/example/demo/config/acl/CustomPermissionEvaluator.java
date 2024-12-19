package com.example.demo.config.acl;

import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.stereotype.Component;

@Component
public class CustomPermissionEvaluator extends AclPermissionEvaluator {

    CustomAclService aclService;
    CustomSidRetrievalStrategy sidRetrievalStrategy = new CustomSidRetrievalStrategy();
    public CustomPermissionEvaluator(CustomAclService aclService) {
        super(aclService);
        setSidRetrievalStrategy(sidRetrievalStrategy);
        this.aclService = aclService;
    }
}
