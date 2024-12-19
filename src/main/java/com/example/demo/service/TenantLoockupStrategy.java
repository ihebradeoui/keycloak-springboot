package com.example.demo.service;

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.PermissionGrantingStrategy;

import javax.sql.DataSource;

public class TenantLoockupStrategy extends BasicLookupStrategy {

    public TenantLoockupStrategy(DataSource dataSource, AclCache aclCache, AclAuthorizationStrategy aclAuthorizationStrategy, PermissionGrantingStrategy grantingStrategy) {
        super(dataSource, aclCache, aclAuthorizationStrategy, grantingStrategy);
    }

    public TenantLoockupStrategy(DataSource dataSource, AclCache aclCache, AclAuthorizationStrategy aclAuthorizationStrategy, AuditLogger auditLogger) {
        super(dataSource, aclCache, aclAuthorizationStrategy, auditLogger);
    }


}
