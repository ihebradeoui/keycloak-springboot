package com.example.demo.config.acl;

import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.model.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.List;
import java.util.Map;


@Service
public class CustomAclService extends JdbcMutableAclService {
    public CustomAclService(DataSource dataSource, BasicLookupStrategy lookupStrategy, AclCache aclCache) {
        super(dataSource, lookupStrategy, aclCache);
    }
    public Acl readAclById(ObjectIdentity object, List<Sid> sids, boolean checkObjectIdentity) throws NotFoundException {
        Map<ObjectIdentity, Acl> map = readAclsById(Collections.singletonList(object), sids,checkObjectIdentity);
        if(checkObjectIdentity) {
        Assert.isTrue(map.containsKey(object),
                () -> "There should have been an Acl entry for ObjectIdentity " + object);
        }
        return map.get(object);
    }
    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids, boolean checkObjectIdentity)
            throws NotFoundException {
        Map<ObjectIdentity, Acl> result = super.readAclsById(objects, sids);
        if(checkObjectIdentity) {
            for (ObjectIdentity oid : objects) {
                if (!result.containsKey(oid)) {
                    throw new NotFoundException("Unable to find ACL information for object identity '" + oid + "'");
                }
            }
        }
        return result;
    }
    public void saveNewAcl(Jwt jwt , ObjectIdentity objectIdentity)
    {
        Sid sid = new PrincipalSid("ROLE_ACCOUNTANT"+jwt.getClaimAsStringList("companies").get(0));
        Permission p = BasePermission.READ;

        MutableAcl acl = null;
        try {
            acl = (MutableAcl) readAclById(objectIdentity);
        } catch (NotFoundException nfe) {
            acl = createAcl(objectIdentity);
        }
        acl.insertAce(acl.getEntries().size(), p, sid, true);
        updateAcl(acl);
    }
}

//TODO: override the lookup strategy to lookup by sid instead of oid
