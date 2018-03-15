package com.css.spring.security.authorities;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

/**
 * @author Kishore Routhu on 15/3/18 12:19 PM.
 */
public class DefaultActiveDirectoryAuthoritiesPopulator implements ActiveDirectoryAuthoritiesPopulator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultActiveDirectoryAuthoritiesPopulator.class);
    private String groupRoleAttribute;

    @Override
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations dirContextOperations, String username) {
        if (!StringUtils.hasText(groupRoleAttribute)) {
            return AuthorityUtils.NO_AUTHORITIES;
        }

        String[] groups = dirContextOperations.getStringAttributes(groupRoleAttribute);
        if (Objects.isNull(groups)) {
            LOGGER.debug("No values for '{}' attribute.", groupRoleAttribute);
            return AuthorityUtils.NO_AUTHORITIES;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("'{}' attribute values : {}", groupRoleAttribute, Arrays.asList(groups));
        }

        List<GrantedAuthority> authorities = new ArrayList<>(groups.length);
        for (String group : groups) {
            authorities.add(new SimpleGrantedAuthority("ROLE_".concat(new DistinguishedName(group).removeLast().getValue())));
        }

        return authorities;
    }

    public String getGroupRoleAttribute() {
        return groupRoleAttribute;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        this.groupRoleAttribute = groupRoleAttribute;
    }
}
