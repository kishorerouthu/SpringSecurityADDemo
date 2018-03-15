package com.css.spring.security.authorities;

import java.util.Collection;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Kishore Routhu on 15/3/18 12:17 PM.
 */
public interface ActiveDirectoryAuthoritiesPopulator {

        Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations dirContextOperations, String username);

}
