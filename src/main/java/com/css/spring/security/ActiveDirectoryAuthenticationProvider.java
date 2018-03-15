package com.css.spring.security;

import java.util.Collection;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;

import com.css.spring.security.authorities.ActiveDirectoryAuthoritiesPopulator;

/**
 * @author Kishore Routhu on 15/3/18 12:14 PM.
 */
public class ActiveDirectoryAuthenticationProvider extends SpringActiveDirectoryAuthenticationProvider {


    private ActiveDirectoryAuthoritiesPopulator authoritiesPopulator;

    /**
     * @param domain the domain name (null or empty)
     * @param url    an LDAP url (or multiple URLs space separated)
     */
    public ActiveDirectoryAuthenticationProvider(String domain, String url) {
        this(domain, url, null);
    }

    /**
     * @param domain the domain name (may be null or empty)
     * @param url    an LDAP url (or multiple URLs)
     * @param rootDn rootDn to override the computed rootDn in super class.
     */
    public ActiveDirectoryAuthenticationProvider(String domain, String url, String rootDn) {
        super(domain, url, rootDn);
        setConvertSubErrorCodesToExceptions(true);
    }

    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations dirContextOperations, String s, String s1) {
        return super.loadUserAuthorities(dirContextOperations, s, s1);
    }

    public ActiveDirectoryAuthoritiesPopulator getAuthoritiesPopulator() {
        return authoritiesPopulator;
    }

    public void setAuthoritiesPopulator(ActiveDirectoryAuthoritiesPopulator authoritiesPopulator) {
        this.authoritiesPopulator = authoritiesPopulator;
    }
}
