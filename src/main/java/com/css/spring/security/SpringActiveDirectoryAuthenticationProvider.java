package com.css.spring.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Specialized LDAP authentication provider which uses Active Directory configuration conventions.
 * <p>
 * It will authenticate using the Active Directory
 * <a href="http://msdn.microsoft.com/en-us/library/ms680857%28VS.85%29.aspx">{@code userPrincipalName}</a>
 * (in the form {@code username@domain}). If the username does not already end with the domain name, the
 * {@code userPrincipalName} will be built by appending the configured domain name to the username supplied in the
 * authentication request. If no domain name is configured, it is assumed that the username will always contain the
 * domain name.
 * <p>
 * The user authorities are obtained from the data contained in the {@code memberOf} attribute.
 *
 * <h3>Active Directory Sub-Error Codes</h3>
 *
 * When an authentication fails, resulting in a standard LDAP 49 error code, Active Directory also supplies its own
 * sub-error codes within the error message. These will be used to provide additional log information on why an
 * authentication has failed. Typical examples are
 *
 * <ul>
 * <li>525 - user not found</li>
 * <li>52e - invalid credentials</li>
 * <li>530 - not permitted to logon at this time</li>
 * <li>532 - password expired</li>
 * <li>533 - account disabled</li>
 * <li>701 - account expired</li>
 * <li>773 - user must reset password</li>
 * <li>775 - account locked</li>
 * </ul>
 *
 * If you set the {@link #setConvertSubErrorCodesToExceptions(boolean) convertSubErrorCodesToExceptions} property to
 * {@code true}, the codes will also be used to control the exception raised.
 *
 * @author Kishore Routhu on 13/3/18 6:02 PM.
 */
public class SpringActiveDirectoryAuthenticationProvider extends AbstractLdapAuthenticationProvider {

    private static final Pattern SUB_ERROR_CODE = Pattern.compile(".*data\\s([0-9a-f]{3,4}).*");

    // Error codes
    private static final int USERNAME_NOT_FOUND = 1317; //0x525;
    private static final int INVALID_PASSWORD = 1326; //0x52e;
    private static final int NOT_PERMITTED = 1328; //0x530;
    private static final int PASSWORD_EXPIRED = 1330; //0x532;
    private static final int ACCOUNT_DISABLED = 1331; //0x533;
    private static final int ACCOUNT_EXPIRED = 1793; //0x701;
    private static final int PASSWORD_NEEDS_RESET = 1907; //0x773;
    private static final int ACCOUNT_LOCKED = 1909; //0x775;

    private final String domain;
    private String rootDn;
    private final String url;
    private boolean convertSubErrorCodesToExceptions;
    private String userSearchPattern = "(&(objectClass=user)(userPrincipalName={0}))";


    private static final Logger thisLogger = LoggerFactory.getLogger(SpringActiveDirectoryAuthenticationProvider.class);

    // Only used to allow tests to substitute a mock LdapContext
    ContextFactory contextFactory = new ContextFactory();



    /**
     * @param domain the domain name (may be null or empty)
     * @param url an LDAP url (or multiple URLs)
     */
    public SpringActiveDirectoryAuthenticationProvider(String domain, String url) {
        this(domain, url, null);

    }

    /**
     * @param domain the domain name (may be null or empty)
     * @param url an LDAP url (or multiple URLs)
     * @param rootDn rootDn to override the computed rootDn.
     */
    public SpringActiveDirectoryAuthenticationProvider(String domain, String url, String rootDn) {
        Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
        this.domain = StringUtils.hasText(domain) ? domain.toLowerCase() : null;
        this.url = url;
        if (!StringUtils.hasText(rootDn)) {
            this.rootDn = this.domain == null ? null : rootDnFromDomain(this.domain);
        } else {
            this.rootDn = rootDn;
        }
    }


    @Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth) {
        String username = auth.getName();
        String password = (String)auth.getCredentials();

        DirContext dirContext = bindAsUser(username, password);

        try {
            return searchForUser(dirContext, username);
        } catch (NamingException e) {
            thisLogger.error("Failed to locate directory entry for authenticated user: {}", username, e);
            throw badCredentials(e);
        } finally {
            LdapUtils.closeContext(dirContext);
        }
    }

    private DirContextOperations searchForUser(DirContext ctx, String username) throws NamingException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String bindPrincipal = createSearchUser(username);
        String searchRoot = rootDn != null? rootDn : searchRootFromPrincipal(bindPrincipal);

        try {
            return SpringSecurityLdapTemplate.searchForSingleEntryInternal(ctx, searchControls, searchRoot, userSearchPattern, new Object[]{bindPrincipal});
        } catch (IncorrectResultSizeDataAccessException incorrectResults) {
            if (incorrectResults.getActualSize() == 0) {
                UsernameNotFoundException userNameNotFoundException = new UsernameNotFoundException("User " + username + " not found in directory.", incorrectResults);
                userNameNotFoundException.initCause(incorrectResults);
                throw badCredentials(userNameNotFoundException);
            }
            // Search should never return multiple results if properly configured, so just rethrow
            throw incorrectResults;
        }
    }

    private String createSearchUser(String username) {
        return StringUtils.hasText(domain)? createPrincipal(username) : username;
    }

    private String searchRootFromPrincipal(String bindPrincipal) {
        int atChar = bindPrincipal.lastIndexOf('@');

        if (atChar < 0) {
            thisLogger.debug("User principal {} does not contain the domain, and no domain has been configured", bindPrincipal);
            throw badCredentials();
        }

        return rootDnFromDomain(bindPrincipal.substring(atChar+ 1, bindPrincipal.length()));
    }

    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations dirContextOperations, String s, String s1) {
        String[] groups = dirContextOperations.getStringAttributes("memberOf");
        if (groups == null) {
            thisLogger.debug("No values of 'memberOf' attribute.");
            return AuthorityUtils.NO_AUTHORITIES;
        }

        if (thisLogger.isDebugEnabled()) {
            thisLogger.debug("'memberOf' attribute values:{}", Arrays.asList(groups));
        }

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(groups.length);
        for (String group : groups) {
            authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()));
        }

        return authorities;
    }

    private DirContext bindAsUser(String username, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        String principal = createPrincipal(username);
        env.put(Context.SECURITY_PRINCIPAL, principal);
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.OBJECT_FACTORIES, DefaultDirObjectFactory.class.getName());
        try {
            return contextFactory.createContext(env);
        } catch (NamingException e) {
            if ((e instanceof AuthenticationException) || (e instanceof OperationNotSupportedException)) {
                handleBindException(principal, e);
                throw badCredentials(e);
            } else {
                throw LdapUtils.convertLdapException(e);
            }
        }
    }

    /**
     * This method formats the principal name depends on the authentication scheme (userPrincipalName/sAMAccountName)
     * case 1: If domain is configured i.e authentication scheme is userPrincipalName, format of principle is username@exmaple.com
     * case 2: If domain is not configured and rootDn is configured i.e authentication scheme can be userPrincipalName/sAMAccountName
     *          -> If username contains @ that means
     *                  It contains domain name falls into authentication scheme userPrincipalName
     *          ->  else
     *                  The authentication scheme is sAMAccountName then format of principal is example/username
     *
     * case 3: If domain and rootDn are not configured then consider that username already contains domain in it.
     * @param username
     * @return formated principal name
     */
    private String createPrincipal(String username) {
        if (StringUtils.hasText(domain)) {
            return createBindPrincipal(username);
        } else if (StringUtils.hasText(rootDn)){
            if (username.toLowerCase().contains("@")) {
                return username;
            } else {
                String []dns = rootDn.split(",");
                String domain = dns[0].split("=")[1];
                return domain.concat("\\").concat(username);
            }
        } else {
            return username;
        }
    }

    /**
     * This method manipulate the username sush that make sure that
     * UserPrincipalName should contains the domain name
     * @param username
     * @return bind principal (username) with associated domain name
     */
    private String createBindPrincipal(String username) {
        if (username.toLowerCase().endsWith(domain)) {
            return username;
        }
        return username.concat("@").concat(domain);
    }

    void handleBindException(String bindPrincipal, NamingException exception) {
        thisLogger.debug("Authentication for {} failed:", bindPrincipal, exception);

        int subErrorCode = parseSubErrorCode(exception.getMessage());

        if (subErrorCode > 0) {
            if (thisLogger.isInfoEnabled()) {
                thisLogger.info("Active Directory authentication failed: {}", subCodeToLogMessage(subErrorCode));
            }

            if (convertSubErrorCodesToExceptions) {
                raiseExceptionForErrorCode(subErrorCode, exception);
            }
        } else {
            thisLogger.debug("Failed to locate AD-specific sub-error code in message");
        }
    }

    int parseSubErrorCode(String message) {
        Matcher m = SUB_ERROR_CODE.matcher(message);

        if (m.matches()) {
            return Integer.parseInt(m.group(1), 16);
        }

        return -1;
    }

    void raiseExceptionForErrorCode(int code, NamingException exception) {
        String hexString = Integer.toHexString(code);
        Throwable cause = new SpringActiveDirectoryAuthenticationException(hexString, exception.getMessage(), exception);
        switch (code) {
            case PASSWORD_EXPIRED:
                throw new CredentialsExpiredException(messages.getMessage("LdapAuthenticationProvider.credentialsExpired",
                        "User credentials have expired"), cause);
            case ACCOUNT_DISABLED:
                throw new DisabledException(messages.getMessage("LdapAuthenticationProvider.disabled",
                        "User is disabled"), cause);
            case ACCOUNT_EXPIRED:
                throw new AccountExpiredException(messages.getMessage("LdapAuthenticationProvider.expired",
                        "User account has expired"), cause);
            case ACCOUNT_LOCKED:
                throw new LockedException(messages.getMessage("LdapAuthenticationProvider.locked",
                        "User account is locked"), cause);
            default:
                throw badCredentials(cause);
        }
    }

    String subCodeToLogMessage(int code) {
        switch (code) {
            case USERNAME_NOT_FOUND:
                return "User was not found in directory";
            case INVALID_PASSWORD:
                return "Supplied password was invalid";
            case NOT_PERMITTED:
                return "User not permitted to logon at this time";
            case PASSWORD_EXPIRED:
                return "Password has expired";
            case ACCOUNT_DISABLED:
                return "Account is disabled";
            case ACCOUNT_EXPIRED:
                return "Account expired";
            case PASSWORD_NEEDS_RESET:
                return "User must reset password";
            case ACCOUNT_LOCKED:
                return "Account locked";
            default:
        }

        return "Unknown (error code " + Integer.toHexString(code) +")";
    }

    private String rootDnFromDomain(String domain) {
        String[] tokens = StringUtils.tokenizeToStringArray(domain, ".");
        StringBuilder root = new StringBuilder();

        for (String token : tokens) {
            if (root.length() > 0) {
                root.append(',');
            }
            root.append("dc=").append(token);
        }

        return root.toString();
    }

    private BadCredentialsException badCredentials() {
        return new BadCredentialsException(messages.getMessage(
                "LdapAuthenticationProvider.badCredentials", "Bad credentials"));
    }

    private BadCredentialsException badCredentials(Throwable cause) {
        return (BadCredentialsException) badCredentials().initCause(cause);
    }

    /**
     * By default, a failed authentication (LDAP error 49) will result in a {@code BadCredentialsException}.
     * <p>
     * If this property is set to {@code true}, the exception message from a failed bind attempt will be parsed
     * for the AD-specific error code and a {@link CredentialsExpiredException}, {@link DisabledException},
     * {@link AccountExpiredException} or {@link LockedException} will be thrown for the corresponding codes. All
     * other codes will result in the default {@code BadCredentialsException}.
     *
     * @param convertSubErrorCodesToExceptions {@code true} to raise an exception based on the AD error code.
     */
    public void setConvertSubErrorCodesToExceptions(boolean convertSubErrorCodesToExceptions) {
        this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
    }

    static class ContextFactory {
        DirContext createContext(Hashtable<?,?> env) throws NamingException {
            return new InitialLdapContext(env, null);
        }
    }

    public String getUserSearchPattern() {
        return userSearchPattern;
    }

    public void setUserSearchPattern(String userSearchPattern) {
        this.userSearchPattern = userSearchPattern;
    }
}
