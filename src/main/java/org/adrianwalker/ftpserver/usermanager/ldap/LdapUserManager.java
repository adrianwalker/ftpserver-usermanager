package org.adrianwalker.ftpserver.usermanager.ldap;

import static java.lang.String.format;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.contains;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.present;

import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.ValidatingPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.EntryMapper;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.apache.directory.ldap.client.template.exception.PasswordException;
import org.apache.ftpserver.ftplet.Authentication;
import org.apache.ftpserver.ftplet.AuthenticationFailedException;
import org.apache.ftpserver.ftplet.Authority;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.User;
import org.apache.ftpserver.usermanager.UsernamePasswordAuthentication;
import org.apache.ftpserver.usermanager.impl.AbstractUserManager;
import org.apache.ftpserver.usermanager.impl.BaseUser;
import org.apache.ftpserver.usermanager.impl.ConcurrentLoginPermission;
import org.apache.ftpserver.usermanager.impl.TransferRatePermission;
import org.apache.ftpserver.usermanager.impl.WritePermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public final class LdapUserManager extends AbstractUserManager {

  private static final Logger LOGGER = LoggerFactory.getLogger(LdapUserManager.class);

  private static final String ATTR_OBJECT_CLASS = "objectClass";
  private static final String ATTR_UID = "uid";
  private static final String ATTR_CN = "cn";
  private static final String ATTR_SN = "sn";
  private static final String ATTR_USER_PASSWORD = "userPassword";
  private static final String ATTR_UNIX_FILE_PATH = "unixFilePath";
  private static final String ATTR_PWD_ATTRBUTE = "pwdAttribute";
  private static final String ATTR_PWD_MAX_IDLE = "pwdMaxIdle";
  private static final String ATTR_PWD_LOCKOUT = "pwdLockout";

  private static final String OBJECT_CLASS_INET_ORG_PERSON = "inetOrgPerson";
  private static final String OBJECT_CLASS_EXTENSIBLE_OBJECT = "extensibleObject";

  private final LdapUserManagerConfiguration configuration;

  private LdapConnectionTemplate ldapConnectionTemplate;

  public LdapUserManager(final Properties properties) {

    this(new LdapUserManagerConfiguration(properties));
  }

  public LdapUserManager(final LdapUserManagerConfiguration configuration) {

    LOGGER.debug("configuration = {}", configuration);

    if (null == configuration) {
      throw new IllegalArgumentException("configuration is null");
    }

    this.configuration = configuration;

    init();
  }

  private void init() {

    LdapConnectionConfig ldapConnectionConfig = new LdapConnectionConfig();
    ldapConnectionConfig.setLdapHost(configuration.getConnectionHost());
    ldapConnectionConfig.setLdapPort(configuration.getConnectionPort());
    ldapConnectionConfig.setName(configuration.getConnectionName());
    ldapConnectionConfig.setCredentials(configuration.getConnectionCredentials());

    GenericObjectPool.Config poolConfig = new GenericObjectPool.Config();
    poolConfig.maxActive = configuration.getConnectionMaxActive();
    poolConfig.maxIdle = configuration.getConnectionMaxIdle();

    DefaultLdapConnectionFactory ldapConnectionFactory
            = new DefaultLdapConnectionFactory(ldapConnectionConfig);
    ldapConnectionFactory.setTimeOut(configuration.getConnectionTimeOut());
    ValidatingPoolableLdapConnectionFactory poolableLdapConnectionFactory
            = new ValidatingPoolableLdapConnectionFactory(ldapConnectionFactory);
    LdapConnectionPool ldapPool = new LdapConnectionPool(poolableLdapConnectionFactory, poolConfig);
    ldapConnectionTemplate = new LdapConnectionTemplate(ldapPool);
  }

  @Override
  public User getUserByName(final String name) throws FtpException {

    LOGGER.debug("name = {}", name);

    if (null == name) {
      throw new IllegalArgumentException("name is null");
    }

    Dn dn = ldapConnectionTemplate.newDn(
            format("%s=%s,%s", ATTR_UID, name, configuration.getUserBaseDn()));

    return ldapConnectionTemplate.lookup(dn, entry -> createUser(entry));
  }

  @Override
  public String[] getAllUserNames() throws FtpException {

    Dn dn = ldapConnectionTemplate.newDn(configuration.getUserBaseDn());

    FilterBuilder filter = and(
            present(ATTR_UID),
            contains(ATTR_OBJECT_CLASS, OBJECT_CLASS_INET_ORG_PERSON));

    EntryMapper<String> mapper = entry -> toString(entry.get(ATTR_UID));
    List<String> userNames = ldapConnectionTemplate.search(
            dn, filter, SearchScope.ONELEVEL, mapper);

    LOGGER.debug("userNames = {}", userNames);

    return userNames.toArray(new String[userNames.size()]);
  }

  @Override
  public void delete(final String name) throws FtpException {

    LOGGER.debug("name = {}", name);

    if (null == name) {
      throw new IllegalArgumentException("name is null");
    }

    Dn dn = ldapConnectionTemplate.newDn(
            format("%s=%s,%s", ATTR_UID, name, configuration.getUserBaseDn()));

    ldapConnectionTemplate.delete(dn);
  }

  @Override
  public void save(final User user) throws FtpException {

    LOGGER.debug("user = {}", user);

    if (null == user) {
      throw new IllegalArgumentException("user is null");
    }

    Dn dn = ldapConnectionTemplate.newDn(
            format("%s=%s,%s", ATTR_UID, user.getName(), configuration.getUserBaseDn()));

    String[] objectClasses = {
      OBJECT_CLASS_INET_ORG_PERSON, OBJECT_CLASS_EXTENSIBLE_OBJECT
    };

    Attribute[] attributes = {
      ldapConnectionTemplate.newAttribute(ATTR_OBJECT_CLASS, objectClasses),
      ldapConnectionTemplate.newAttribute(ATTR_CN, user.getName()),
      ldapConnectionTemplate.newAttribute(ATTR_SN, user.getName()),
      ldapConnectionTemplate.newAttribute(ATTR_USER_PASSWORD, user.getPassword()),
      ldapConnectionTemplate.newAttribute(ATTR_PWD_ATTRBUTE, ATTR_USER_PASSWORD),
      ldapConnectionTemplate.newAttribute(ATTR_UNIX_FILE_PATH, user.getHomeDirectory()),
      ldapConnectionTemplate.newAttribute(ATTR_PWD_MAX_IDLE, toString(user.getMaxIdleTime())),
      ldapConnectionTemplate.newAttribute(ATTR_PWD_LOCKOUT, toString(!user.getEnabled()))
    };

    ldapConnectionTemplate.add(dn, attributes);
  }

  @Override
  public boolean doesExist(final String name) throws FtpException {

    LOGGER.debug("name = {}", name);

    if (null == name) {
      throw new IllegalArgumentException("name is null");
    }

    return null != getUserByName(name);
  }

  @Override
  public User authenticate(final Authentication auth)
          throws AuthenticationFailedException {

    LOGGER.debug("auth = {}", auth);

    if (null == auth) {
      throw new IllegalArgumentException("auth is null");
    }

    boolean isUsernamePasswordAuth = auth instanceof UsernamePasswordAuthentication;

    if (!isUsernamePasswordAuth) {
      throw new AuthenticationFailedException();
    }

    UsernamePasswordAuthentication usernamePasswordAuth = (UsernamePasswordAuthentication) auth;
    String username = usernamePasswordAuth.getUsername();
    String password = usernamePasswordAuth.getPassword();

    Dn dn = ldapConnectionTemplate.newDn(
            format("%s=%s,%s", ATTR_UID, username, configuration.getUserBaseDn()));

    try {
      ldapConnectionTemplate.authenticate(dn, password.toCharArray());
    } catch (final PasswordException pe) {
      LOGGER.error(pe.getMessage(), pe);
      throw new AuthenticationFailedException(pe);
    }

    try {
      return getUserByName(username);
    } catch (final FtpException fe) {
      LOGGER.error(fe.getMessage(), fe);
      throw new AuthenticationFailedException(fe);
    }
  }

  private User createUser(final Entry entry)
          throws LdapInvalidAttributeValueException {

    BaseUser user = new BaseUser();
    user.setName(toString(entry.get(ATTR_UID)));
    user.setHomeDirectory(toString(entry.get(ATTR_UNIX_FILE_PATH)));
    user.setMaxIdleTime(toInt(entry.get(ATTR_PWD_MAX_IDLE)));
    user.setEnabled(!toBoolean(entry.get(ATTR_PWD_LOCKOUT)));
    user.setAuthorities(createAuthorities());

    return user;
  }

  private List<Authority> createAuthorities() {

    List<Authority> authorities = new ArrayList<>();

    authorities.add(new WritePermission());
    authorities.add(new ConcurrentLoginPermission(
            configuration.getMaxConcurrentLogins(),
            configuration.getMaxConcurrentLoginsPerIp()));
    authorities.add(new TransferRatePermission(
            configuration.getDownloadRate(),
            configuration.getUploadRate()));

    return authorities;
  }

  private boolean toBoolean(final Attribute attribute)
          throws LdapInvalidAttributeValueException {

    return Boolean.parseBoolean(toString(attribute));
  }

  private int toInt(final Attribute attribute)
          throws LdapInvalidAttributeValueException {

    return Integer.parseInt(toString(attribute));
  }

  private String toString(final Attribute attribute)
          throws LdapInvalidAttributeValueException {

    return attribute.getString();
  }

  private String toString(final int value) {

    return String.valueOf(value);
  }

  private String toString(final boolean value) {

    return String.valueOf(value);
  }
}
