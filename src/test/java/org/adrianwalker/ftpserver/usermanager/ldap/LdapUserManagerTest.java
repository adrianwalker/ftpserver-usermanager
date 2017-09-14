package org.adrianwalker.ftpserver.usermanager.ldap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.ValidatingPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.ftpserver.ftplet.AuthenticationFailedException;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.User;
import org.apache.ftpserver.usermanager.UsernamePasswordAuthentication;
import org.apache.ftpserver.usermanager.impl.BaseUser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = {
  @CreateTransport(protocol = "LDAP", port = 10389)
})
@ApplyLdifFiles("testuser.ldif")
public final class LdapUserManagerTest extends AbstractLdapTestUnit {

  public static final String HOST = "localhost";
  public static final int PORT = 10389;
  public static final String NAME = "uid=admin,ou=system";
  public static final String CREDENTIALS = "secret";
  public static final long TIMEOUT = 1000 * 60 * 3;
  public static final int MAX_IDLE = 20;
  public static final int MAX_ACTIVE = 200;

  private static final String USER_BASE_DN = "ou=users,ou=system";
  private static final String USERNAME = "testuser";
  private static final String PASSWORD = "password";
  private static final String HOME_DIRECTORY = "/testuser";
  private static final int MAX_IDLE_TIMEOUT = 1800;

  private LdapConnectionTemplate ldapConnectionTemplate;

  @Before
  public void before() {

    LdapConnectionConfig config = new LdapConnectionConfig();
    config.setLdapHost(HOST);
    config.setLdapPort(PORT);
    config.setName(NAME);
    config.setCredentials(CREDENTIALS);

    GenericObjectPool.Config poolConfig = new GenericObjectPool.Config();
    poolConfig.maxActive = MAX_ACTIVE;
    poolConfig.maxIdle = MAX_IDLE;

    DefaultLdapConnectionFactory ldapConnectionFactory = new DefaultLdapConnectionFactory(config);
    ldapConnectionFactory.setTimeOut(TIMEOUT);
    ValidatingPoolableLdapConnectionFactory poolableLdapConnectionFactory
            = new ValidatingPoolableLdapConnectionFactory(ldapConnectionFactory);
    LdapConnectionPool ldapPool = new LdapConnectionPool(poolableLdapConnectionFactory, poolConfig);
    ldapConnectionTemplate = new LdapConnectionTemplate(ldapPool);
  }

  @Test
  public void testGetUserByName() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    User user = ldapUserManager.getUserByName(USERNAME);

    assertTrue(user.getEnabled());
    assertEquals(HOME_DIRECTORY, user.getHomeDirectory());
    assertEquals(MAX_IDLE_TIMEOUT, user.getMaxIdleTime());

    user = ldapUserManager.getUserByName("foobar");
    assertNull(user);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetUserByNameIllegalArgument() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.getUserByName(null);
  }

  @Test
  public void testGetAllUserNames() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    String[] usernames = ldapUserManager.getAllUserNames();

    assertArrayEquals(new String[]{"testuser"}, usernames);
  }

  @Test
  public void testSaveDelete() throws FtpException {

    String name = "deleteme";

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    assertFalse(ldapUserManager.doesExist(name));

    BaseUser user = new BaseUser();
    user.setName(name);
    user.setHomeDirectory("/deleteme");
    user.setMaxIdleTime(MAX_IDLE_TIMEOUT);
    user.setEnabled(true);
    user.setAuthorities(Collections.EMPTY_LIST);

    ldapUserManager.save(user);
    assertTrue(ldapUserManager.doesExist(name));

    ldapUserManager.delete(name);
    assertFalse(ldapUserManager.doesExist(name));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSaveIllegalArgument() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.save(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDeleteIllegalArgument() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.delete(null);
  }

  @Test
  public void testDoesExist() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    assertTrue(ldapUserManager.doesExist(USERNAME));
    assertFalse(ldapUserManager.doesExist("foobar"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDoesExistIllegalArgument() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.doesExist(null);
  }

  @Test
  public void testAuthenticate() throws FtpException {

    UsernamePasswordAuthentication auth = new UsernamePasswordAuthentication(USERNAME, PASSWORD);

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    User user = ldapUserManager.authenticate(auth);

    assertTrue(user.getEnabled());
    assertEquals(HOME_DIRECTORY, user.getHomeDirectory());
    assertEquals(MAX_IDLE_TIMEOUT, user.getMaxIdleTime());
  }

  @Test(expected = AuthenticationFailedException.class)
  public void testAuthentionFailed() throws FtpException {

    UsernamePasswordAuthentication auth = new UsernamePasswordAuthentication("foobar", "foobar");

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.authenticate(auth);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAuthenticateIllegalArgument() throws FtpException {

    LdapUserManager ldapUserManager = new LdapUserManager(ldapConnectionTemplate, USER_BASE_DN);
    ldapUserManager.authenticate(null);
  }
}
