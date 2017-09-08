package org.adrianwalker.ftpserver.usermanager.ldap;

import java.util.Collections;
import java.util.Properties;

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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = {
  @CreateTransport(protocol = "LDAP", port = 10389)
})
@ApplyLdifFiles("testuser.ldif")
public final class LdapUserManagerTest extends AbstractLdapTestUnit {

  private static final String USERNAME = "testuser";
  private static final String PASSWORD = "password";
  private static final String HOME_DIRECTORY = "/testuser";
  private static final int MAX_IDLE_TIMEOUT = 1800;

  private LdapUserManager ldapUserManager;

  @Before
  public void before() {

    Properties properties = new Properties();
    ldapUserManager = new LdapUserManager(properties);
  }

  @Test
  public void testGetUserByName() throws FtpException {

    User user = ldapUserManager.getUserByName(USERNAME);

    assertTrue(user.getEnabled());
    assertEquals(HOME_DIRECTORY, user.getHomeDirectory());
    assertEquals(MAX_IDLE_TIMEOUT, user.getMaxIdleTime());

    user = ldapUserManager.getUserByName("foobar");
    assertNull(user);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testGetUserByNameIllegalArgument() throws FtpException {

    ldapUserManager.getUserByName(null);
  }

  @Test
  public void testGetAllUserNames() throws FtpException {

    String[] usernames = ldapUserManager.getAllUserNames();

    assertArrayEquals(new String[]{"testuser"}, usernames);
  }

  @Test
  public void testSaveDelete() throws FtpException {

    String name = "deleteme";

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

    ldapUserManager.save(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDeleteIllegalArgument() throws FtpException {

    ldapUserManager.delete(null);
  }

  @Test
  public void testDoesExist() throws FtpException {

    assertTrue(ldapUserManager.doesExist(USERNAME));
    assertFalse(ldapUserManager.doesExist("foobar"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDoesExistIllegalArgument() throws FtpException {

    ldapUserManager.doesExist(null);
  }

  @Test
  public void testAuthenticate() throws FtpException {

    UsernamePasswordAuthentication auth = new UsernamePasswordAuthentication(USERNAME, PASSWORD);
    User user = ldapUserManager.authenticate(auth);

    assertTrue(user.getEnabled());
    assertEquals(HOME_DIRECTORY, user.getHomeDirectory());
    assertEquals(MAX_IDLE_TIMEOUT, user.getMaxIdleTime());
  }

  @Test(expected = AuthenticationFailedException.class)
  public void testAuthentionFailed() throws FtpException {

    UsernamePasswordAuthentication auth = new UsernamePasswordAuthentication("foobar", "foobar");
    ldapUserManager.authenticate(auth);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAuthenticateIllegalArgument() throws FtpException {

    ldapUserManager.authenticate(null);
  }
}
