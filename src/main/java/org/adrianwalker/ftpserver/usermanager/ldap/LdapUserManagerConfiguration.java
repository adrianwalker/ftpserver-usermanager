package org.adrianwalker.ftpserver.usermanager.ldap;

import java.util.Properties;

public final class LdapUserManagerConfiguration extends Properties {

  public static final String CONNECTION_HOST = "ldap.user.manager.connection.host";
  public static final String CONNECTION_PORT = "ldap.user.manager.connection.port";
  public static final String CONNECTION_NAME = "ldap.user.manager.connection.name";
  public static final String CONNECTION_CREDENTIALS = "ldap.user.manager.connection.credentials";
  public static final String CONNECTION_TIMEOUT = "ldap.user.manager.connection.timeout";
  public static final String CONNECTION_MAX_IDLE = "ldap.user.manager.connection.max.active";
  public static final String CONNECTION_MAX_ACTIVE = "ldap.user.manager.connection.max.active";
  public static final String USER_BASE_DN = "ldap.user.manager.user.base.dn";
  public static final String MAX_CONCURRENT_LOGINS = "ldap.user.manager.max.concurrent.logins";
  public static final String MAX_CONCURRENT_LOGINS_PER_IP
          = "ldap.user.manager.max.concurrent.logins.per.ip";
  public static final String DOWNLOAD_RATE = "ldap.user.manager.download.rate ";
  public static final String UPLOAD_RATE = "ldap.user.manager.upload.rate";

  public static final String DEFAULT_CONNECTION_HOST = "localhost";
  public static final int DEFAULT_CONNECTION_PORT = 10389;
  public static final String DEFAULT_CONNECTION_NAME = "uid=admin,ou=system";
  public static final String DEFAULT_CONNECTION_CREDENTIALS = "secret";
  public static final long DEFAULT_CONNECTION_TIMEOUT = 1000 * 60 * 3;
  public static final int DEFAULT_CONNECTION_MAX_IDLE = 20;
  public static final int DEFAULT_CONNECTION_MAX_ACTIVE = 200;
  public static final String DEFAULT_USER_BASE_DN = "ou=users,ou=system";
  public static final int DEFAULT_MAX_CONCURRENT_LOGINS = 2;
  public static final int DEFAULT_MAX_CONCURRENT_LOGINS_PER_IP = 2;
  public static final int DEFAULT_DOWNLOAD_RATE = Integer.MAX_VALUE;
  public static final int DEFAULT_UPLOAD_RATE = Integer.MAX_VALUE;

  public LdapUserManagerConfiguration(final Properties properties) {

    super(properties);
  }

  public String getConnectionHost() {

    return getProperty(CONNECTION_HOST, DEFAULT_CONNECTION_HOST);
  }

  public int getConnectionPort() {

    return toInt(getProperty(CONNECTION_PORT), DEFAULT_CONNECTION_PORT);
  }

  public String getConnectionName() {

    return getProperty(CONNECTION_NAME, DEFAULT_CONNECTION_NAME);
  }

  public String getConnectionCredentials() {

    return getProperty(CONNECTION_CREDENTIALS, DEFAULT_CONNECTION_CREDENTIALS);
  }

  public long getConnectionTimeOut() {

    return toLong(getProperty(CONNECTION_TIMEOUT), DEFAULT_CONNECTION_TIMEOUT);
  }

  public int getConnectionMaxActive() {

    return toInt(getProperty(CONNECTION_MAX_ACTIVE), DEFAULT_CONNECTION_MAX_ACTIVE);
  }

  public int getConnectionMaxIdle() {

    return toInt(getProperty(CONNECTION_MAX_IDLE), DEFAULT_CONNECTION_MAX_IDLE);
  }

  public String getUserBaseDn() {

    return getProperty(USER_BASE_DN, DEFAULT_USER_BASE_DN);
  }

  public int getMaxConcurrentLogins() {

    return toInt(getProperty(MAX_CONCURRENT_LOGINS), DEFAULT_MAX_CONCURRENT_LOGINS);
  }

  public int getMaxConcurrentLoginsPerIp() {

    return toInt(getProperty(MAX_CONCURRENT_LOGINS_PER_IP), DEFAULT_MAX_CONCURRENT_LOGINS_PER_IP);
  }

  public int getDownloadRate() {

    return toInt(getProperty(DOWNLOAD_RATE), DEFAULT_DOWNLOAD_RATE);
  }

  public int getUploadRate() {

    return toInt(getProperty(UPLOAD_RATE), DEFAULT_UPLOAD_RATE);
  }

  public int toInt(final String value, final int defaultValue) {

    return null == value
            ? defaultValue
            : Integer.parseInt(value);
  }

  public long toLong(final String value, final long defaultValue) {

    return null == value
            ? defaultValue
            : Long.parseLong(value);
  }
}
