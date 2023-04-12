// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package relationalLogin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.*;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;

/**
 * Module to authenticate against Postgres crypt()
 *
 */
public class PGCryptLogin extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String                where;

	protected boolean			    debug_unsafe			= false;

	protected synchronized Vector validateUser(String username, char password[]) throws LoginException
	{
		ResultSet rsu = null, rsr = null;
		Connection con = null;
		PreparedStatement psu = null;
        Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

		try
		{
			Class.forName(dbDriver);
			if (dbUser != null)
			   con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
			   con = DriverManager.getConnection(dbURL);

			psu = con.prepareStatement("SELECT " + userColumn + " FROM " + userTable +
									   " WHERE " + userColumn + "=? AND " +
									   passColumn + "=crypt(?, "+passColumn +")" + where);

            String pw = String.valueOf(password);
			psu.setString(1, username);
			psu.setString(2, pw);
			rsu = psu.executeQuery();
			String executedQuery = rsu.getStatement().toString();
			if (debug_unsafe){
			    logger.info("used query: " + executedQuery);
			}
			if (!rsu.next()) throw new FailedLoginException(getOption("errorMessage", "Login Failed"));
            if (debug_unsafe){
			    logger.info("creating principal with username: " + username);
			}
			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		}
		catch (ClassNotFoundException e)
		{
			throw new LoginException("Class not found: (" + e.getMessage() + ")");
		}
		catch (SQLException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
		finally
		{
			try {
				if (rsu != null) rsu.close();
				if (rsr != null) rsr.close();
				if (psu != null) psu.close();
				if (con != null) con.close();
			} catch (Exception e) { }
		}
	}

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
		dbURL = getOption("dbURL", null);
		if (dbURL == null) throw new Error("No database URL specified (dbURL=?)");
		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
		   throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

        debug_unsafe = getOption("debug_unsafe", debug_unsafe);

		userTable    = getOption("userTable",    "User");
		userColumn   = getOption("userColumn", "user_name");
		passColumn   = getOption("passColumn",    "user_passwd");
		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}
}