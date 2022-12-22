/*
 * This module is DANGEROUS: It is writing debugging information about the login process into /tmp/jrl.log
 */
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.apache.commons.codec.digest.Md5Crypt;

/**
 * Debugging Login Module to see what is used to authenticate against the database
 */
public class DBDebugLoginDangerous extends SimpleLogin
{
	protected String                dbDriver;
	protected String                dbURL;
	protected String                dbUser;
	protected String                dbPassword;
	protected String                userTable;
	protected String                userColumn;
	protected String                passColumn;
	protected String                saltColumn;
	protected String                where;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	protected synchronized Vector validateUser(String username, char password[]) throws LoginException
	{
		ResultSet rsu = null, rsr = null;
		Connection con = null;
		PreparedStatement psu = null;

        Logger logger = Logger.getLogger(DBLoginDebug.class.getName());
        FileHandler fh;
        try
        {
                fh = new FileHandler("/tmp/jrl.log");
        }catch (IOException ex){
                throw new FailedLoginException(ex.getMessage());
        }
        SimpleFormatter formatter = new SimpleFormatter();
        fh.setFormatter(formatter);
        logger.addHandler(fh);

		try
		{
			Class.forName(dbDriver);

			if (dbUser != null)
			   con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
			else
			   con = DriverManager.getConnection(dbURL);

            String stmt = "SELECT " + passColumn + (!saltColumn.equals("") ? ("," + saltColumn) : "")  + " FROM " +
                userTable + " WHERE " + userColumn + "=?" + where;

            logger.log(Level.SEVERE, stmt);

			psu = con.prepareStatement(stmt);

			psu.setString(1, username);
			rsu = psu.executeQuery();
			if (!rsu.next()) throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
			String upwd = rsu.getString(1);
                        String salt = (!saltColumn.equals("") ? rsu.getString(2) : "");
                                               
                        String tpwd = new String();
                        
                        String hashingAlg = getOption("hashAlgorithm", null);
                                       
                        if (hashingAlg != null && (!hashingAlg.isEmpty())) {

			    if (hashingAlg.toLowerCase().equals("bcrypt")) {
					tpwd = new String(password);
					String upwd2 = "$2a" + upwd.substring(3);
					if (!passwordEncoder.matches(tpwd, upwd2))
						throw new FailedLoginException(getOption("errorMessage", "Invalid details (b)"));
				} else if (hashingAlg.toLowerCase().equals("md5crypt")) {
					tpwd = new String(password);
					/* Check the password */
					if (!upwd.equals(Md5Crypt.md5Crypt(tpwd.getBytes(), upwd))) throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
				} else {
                               try {
                                   tpwd = this.hash(new String(password) + salt, hashingAlg);
                                   logger.log(Level.SEVERE, new String(password) + " => " + tpwd);
                               } catch (NoSuchAlgorithmException ex) {
                                   Logger.getLogger(DBLogin.class.getName()).log(Level.SEVERE, null, ex);
                               }
                               /* Check the password */                        
                               if (!upwd.toLowerCase().equals(tpwd.toLowerCase())) throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
			    }
                        } else {
		            tpwd = new String(password);
                            if (!upwd.equals(tpwd)) throw new FailedLoginException(getOption("errorMessage", "Invalid details"));
                        }

			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		}
		catch (ClassNotFoundException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
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

		userTable    = getOption("userTable",    "User");
		userColumn   = getOption("userColumn", "user_name");
		passColumn   = getOption("passColumn",    "user_passwd");
                saltColumn   = getOption("saltColumn", "");
		where        = getOption("where",        "");
		if (null != where && where.length() > 0)
			where = " AND " + where;
		else
			where = "";
	}
        
        String hash(String input, String hashingAlg) throws NoSuchAlgorithmException {
            MessageDigest mDigest = MessageDigest.getInstance(hashingAlg);
            byte[] result = mDigest.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < result.length; i++) {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
         
        return sb.toString();
    }
}
