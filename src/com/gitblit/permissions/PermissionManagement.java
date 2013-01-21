package com.gitblit.permissions;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.Principal;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.wicket.RequestCycle;
import org.apache.wicket.protocol.http.WebResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gitblit.ConfigUserService;
import com.gitblit.Constants;
import com.gitblit.Constants.AccessPermission;
import com.gitblit.Constants.AccessRestrictionType;
import com.gitblit.Constants.AuthenticationType;
import com.gitblit.Constants.AuthorizationControl;
import com.gitblit.Constants.PermissionType;
import com.gitblit.Constants.RegistrantType;
import com.gitblit.FileUserService;
import com.gitblit.GitBlit;
import com.gitblit.GitBlitException;
import com.gitblit.IStoredSettings;
import com.gitblit.IUserService;
import com.gitblit.Keys;
import com.gitblit.models.RegistrantAccessPermission;
import com.gitblit.models.RepositoryModel;
import com.gitblit.models.TeamModel;
import com.gitblit.models.UserModel;
import com.gitblit.repositories.IRepositoryService;
import com.gitblit.utils.Base64;
import com.gitblit.utils.HttpUtils;
import com.gitblit.utils.StringUtils;
import com.gitblit.utils.X509Utils.X509Metadata;
import com.gitblit.wicket.GitBlitWebSession;

public class PermissionManagement implements IPermissionManagement {

	private boolean checkValidity, canFederate, allowCookieAuthentication;
	private List<String> federationTokens;
	private final Logger logger = LoggerFactory
			.getLogger(PermissionManagement.class);
	private String[] oids;
	private IUserService userService;
	private IRepositoryService repositoryService;

	@SuppressWarnings("deprecation")
	public PermissionManagement(IStoredSettings settings,
			IRepositoryService repositoryService) {
		this.repositoryService = repositoryService;

		String realm = settings.getString(Keys.realm.userService,
				"${baseFolder}/users.properties");

		if (realm.toLowerCase().endsWith(".properties")
				|| realm.toLowerCase().endsWith(".conf")) {
			// File based User Service

			if (realm.toLowerCase().endsWith(".properties")) {
				// v0.5.0 - v0.7.0 properties-based realm file
				this.userService = new FileUserService(new File(realm));
			} else if (realm.toLowerCase().endsWith(".conf")) {
				// v0.8.0+ config-based realm file
				this.userService = new ConfigUserService(new File(realm));
			}

			assert this.userService != null;

			File realmFile = new File(realm);
			if (!realmFile.exists()) {
				// Create the Administrator account for a new realm file
				try {
					realmFile.createNewFile();
				} catch (IOException x) {
					logger.error(MessageFormat.format(
							"COULD NOT CREATE REALM FILE {0}!", realmFile), x);
				}
				UserModel admin = new UserModel("admin");
				admin.password = "admin";
				admin.canAdmin = true;
				admin.excludeFromFederation = true;
				this.userService.updateUserModel(admin);
			}

			if (this.userService instanceof FileUserService) {
				// automatically create a users.conf realm file from the
				// original
				// users.properties file
				File usersConfig = new File(realmFile.getParentFile(),
						"users.conf");
				if (!usersConfig.exists()) {
					logger.info(MessageFormat.format(
							"Automatically creating {0} based on {1}",
							usersConfig.getAbsolutePath(),
							realmFile.getAbsolutePath()));
					ConfigUserService configService = new ConfigUserService(
							usersConfig);
					for (String username : this.userService.getAllUsernames()) {
						UserModel userModel = this.userService
								.getUserModel(username);
						configService.updateUserModel(userModel);
					}
				}
				// issue suggestion about switching to users.conf
				logger.warn("Please consider using \"users.conf\" instead of the deprecated \"users.properties\" file");
			}
		} else {
			// custom user service
			try {
				// check to see if this "file" is a login service class
				Class<?> realmClass = Class.forName(realm);
				this.userService = (IUserService) realmClass.newInstance();
			} catch (Throwable t) {
				logger.error("User Service could not be initialized: " + realm);
			}
		}
	}

	public void setup(boolean allowCookieAuthentication, boolean canFederate,
			List<String> federationTokens, boolean checkValidity, String[] oids) {
		this.allowCookieAuthentication = allowCookieAuthentication;
		this.canFederate = canFederate;
		this.federationTokens = federationTokens;
		this.checkValidity = checkValidity;
		this.oids = oids;
	}

	public UserModel authenticate(String username, char[] password) {
		if (StringUtils.isEmpty(username)) {
			// can not authenticate empty username
			return null;
		}
		String pw = new String(password);
		if (StringUtils.isEmpty(pw)) {
			// can not authenticate empty password
			return null;
		}

		// check to see if this is the federation user
		if (canFederate()) {
			if (username.equalsIgnoreCase(Constants.FEDERATION_USER)) {
				List<String> tokens = getFederationTokens();
				if (tokens.contains(pw)) {
					// the federation user is an administrator
					UserModel federationUser = new UserModel(
							Constants.FEDERATION_USER);
					federationUser.canAdmin = true;
					return federationUser;
				}
			}
		}
		// delegate authentication to the user service
		if (userService == null) {
			return null;
		}
		return userService.authenticate(username, password);
	}

	public UserModel authenticate(Cookie[] cookies) {
		if (supportsCookies()) {
			if (cookies != null && cookies.length > 0) {
				for (Cookie cookie : cookies) {
					if (cookie.getName().equals(Constants.NAME)) {
						String value = cookie.getValue();
						return authenticate(value.toCharArray());
					}
				}
			}
		}
		return null;
	}

	private UserModel authenticate(char[] cookie) {
		return userService.authenticate(cookie);
	}

	/**
	 * Authenticate a user based on HTTP request parameters.
	 * 
	 * Authentication by X509Certificate is tried first and then by cookie.
	 * 
	 * @param httpRequest
	 * @return a user object or null
	 */
	public UserModel authenticate(HttpServletRequest httpRequest) {
		return authenticate(httpRequest, false);
	}

	/**
	 * Authenticate a user based on HTTP request parameters.
	 * 
	 * Authentication by X509Certificate, servlet container principal, cookie,
	 * and BASIC header.
	 * 
	 * @param httpRequest
	 * @param requiresCertificate
	 * @return a user object or null
	 */
	public UserModel authenticate(HttpServletRequest httpRequest,
			boolean requiresCertificate) {
		// try to authenticate by certificate
		// boolean checkValidity =
		// settings.getBoolean(Keys.git.enforceCertificateValidity, true);
		// String [] oids =
		// getStrings(Keys.git.certificateUsernameOIDs).toArray(new String[0]);
		UserModel model = HttpUtils.getUserModelFromCertificate(httpRequest,
				checkValidity(), getOids());
		if (model != null) {
			// grab real user model and preserve certificate serial number
			UserModel user = getUserModel(model.username);
			X509Metadata metadata = HttpUtils
					.getCertificateMetadata(httpRequest);
			if (user != null) {
				flagWicketSession(AuthenticationType.CERTIFICATE);
				logger.info(MessageFormat.format(
						"{0} authenticated by client certificate {1} from {2}",
						user.username, metadata.serialNumber,
						httpRequest.getRemoteAddr()));
				return user;
			} else {
				logger.warn(MessageFormat
						.format("Failed to find UserModel for {0}, attempted client certificate ({1}) authentication from {2}",
								model.username, metadata.serialNumber,
								httpRequest.getRemoteAddr()));
			}
		}

		if (requiresCertificate) {
			// caller requires client certificate authentication (e.g. git
			// servlet)
			return null;
		}

		// try to authenticate by servlet container principal
		Principal principal = httpRequest.getUserPrincipal();
		if (principal != null) {
			UserModel user = getUserModel(principal.getName());
			if (user != null) {
				flagWicketSession(AuthenticationType.CONTAINER);
				logger.info(MessageFormat
						.format("{0} authenticated by servlet container principal from {1}",
								user.username, httpRequest.getRemoteAddr()));
				return user;
			} else {
				logger.warn(MessageFormat
						.format("Failed to find UserModel for {0}, attempted servlet container authentication from {1}",
								principal.getName(),
								httpRequest.getRemoteAddr()));
			}
		}

		// try to authenticate by cookie
		if (allowCookieAuthentication()) {
			UserModel user = authenticate(httpRequest.getCookies());
			if (user != null) {
				flagWicketSession(AuthenticationType.COOKIE);
				logger.info(MessageFormat.format(
						"{0} authenticated by cookie from {1}", user.username,
						httpRequest.getRemoteAddr()));
				return user;
			}
		}

		// try to authenticate by BASIC
		final String authorization = httpRequest.getHeader("Authorization");
		if (authorization != null && authorization.startsWith("Basic")) {
			// Authorization: Basic base64credentials
			String base64Credentials = authorization
					.substring("Basic".length()).trim();
			String credentials = new String(Base64.decode(base64Credentials),
					Charset.forName("UTF-8"));
			// credentials = username:password
			final String[] values = credentials.split(":", 2);

			if (values.length == 2) {
				String username = values[0];
				char[] password = values[1].toCharArray();
				UserModel user = authenticate(username, password);
				if (user != null) {
					flagWicketSession(AuthenticationType.CREDENTIALS);
					logger.info(MessageFormat
							.format("{0} authenticated by BASIC request header from {1}",
									user.username, httpRequest.getRemoteAddr()));
					return user;
				} else {
					logger.warn(MessageFormat
							.format("Failed login attempt for {0}, invalid credentials ({1}) from {2}",
									username, credentials,
									httpRequest.getRemoteAddr()));
				}
			}
		}
		return null;
	}

	protected void flagWicketSession(AuthenticationType authenticationType) {
		RequestCycle requestCycle = RequestCycle.get();
		if (requestCycle != null) {
			// flag the Wicket session, if this is a Wicket request
			GitBlitWebSession session = GitBlitWebSession.get();
			session.authenticationType = authenticationType;
		}
	}

	/**
	 * Sets a cookie for the specified user.
	 * 
	 * @param response
	 * @param user
	 */
	public void setCookie(WebResponse response, UserModel user) {
		if (userService == null) {
			return;
		}
		if (userService.supportsCookies()) {
			Cookie userCookie;
			if (user == null) {
				// clear cookie for logout
				userCookie = new Cookie(Constants.NAME, "");
			} else {
				// set cookie for login
				String cookie = userService.getCookie(user);
				if (StringUtils.isEmpty(cookie)) {
					// create empty cookie
					userCookie = new Cookie(Constants.NAME, "");
				} else {
					// create real cookie
					userCookie = new Cookie(Constants.NAME, cookie);
					userCookie.setMaxAge(Integer.MAX_VALUE);
				}
			}
			userCookie.setPath("/");
			response.addCookie(userCookie);
		}
	}

	/**
	 * Logout a user.
	 * 
	 * @param user
	 */
	public void logout(UserModel user) {
		if (userService == null) {
			return;
		}
		userService.logout(user);
	}

	/**
	 * Retrieve the user object for the specified username.
	 * 
	 * @see IUserService.getUserModel(String)
	 * @param username
	 * @return a user object or null
	 */
	public UserModel getUserModel(String username) {
		if (StringUtils.isEmpty(username)) {
			return null;
		}
		// TODO check all registered IUserServices
		UserModel user = userService.getUserModel(username);
		return user;
	}

	public boolean supportsCookies() {
		// TODO check all registered IUserServices
		return false;
	}

	private boolean canFederate() {
		return canFederate;
	}

	// private void setFederationTokens(List<String> federationTokens) {
	// this.federationTokens = federationTokens;
	// }

	private List<String> getFederationTokens() {
		return federationTokens;
	}

	// private void setCheckValidity(boolean checkValidity) {
	// this.checkValidity = checkValidity;
	// }

	private boolean checkValidity() {
		return checkValidity;
	}

	// private void setAllowCookieAuthentication(boolean
	// allowCookieAuthentication) {
	// this.allowCookieAuthentication = allowCookieAuthentication;
	// }

	private boolean allowCookieAuthentication() {
		return allowCookieAuthentication;
	}

	// private void setOids(String [] oids) {
	// this.oids = oids;
	// }

	private String[] getOids() {
		return oids;
	}

	/**
	 * Returns the list of all users available to the login service.
	 * 
	 * @see IUserService.getAllUsernames()
	 * @return list of all usernames
	 */
	public List<String> getAllUsernames() {
		List<String> names = new ArrayList<String>(
				userService.getAllUsernames());
		return names;
	}

	/**
	 * Returns the list of all users available to the login service.
	 * 
	 * @see IUserService.getAllUsernames()
	 * @return list of all usernames
	 */
	public List<UserModel> getAllUsers() {
		List<UserModel> users = userService.getAllUsers();
		return users;
	}

	/**
	 * Updates/writes all specified user objects.
	 * 
	 * @param models
	 *            a list of user models
	 * @return true if update is successful
	 * @since 1.2.0
	 */
	public boolean updateUserModels(List<UserModel> models) {
		return false;
	}

	/**
	 * Returns the list of all users who have an explicit access permission for
	 * the specified repository.
	 * 
	 * @see IUserService.getUsernamesForRepositoryRole(String)
	 * @param repository
	 * @return list of all usernames that have an access permission for the
	 *         repository
	 */
	public List<String> getRepositoryUsers(RepositoryModel repository) {
		return userService.getUsernamesForRepositoryRole(repository.name);
	}

	/**
	 * Sets the access permissions to the specified repository for the specified
	 * users.
	 * 
	 * @param repository
	 * @param permissions
	 * @return true if the user models have been updated
	 */
	public boolean setUserAccessPermissions(RepositoryModel repository,
			Collection<RegistrantAccessPermission> permissions) {
		List<UserModel> users = new ArrayList<UserModel>();
		for (RegistrantAccessPermission up : permissions) {
			if (up.mutable) {
				// only set editable defined permissions
				UserModel user = getUserModel(up.registrant);
				user.setRepositoryPermission(repository.name, up.permission);
				users.add(user);
			}
		}
		return updateUserModels(users);
	}

	/**
	 * Delete the user object with the specified username
	 * 
	 * @see IUserService.deleteUser(String)
	 * @param username
	 * @return true if successful
	 */
	public boolean deleteUser(String username) {
		if (StringUtils.isEmpty(username)) {
			return false;
		}
		return userService.deleteUser(username);
	}

	/**
	 * Adds/updates a complete user object keyed by username. This method allows
	 * for renaming a user.
	 * 
	 * @see IUserService.updateUserModel(String, UserModel)
	 * @param username
	 * @param user
	 * @param isCreate
	 * @throws GitBlitException
	 */
	public void updateUserModel(String username, UserModel user,
			boolean isCreate) throws GitBlitException {
		if (!username.equalsIgnoreCase(user.username)) {
			if (userService.getUserModel(user.username) != null) {
				throw new GitBlitException(
						MessageFormat
								.format("Failed to rename ''{0}'' because ''{1}'' already exists.",
										username, user.username));
			}

			// rename repositories and owner fields for all repositories
			for (RepositoryModel model : repositoryService
					.getRepositoryModels(user)) {
				if (model.isUsersPersonalRepository(username)) {
					// personal repository
					model.addRepoAdministrator(user.username);
					String oldRepositoryName = model.name;
					model.name = "~" + user.username
							+ model.name.substring(model.projectPath.length());
					model.projectPath = "~" + user.username;
					repositoryService.updateRepositoryModel(oldRepositoryName,
							model, false);
				} else if (model.isRepoAdministrator(username)) {
					// common/shared repo
					model.addRepoAdministrator(user.username);
					repositoryService.updateRepositoryModel(model.name, model,
							false);
				}
			}
		}
		if (!userService.updateUserModel(username, user)) {
			throw new GitBlitException(isCreate ? "Failed to add user!"
					: "Failed to update user!");
		}
	}

	/**
	 * Returns the list of available teams that a user or repository may be
	 * assigned to.
	 * 
	 * @return the list of teams
	 */
	public List<String> getAllTeamnames() {
		List<String> teams = new ArrayList<String>(
				userService.getAllTeamNames());
		return teams;
	}

	/**
	 * Returns the list of available teams that a user or repository may be
	 * assigned to.
	 * 
	 * @return the list of teams
	 */
	public List<TeamModel> getAllTeams() {
		List<TeamModel> teams = userService.getAllTeams();
		return teams;
	}

	/**
	 * Returns the TeamModel object for the specified name.
	 * 
	 * @param teamname
	 * @return a TeamModel object or null
	 */
	public TeamModel getTeamModel(String teamname) {
		return userService.getTeamModel(teamname);
	}

	/**
	 * Returns the list of teams and their access permissions for the specified
	 * repository including the source of the permission such as the admin flag
	 * or a regular expression.
	 * 
	 * @param repository
	 * @return a list of RegistrantAccessPermissions
	 */
	public List<RegistrantAccessPermission> getTeamAccessPermissions(
			RepositoryModel repository) {
		List<RegistrantAccessPermission> list = new ArrayList<RegistrantAccessPermission>();
		for (TeamModel team : userService.getAllTeams()) {
			RegistrantAccessPermission ap = team
					.getRepositoryPermission(repository);
			if (ap.permission.exceeds(AccessPermission.NONE)) {
				list.add(ap);
			}
		}
		Collections.sort(list);
		return list;
	}

	/**
	 * Sets the access permissions to the specified repository for the specified
	 * teams.
	 * 
	 * @param repository
	 * @param permissions
	 * @return true if the team models have been updated
	 */
	public boolean setTeamAccessPermissions(RepositoryModel repository,
			Collection<RegistrantAccessPermission> permissions) {
		List<TeamModel> teams = new ArrayList<TeamModel>();
		for (RegistrantAccessPermission tp : permissions) {
			if (tp.mutable) {
				// only set explicitly defined access permissions
				TeamModel team = userService.getTeamModel(tp.registrant);
				team.setRepositoryPermission(repository.name, tp.permission);
				teams.add(team);
			}
		}
		return userService.updateTeamModels(teams);
	}

	/**
	 * Returns the list of all teams who have an explicit access permission for
	 * the specified repository.
	 * 
	 * @see IUserService.getTeamnamesForRepositoryRole(String)
	 * @param repository
	 * @return list of all teamnames with explicit access permissions to the
	 *         repository
	 */
	public List<String> getRepositoryTeams(RepositoryModel repository) {
		return userService.getTeamnamesForRepositoryRole(repository.name);
	}

	/**
	 * Returns the effective list of permissions for this user, taking into
	 * account team memberships, ownerships.
	 * 
	 * @param user
	 * @return the effective list of permissions for the user
	 */
	public List<RegistrantAccessPermission> getUserAccessPermissions(
			UserModel user) {
		if (StringUtils.isEmpty(user.username)) {
			// new user
			return new ArrayList<RegistrantAccessPermission>();
		}
		Set<RegistrantAccessPermission> set = new LinkedHashSet<RegistrantAccessPermission>();
		set.addAll(user.getRepositoryPermissions());
		// Flag missing repositories
		for (RegistrantAccessPermission permission : set) {
			if (permission.mutable
					&& PermissionType.EXPLICIT
							.equals(permission.permissionType)) {
				RepositoryModel rm = GitBlit.self().getRepositoryModel(
						permission.registrant);
				if (rm == null) {
					permission.permissionType = PermissionType.MISSING;
					permission.mutable = false;
					continue;
				}
			}
		}

		// TODO reconsider ownership as a user property
		// manually specify personal repository ownerships
		Collection<RepositoryModel> repositoryListCacheValues = repositoryService
				.getRepositoryListCacheValues();
		if (repositoryListCacheValues != null) {
			for (RepositoryModel rm : repositoryListCacheValues) {
				if (rm.isUsersPersonalRepository(user.username)
						|| rm.isRepoAdministrator(user.username)) {
					RegistrantAccessPermission rp = new RegistrantAccessPermission(
							rm.name, AccessPermission.REWIND,
							PermissionType.OWNER, RegistrantType.REPOSITORY,
							null, false);
					// user may be owner of a repository to which they've
					// inherited
					// a team permission, replace any existing perm with owner
					// perm
					set.remove(rp);
					set.add(rp);
				}
			}
		}
		List<RegistrantAccessPermission> list = new ArrayList<RegistrantAccessPermission>(
				set);
		Collections.sort(list);
		return list;
	}

	/**
	 * Returns the list of users and their access permissions for the specified
	 * repository including permission source information such as the team or
	 * regular expression which sets the permission.
	 * 
	 * @param repository
	 * @return a list of RegistrantAccessPermissions
	 */
	public List<RegistrantAccessPermission> getUserAccessPermissions(
			RepositoryModel repository) {
		List<RegistrantAccessPermission> list = new ArrayList<RegistrantAccessPermission>();
		if (AccessRestrictionType.NONE.equals(repository.accessRestriction)) {
			// no permissions needed, REWIND for everyone!
			return list;
		}
		if (AuthorizationControl.AUTHENTICATED
				.equals(repository.authorizationControl)) {
			// no permissions needed, REWIND for authenticated!
			return list;
		}
		// NAMED users and teams
		for (UserModel user : getAllUsers()) {
			RegistrantAccessPermission ap = user
					.getRepositoryPermission(repository);
			if (ap.permission.exceeds(AccessPermission.NONE)) {
				list.add(ap);
			}
		}
		return list;
	}

	/**
	 * Updates the TeamModel object for the specified name.
	 * 
	 * @param teamname
	 * @param team
	 * @param isCreate
	 */
	public void updateTeamModel(String teamname, TeamModel team,
			boolean isCreate) throws GitBlitException {
		if (!teamname.equalsIgnoreCase(team.name)) {
			if (userService.getTeamModel(team.name) != null) {
				throw new GitBlitException(
						MessageFormat
								.format("Failed to rename ''{0}'' because ''{1}'' already exists.",
										teamname, team.name));
			}
		}
		if (!userService.updateTeamModel(teamname, team)) {
			throw new GitBlitException(isCreate ? "Failed to add team!"
					: "Failed to update team!");
		}
	}

	/**
	 * Delete the team object with the specified teamname
	 * 
	 * @see IUserService.deleteTeam(String)
	 * @param teamname
	 * @return true if successful
	 */
	public boolean deleteTeam(String teamname) {
		return userService.deleteTeam(teamname);
	}

	public boolean renameRepositoryRole(String oldRole, String newRole) {
		// TODO do it in all registered IUserServices
		return userService.renameRepositoryRole(oldRole, newRole);
	}

	public boolean deleteRepositoryRole(String role) {
		// TODO do it in all registered IUserServices
		return userService.deleteRepositoryRole(role);
	}

	public List<String> getTeamnamesForRepositoryRole(String role) {
		// TODO do it in all registered IUserServices
		return userService.getTeamnamesForRepositoryRole(role);
	}

	public boolean supportsCredentialChanges(String username) {
		// TODO check all userModels
		return userService.supportsCredentialChanges();
	}

	public boolean supportsDisplayNameChanges(String username) {
		// TODO check all userModels
		return userService.supportsDisplayNameChanges();
	}

	public boolean supportsEmailAddressChanges(String username) {
		// TODO check all userModels
		return userService.supportsEmailAddressChanges();
	}

	public boolean supportsTeamMembershipChanges(String username) {
		// TODO check all userModels
		return userService.supportsTeamMembershipChanges();
	}

	/**
	 * Updates/writes all specified team objects.
	 * 
	 * @param models
	 *            a list of team models
	 * @return true if update is successful
	 * @since 1.2.0
	 */
	public boolean updateTeamModels(List<TeamModel> models) {
		// TODO do it in all registered IUserServices
		return userService.updateTeamModels(models);
	}

	@SuppressWarnings("deprecation")
	public boolean supportsAddUser() {
		// TODO do it in all registered IUserServices
		return (userService != null && (userService instanceof FileUserService || userService instanceof ConfigUserService));
	}

}
