package com.gitblit.permissions;

import java.util.Collection;
import java.util.List;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.wicket.protocol.http.WebResponse;

import com.gitblit.GitBlitException;
import com.gitblit.models.RegistrantAccessPermission;
import com.gitblit.models.RepositoryModel;
import com.gitblit.models.TeamModel;
import com.gitblit.models.UserModel;

public interface IPermissionManagement {
	public void setup(boolean allowCookieAuthentication, boolean canFederate,
			List<String> federationTokens, boolean checkValidity, String[] oids);

	public UserModel authenticate(String username, char[] password);

	public UserModel authenticate(Cookie[] cookies);

	public UserModel authenticate(HttpServletRequest httpRequest);

	public UserModel authenticate(HttpServletRequest httpRequest,
			boolean requiresCertificate);

	public void setCookie(WebResponse response, UserModel user);

	public void logout(UserModel user);

	public UserModel getUserModel(String username);

	public boolean supportsCookies();

	public List<String> getAllUsernames();

	public List<UserModel> getAllUsers();

	public boolean updateUserModels(List<UserModel> models);

	public List<String> getRepositoryUsers(RepositoryModel repository);

	public boolean setUserAccessPermissions(RepositoryModel repository,
			Collection<RegistrantAccessPermission> permissions);

	public boolean deleteUser(String username);

	public void updateUserModel(String username, UserModel user,
			boolean isCreate) throws GitBlitException;

	public List<String> getAllTeamnames();

	public List<TeamModel> getAllTeams();

	public TeamModel getTeamModel(String teamname);

	public List<RegistrantAccessPermission> getTeamAccessPermissions(
			RepositoryModel repository);

	public boolean setTeamAccessPermissions(RepositoryModel repository,
			Collection<RegistrantAccessPermission> permissions);

	public List<String> getRepositoryTeams(RepositoryModel repository);

	public List<RegistrantAccessPermission> getUserAccessPermissions(
			UserModel user);

	public List<RegistrantAccessPermission> getUserAccessPermissions(
			RepositoryModel repository);

	public void updateTeamModel(String teamname, TeamModel team,
			boolean isCreate) throws GitBlitException;

	public boolean deleteTeam(String teamname);

	public boolean renameRepositoryRole(String repositoryName, String name);

	public boolean deleteRepositoryRole(String repositoryName);

	public List<String> getTeamnamesForRepositoryRole(String role);

	public boolean supportsCredentialChanges(String username);

	public boolean supportsDisplayNameChanges(String username);

	public boolean supportsEmailAddressChanges(String username);

	public boolean supportsTeamMembershipChanges(String username);

	public boolean updateTeamModels(List<TeamModel> models);

	public boolean supportsAddUser();
}
