/*
 * Copyright (c) 2002-2009, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.mylutece.modules.cas.authentication;

import java.util.ArrayList;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.authentication.AttributePrincipal;

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.plugins.mylutece.modules.cas.service.CASPlugin;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

/**
 * The class provides an implementation of the inherited abstract class
 * PortalAuthentication based on CAS
 * 
 */
public class CASAuthentication extends PortalAuthentication {
	// //////////////////////////////////////////////////////////////////////////////////////////////
	// Constants
	private static final String AUTH_SERVICE_NAME = AppPropertiesService
			.getProperty("mylutece-cas.service.name");
	private static final String DEFAULT_ROLE_NAME = AppPropertiesService
			.getProperty("mylutece-cas.role.name");
	private static final String ATTRIBUTE_KEY_DIRECTION = AppPropertiesService
			.getProperty("mylutece-cas.attributeKeyDirection");
	private static final String ATTRIBUTE_KEY_USERNAME = AppPropertiesService
			.getProperty("mylutece-cas.attributeKeyUsername");

	/**
	 * Constructor
	 */
	public CASAuthentication() {
		super();
	}

	/**
	 * Gets the Authentication service name
	 * 
	 * @return The name of the authentication service
	 */
	public String getAuthServiceName() {
		return AUTH_SERVICE_NAME;
	}

	/**
	 * Gets the Authentication type
	 * 
	 * @param request
	 *            The HTTP request
	 * @return The type of authentication
	 */
	public String getAuthType(HttpServletRequest request) {
		return HttpServletRequest.BASIC_AUTH;
	}

	public LuteceUser login(String strUserName, String strUserPassword,
			HttpServletRequest request) throws LoginException {

		return getHttpAuthenticatedUser(request);

	}

	/**
	 * Returns a Lutece user object if the user is already authenticated by the
	 * WSSO
	 * 
	 * @param request
	 *            The HTTP request
	 * @return Returns A Lutece User
	 */
	public LuteceUser getHttpAuthenticatedUser(HttpServletRequest request) {
		// String strCASUserLogin = (String) request.getSession( ).getAttribute(
		// CASFilter.CAS_FILTER_USER );
		AttributePrincipal principal = (AttributePrincipal) request
				.getUserPrincipal();
		if (principal != null) {
			String strDirection = (String) principal.getAttributes().get(
					ATTRIBUTE_KEY_DIRECTION);
			String strCASUserLogin = (String) principal.getAttributes().get(
					ATTRIBUTE_KEY_USERNAME);
			if (strCASUserLogin != null) {
				CASUser user = new CASUser(strCASUserLogin, this);
				ArrayList<String> arrayRoles = new ArrayList<String>();
				arrayRoles.add(DEFAULT_ROLE_NAME);
				arrayRoles.add(strDirection);
				user.setRoles(arrayRoles);

				return user;
			}
		}
		return null;

	}

	/**
	 * This methods logout the user
	 * 
	 * @param user
	 *            The user
	 */
	public void logout(LuteceUser user) {
	}

	public String[] getRolesByUser(LuteceUser user) {
		return user.getRoles();
	}

	/**
	 * This method returns an anonymous Lutece user
	 * 
	 * @return An anonymous Lutece user
	 */
	public LuteceUser getAnonymousUser() {
		return new CASUser(LuteceUser.ANONYMOUS_USERNAME, this);
	}

	/**
	 * Checks that the current user is associated to a given role
	 * 
	 * @param user
	 *            The user
	 * @param request
	 *            The HTTP request
	 * @param strRole
	 *            The role name
	 * @return Returns true if the user is associated to the role, otherwise
	 *         false
	 */
	public boolean isUserInRole(LuteceUser user, HttpServletRequest request,
			String strRole) {

		if ((user == null) || (strRole == null)) {
			return false;
		}

		String[] roles = user.getRoles();

		if (roles != null) {
			for (int i = 0; i < roles.length; i++) {
				if (strRole.equals(roles[i])) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Returns true
	 * @return true
	 */
	public boolean isExternalAuthentication() {
		return true;

	}

	/**
	 * 
	 *{@inheritDoc}
	 */
	public String getName()
	{
		return CASPlugin.PLUGIN_NAME;
	}

	/**
	 * 
	 *{@inheritDoc}
	 */
	public String getPluginName()
	{
		return CASPlugin.PLUGIN_NAME;
	}

}
