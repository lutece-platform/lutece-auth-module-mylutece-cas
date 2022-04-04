/*
 * Copyright (c) 2002-2017, Mairie de Paris
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

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.plugins.mylutece.modules.cas.exception.CASAuthenticationException;
import fr.paris.lutece.plugins.mylutece.modules.cas.exception.CASUserKeyEmptyException;
import fr.paris.lutece.plugins.mylutece.modules.cas.exception.CASUserNotAuthorizedException;
import fr.paris.lutece.plugins.mylutece.modules.cas.service.CASPlugin;
import fr.paris.lutece.plugins.mylutece.modules.cas.service.ICASUserKeyService;
import fr.paris.lutece.portal.service.message.SiteMessage;
import fr.paris.lutece.portal.service.message.SiteMessageException;
import fr.paris.lutece.portal.service.message.SiteMessageService;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import org.apache.commons.lang3.StringUtils;

import org.jasig.cas.client.authentication.AttributePrincipal;

import java.io.Serializable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.login.LoginException;

import javax.servlet.http.HttpServletRequest;


/**
 * The class provides an implementation of the inherited abstract class
 * PortalAuthentication based on CAS
 *
 */
public class CASAuthentication extends PortalAuthentication implements Serializable
{
    // //////////////////////////////////////////////////////////////////////////////////////////////
    // Constants

    /**
         *
         */
    private static final long serialVersionUID = -4537783302819258998L;

    /** user roles key */
    private static final String PROPRETY_ATTRIBUTE_ROLES = "mylutece-cas.attributeRoles";

    /** Lutece User Attributs */
    public static final String PROPERTY_USER_MAPPING_ATTRIBUTES = "mylutece-cas.userMappingAttributes";
    public static final String PROPERTY_USER_MANDATORY_ATTRIBUTES = "mylutece-cas.userMandatoryAttributes";
    public static final String PROPERTY_ROLES_ASSOCIATIONS = "mylutece-cas.rolesAssociations";
    public static final String PROPERTY_URL_ERROR_LOGIN_PAGE = "mylutece-cas.urlErrorLoginPage";
    public static final String PROPERTY_BACK_URL_ERROR = "mylutece-cas.backUrlError";
    public static final String PROPERTY_MESSAGE_ERROR_LOGIN = "module.mylutece.cas.message.error.login";

    /** Constants **/
    public static final String CONSTANT_LUTECE_USER_PROPERTIES_PATH = "mylutece-cas.attribute";
    public static final String CONSTANT_MANDATORY_ATTRIBUTE = "mylutece-cas.mandatoryAttribute";
    public static final String CONSTANT_ROLE_ASSOCIATIONS_PATH = "mylutece-cas.roleAssociations";
    public static final String CONSTANT_HTTP = "http://";
    public static final String CONSTANT_HTTPS = "https://";
    private static final String SEPARATOR = ",";
    private String _strAuthServiceName;

    /** default role can be used and will be added to all users */
    private String _strPropertyDefaultRoleName;
    private String _strAttributeKeyUsername;
    private ICASUserKeyService cASUserKeyService;

    /** Attributs */
    private String[] ATTRIBUTE_ROLES;
    private Map<String, String> USER_MANDATORY_ATTRIBUTES;
    private Map<String, List<String>> ROLES_ASSOCIATIONS;
    private Map<String, String> ATTRIBUTE_USER_MAPPING;

    /**
     * Constructor
     */
    public CASAuthentication(  )
    {
        super(  );

        String strAttributes = AppPropertiesService.getProperty( PROPRETY_ATTRIBUTE_ROLES );

        if ( StringUtils.isNotBlank( strAttributes ) )
        {
            ATTRIBUTE_ROLES = strAttributes.split( SEPARATOR );
        }
        else
        {
            ATTRIBUTE_ROLES = new String[0];
        }

        String strUserMappingAttributes = AppPropertiesService.getProperty( PROPERTY_USER_MAPPING_ATTRIBUTES );
        ATTRIBUTE_USER_MAPPING = new HashMap<>(  );

        if ( StringUtils.isNotBlank( strUserMappingAttributes ) )
        {
            String[] tabUserProperties = strUserMappingAttributes.split( SEPARATOR );
            String userPropertie;

            for ( int i = 0; i < tabUserProperties.length; i++ )
            {
                userPropertie = AppPropertiesService.getProperty( CONSTANT_LUTECE_USER_PROPERTIES_PATH + "." +
                        tabUserProperties[i] );

                if ( StringUtils.isNotBlank( userPropertie ) )
                {
                    ATTRIBUTE_USER_MAPPING.put( userPropertie, tabUserProperties[i] );
                }
            }
        }

        String strUserMandatoryAttributes = AppPropertiesService.getProperty( PROPERTY_USER_MANDATORY_ATTRIBUTES );
        USER_MANDATORY_ATTRIBUTES = new HashMap<>(  );

        if ( StringUtils.isNotBlank( strUserMandatoryAttributes ) )
        {
            String[] tabUserMandatoryAttributes = strUserMandatoryAttributes.split( SEPARATOR );
            String userMandatoryAttributes;

            for ( int i = 0; i < tabUserMandatoryAttributes.length; i++ )
            {
                userMandatoryAttributes = AppPropertiesService.getProperty( CONSTANT_MANDATORY_ATTRIBUTE + "." +
                        tabUserMandatoryAttributes[i] + ".value" );
                USER_MANDATORY_ATTRIBUTES.put( tabUserMandatoryAttributes[i], userMandatoryAttributes );
            }
        }

        String strRolesAssociations = AppPropertiesService.getProperty( PROPERTY_ROLES_ASSOCIATIONS );
        ROLES_ASSOCIATIONS = new HashMap<>(  );

        if ( StringUtils.isNotBlank( strRolesAssociations ) )
        {
            String[] tabRolesAssociations = strRolesAssociations.split( SEPARATOR );
            String strRoleAssociations;

            for ( int i = 0; i < tabRolesAssociations.length; i++ )
            {
                strRoleAssociations = AppPropertiesService.getProperty( CONSTANT_ROLE_ASSOCIATIONS_PATH + "." +
                        tabRolesAssociations[i] );

                if ( StringUtils.isNotBlank( strRoleAssociations ) )
                {
                    List<String> listAssociations = Arrays.asList( strRoleAssociations.split( SEPARATOR ) );
                    ROLES_ASSOCIATIONS.put( tabRolesAssociations[i], listAssociations );
                }
            }
        }
    }

    /**
     * Gets the Authentication service name
     *
     * @return The name of the authentication service
     */
    public String getAuthServiceName(  )
    {
        if ( _strAuthServiceName == null )
        {
            _strAuthServiceName = AppPropertiesService.getProperty( "mylutece-cas.service.name" );
        }

        return _strAuthServiceName;
    }

    /**
     * Gets the Authentication type
     *
     * @param request
     *            The HTTP request
     * @return The type of authentication
     */
    public String getAuthType( HttpServletRequest request )
    {
        return HttpServletRequest.BASIC_AUTH;
    }
    
    
    @Override
    public LuteceUser login( String strUserName, String strUserPassword, HttpServletRequest request )
        throws LoginException, LoginRedirectException
    {
    	LuteceUser user=null;
    	try {
    			user=getCasAuthenticatedUser(request);
			} catch (CASAuthenticationException e) {
		
			String strUrlErrorLoginPage = AppPropertiesService.getProperty( PROPERTY_URL_ERROR_LOGIN_PAGE );
            String strBackUrlError = AppPropertiesService.getProperty( PROPERTY_BACK_URL_ERROR );

            if ( StringUtils.isEmpty( strUrlErrorLoginPage ) )
            {
                try
                {
                    SiteMessageService.setMessage( request, PROPERTY_MESSAGE_ERROR_LOGIN, null, " ", null, "",
                        SiteMessage.TYPE_STOP, null, strBackUrlError );
                }
                catch ( SiteMessageException lme )
                {
                    strUrlErrorLoginPage = SiteMessageService.setSiteMessageUrl( AppPathService.getPortalUrl(  ) );
                }
            }

            if ( ( strUrlErrorLoginPage == null ) ||
                    ( !strUrlErrorLoginPage.startsWith( CONSTANT_HTTP ) &&
                    !strUrlErrorLoginPage.startsWith( CONSTANT_HTTPS ) ) )
            {
                strUrlErrorLoginPage = AppPathService.getBaseUrl( request ) + strUrlErrorLoginPage;
            }

            LoginRedirectException ex = new LoginRedirectException( strUrlErrorLoginPage );
            throw ex;
		}

      
        return user;
    }

    /**
     * Returns a Lutece user object if the user is already authenticated by the
     * WSSO
     *
     * @param request
     *            The HTTP request
     * @return Returns A Lutece User
     */
    public LuteceUser getHttpAuthenticatedUser( HttpServletRequest request )
    {
    	LuteceUser user = null;
    	try
    	{
    		user = getCasAuthenticatedUser( request );
		}
    	catch ( CASAuthenticationException e )
    	{
    		AppLogService.error( e.getMessage( ), e );
		}
	
		 
    	return user;
    }
    
    
    
    /**
     * Returns a user object if the user is already authenticated by the
     * Cas
     *
     * @param request
     *            The HTTP request
     * @return Returns A Lutece User
     */
    private LuteceUser getCasAuthenticatedUser( HttpServletRequest request )throws CASAuthenticationException
    {
        AttributePrincipal principal = (AttributePrincipal) request.getUserPrincipal(  );

        if ( principal != null )
        {
            String strCASUserLogin = cASUserKeyService.getKey( principal.getName(  ),
                    principal.getAttributes(  ).get( getAttributeUsernameKey(  ) ) );

            if ( strCASUserLogin != null )
            {
                CASUser user = new CASUser( strCASUserLogin, this );
                List<String> listRoles = new ArrayList<>(  );

                if ( StringUtils.isNotBlank( getDefaultRoleName(  ) ) )
                {
                    listRoles.add( getDefaultRoleName(  ) );
                }

                addUserRoles( principal, listRoles );
                user.setRoles( listRoles );

                addUserAttributes( principal, user );

                if ( !isAuthorized( user ) )
                {
                	AppLogService.debug( "Principal found, but user not Authorized" + principal.getName(  ) );
                    throw new CASUserNotAuthorizedException();
                	
                }
                return user;
            }
            else
            {
                AppLogService.error( "Principal found, but not username attribute can be found for " +
                    principal.getName(  ) );
                throw new CASUserKeyEmptyException();
            }
        }

        return null;
    }
    

    /**
     * Adds user role, according to {@link #ATTRIBUTE_ROLES} keys
     *
     * @param principal
     *            principal
     * @param roles
     *            the roles list
     */
    private void addUserRoles( AttributePrincipal principal, List<String> roles )
    {
        for ( String strAttributeKey : ATTRIBUTE_ROLES )
        {
            Object attributeValue = principal.getAttributes(  ).get( strAttributeKey );

            if ( attributeValue instanceof String )
            {
                roles.add( (String) attributeValue );
                addRolesAssociated( (String) attributeValue, roles );
            }
            else if ( attributeValue instanceof List )
            {
                for ( Object oValue : (List) attributeValue )
                {
                    if ( oValue instanceof String )
                    {
                        roles.add( (String) oValue );
                        addRolesAssociated( (String) oValue, roles );
                    }
                }
            }
        }
    }

    /**
     * Add all principal attributes to the user
     *
     * @param principal
     *            the principal
     * @param user
     *            the user
     */
    private void addUserAttributes( AttributePrincipal principal, CASUser user )
    {
        String strValue;

        for ( Entry<String, Object> entry : ( (Map<String, Object>) principal.getAttributes(  ) ).entrySet(  ) )
        {
            strValue = null;

            if ( entry.getValue(  ) instanceof String )
            {
                strValue = (String) entry.getValue(  );
            }
            else if ( entry.getValue(  ) instanceof List )
            {
                strValue = getValueAttributeMultivalued( (List) entry.getValue(  ) );
            }

            if ( strValue != null )
            {
                if ( ATTRIBUTE_USER_MAPPING.containsKey( entry.getKey(  ) ) )
                {
                    user.setUserInfo( ATTRIBUTE_USER_MAPPING.get( entry.getKey(  ) ), strValue );
                }
                else
                {
                    user.setUserInfo( entry.getKey(  ), strValue );
                }
            }
        }
    }

    /**
     * This methods logout the user
     *
     * @param user
     *            The user
     */
    public void logout( LuteceUser user )
    {
    }

    public String[] getRolesByUser( LuteceUser user )
    {
        return user.getRoles(  );
    }

    /**
     * This method returns an anonymous Lutece user
     *
     * @return An anonymous Lutece user
     */
    public LuteceUser getAnonymousUser(  )
    {
        return new CASUser( LuteceUser.ANONYMOUS_USERNAME, this );
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
    public boolean isUserInRole( LuteceUser user, HttpServletRequest request, String strRole )
    {
        if ( ( user == null ) || ( strRole == null ) )
        {
            return false;
        }

        String[] roles = user.getRoles(  );

        if ( roles != null )
        {
            for ( int i = 0; i < roles.length; i++ )
            {
                if ( strRole.equals( roles[i] ) )
                {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns true
     *
     * @return true
     */
    public boolean isExternalAuthentication(  )
    {
        return true;
    }

    /**
     *
     * {@inheritDoc}
     */
    public String getName(  )
    {
        return CASPlugin.PLUGIN_NAME;
    }

    /**
     *
     * {@inheritDoc}
     */
    public String getPluginName(  )
    {
        return CASPlugin.PLUGIN_NAME;
    }

    public ICASUserKeyService getCASUserKeyService(  )
    {
        return cASUserKeyService;
    }

    public void setCASUserKeyService( ICASUserKeyService cASUserKeyService )
    {
        this.cASUserKeyService = cASUserKeyService;
    }

    /**
     * Get the default role name property
     * @return The default role name property
     */
    private String getDefaultRoleName(  )
    {
        if ( _strPropertyDefaultRoleName == null )
        {
            _strPropertyDefaultRoleName = AppPropertiesService.getProperty( "mylutece-cas.role.name" );
        }

        return _strPropertyDefaultRoleName;
    }

    /**
     * Get the user name key attribute
     * @return The user name key attribute
     */
    private String getAttributeUsernameKey(  )
    {
        if ( _strAttributeKeyUsername == null )
        {
            _strAttributeKeyUsername = AppPropertiesService.getProperty( "mylutece-cas.attributeKeyUsername" );
        }

        return _strAttributeKeyUsername;
    }

    /**
     * Get the value of an attribute multivalued
     * @param value the attribute value
     * @return the value of an attribute multivalued
     */
    private String getValueAttributeMultivalued( List lValues )
    {
        StringBuffer strBuffer = new StringBuffer(  );
        int ncpt = 1;

        for ( Object oValue : lValues )
        {
            if ( oValue instanceof String )
            {
                strBuffer.append( (String) oValue );

                if ( ncpt < lValues.size(  ) )
                {
                    strBuffer.append( SEPARATOR );
                }

                ncpt++;
            }
        }

        return strBuffer.toString(  );
    }

    /**
     * Add in the list of roles the roles associated to the given role passed in parameter
     * @param strRole the role
     * @param roles the roles list
     */
    private void addRolesAssociated( String strRole, List<String> roles )
    {
        if ( ROLES_ASSOCIATIONS.containsKey( strRole ) )
        {
            roles.addAll( ROLES_ASSOCIATIONS.get( strRole ) );
        }
    }

    /**
     * return true if the user  is Authorized to be authenticate depending the mandatory attributes
     * @param user LuteceUser
     * @return true if the user is Authorized to be authenticate depending the mandatory attributes
     */
    private boolean isAuthorized( LuteceUser user )
    {
        if ( !USER_MANDATORY_ATTRIBUTES.isEmpty(  ) )
        {
            for ( Entry<String, String> entry : ( USER_MANDATORY_ATTRIBUTES ).entrySet(  ) )
            {
                if ( ( StringUtils.isEmpty( user.getUserInfo( entry.getKey(  ) ) ) ) ||
                        ( !StringUtils.isEmpty( entry.getValue(  ) ) &&
                        !entry.getValue(  ).equals( user.getUserInfo( entry.getKey(  ) ) ) ) )
                {
                    return false;
                }
            }
        }

        return true;
    }
}
