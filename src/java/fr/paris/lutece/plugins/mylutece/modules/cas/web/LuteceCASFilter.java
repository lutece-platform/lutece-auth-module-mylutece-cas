/*
 * Copyright (c) 2002-2014, Mairie de Paris
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
package fr.paris.lutece.plugins.mylutece.modules.cas.web;

import fr.paris.lutece.plugins.mylutece.modules.cas.authentication.CASAuthentication;
import fr.paris.lutece.portal.service.message.SiteMessage;
import fr.paris.lutece.portal.service.message.SiteMessageException;
import fr.paris.lutece.portal.service.message.SiteMessageService;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPathService;

import java.io.IOException;
import java.util.Enumeration;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;


/**
 * LuteceCASFilter.
 */
public class LuteceCASFilter implements Filter
{
    
    /**
     * Filter parameter that, if present, indicates that a message should be displayed
     * if cookies are not supported
     */
    private static final String  PARAM_NOCOOKIEMESSAGEKEY  = "noCookieMessageKey";
    /**
     * Message key when cookies are not supported
     */
    private String noCookieMessageKey = null;
    /**
     * Filter parameter that, if present, indicates whether the user should be
     * redirected to remove the gateway parameter from the query
     * string.
     */
    private static final String  PARAM_REDIRECTAFTERGATEWWAY  = "redirectAfterGateway";
    /**
     * Specify whether the filter should redirect the user agent after a
     * successful validation to remove the gateway parameter from the query
     * string.
     */
    private boolean redirectAfterGateway = false;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void destroy(  )
    {
        // nothing
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter( ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain )
        throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        Boolean attrSupportsCookies = ( Boolean ) request.getAttribute( ParameterGatewayResolver.ATTR_SUPPORTS_COOKIES );
        if ( attrSupportsCookies != null && !attrSupportsCookies.booleanValue() && noCookieMessageKey != null )
        {
        	// cookies are blocked
        	try
        	{
                SiteMessageService.setMessage(request, noCookieMessageKey, SiteMessage.TYPE_ERROR);
            } catch ( SiteMessageException e )
        	{
                request.getSession( true ).setAttribute( DefaultGatewayResolverImpl.CONST_CAS_GATEWAY, "yes" );
                response.sendRedirect(
                        response.encodeRedirectURL( AppPathService.getSiteMessageUrl( request ) ) );
                return;
            }	
        }
        if ( redirectAfterGateway && request.getParameter( ParameterGatewayResolver.PARAM_GATEWAY ) != null )
        {
        	String url = constructServiceURL(request);
        	request.getSession( true ).setAttribute( DefaultGatewayResolverImpl.CONST_CAS_GATEWAY, "yes" );
        	response.sendRedirect( response.encodeRedirectURL( url ) );
        	return;
        }
        
        LuteceUser user = SecurityService.getInstance(  ).getRegisteredUser( request );

        if ( user == null )
        {
            CASAuthentication casAuthentication = (CASAuthentication) SpringContextService.getBean( 
                    "mylutece-cas.authentication" );

            try
            {
                user = casAuthentication.login( "", "", request );
            }
            catch ( LoginException e )
            {
                AppLogService.error( e.getMessage(  ), e );
            }
            catch ( LoginRedirectException e )
            {
                AppLogService.error( e.getMessage(  ), e );
            }

            if ( AppLogService.isDebugEnabled(  ) )
            {
                AppLogService.debug( "User " + user + " logged" );
            }

            SecurityService.getInstance(  ).registerUser( request, user );
        }

        chain.doFilter( servletRequest, response );
    }

	/**
	 * Constructs the service URL, removing the gateway parameter
	 * @param request the request
	 * @return the service url
	 */
	private String constructServiceURL(HttpServletRequest request) {
		StringBuffer url = request.getRequestURL( );
		@SuppressWarnings("unchecked")
		Enumeration<String> paramNames = request.getParameterNames( );
		boolean firstParamater = true;
		while ( paramNames.hasMoreElements( ) ) {
			String param = paramNames.nextElement( );
			if ( !param.equals( ParameterGatewayResolver.PARAM_GATEWAY ) )
			{
				if ( firstParamater )
				{
					url.append( '?' );
					firstParamater = false;
				} else {
					url.append('&');
				}
				url.append( param ).append( '=' ).append( request.getParameter( param ) );
			}
		}
		return url.toString();
	}

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void init( FilterConfig config ) throws ServletException
    {
    	noCookieMessageKey = config.getInitParameter( PARAM_NOCOOKIEMESSAGEKEY );
    	String paramRedirect = config.getInitParameter( PARAM_REDIRECTAFTERGATEWWAY );
    	redirectAfterGateway = paramRedirect != null && Boolean.parseBoolean( paramRedirect );
    }
}
