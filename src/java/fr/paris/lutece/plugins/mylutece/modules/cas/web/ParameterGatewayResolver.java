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
package fr.paris.lutece.plugins.mylutece.modules.cas.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;

/**
 * This class is similar to the DefaultGatewayResolverImpl, but it adds a parameter
 * on the query string to be able to detect browsers with cookies disabled.
 * When cookies are disabled, an attribute is set on the request so that subsequent
 * treatments are able to act on that (display an error message, for instance)
 */
public class ParameterGatewayResolver implements GatewayResolver {

	public static final String PARAM_GATEWAY = "g";
	public static final String ATTR_SUPPORTS_COOKIES = "mylutece-cas.supports-cookies";
	private static final String PARAM_YES = "yes";

	@Override
	public boolean hasGatewayedAlready( HttpServletRequest request,
			String serviceUrl )
	{
		final HttpSession session = request.getSession( false );
		
		if ( session == null )
		{
			if ( request.getParameter( PARAM_GATEWAY ) != null )
			{
				// we were gatewayed, but it was not stored in the session
				// cookies must be blocked
				request.setAttribute( ATTR_SUPPORTS_COOKIES, Boolean.FALSE );
				return true;
			}
			return false;
		}
		
		final boolean result = session.getAttribute( DefaultGatewayResolverImpl.CONST_CAS_GATEWAY ) != null;
		session.removeAttribute( DefaultGatewayResolverImpl.CONST_CAS_GATEWAY );
		
		if ( result )
		{
			session.setAttribute( ATTR_SUPPORTS_COOKIES, Boolean.TRUE );
		}
		
		return result;
	}

	@Override
	public String storeGatewayInformation( HttpServletRequest request,
			String serviceUrl )
	{
		HttpSession session = request.getSession( true );
		session.setAttribute( DefaultGatewayResolverImpl.CONST_CAS_GATEWAY, PARAM_YES );
		if ( session.getAttribute( ATTR_SUPPORTS_COOKIES ) == null )
		{
			return serviceUrl + (serviceUrl.indexOf( "?" ) != -1 ? "&" : "?" ) + PARAM_GATEWAY + "=t";
		}
		return serviceUrl;
	}

}
