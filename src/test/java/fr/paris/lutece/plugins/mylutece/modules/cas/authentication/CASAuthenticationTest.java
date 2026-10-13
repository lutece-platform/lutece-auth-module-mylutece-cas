/*
 * Copyright (c) 2002-2026, Mairie de Paris
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apereo.cas.client.authentication.AttributePrincipalImpl;
import org.junit.jupiter.api.Test;

import fr.paris.lutece.plugins.mylutece.modules.cas.service.CASService;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.test.LuteceTestCase;
import fr.paris.lutece.test.mocks.MockHttpServletRequest;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Tests the user built from a CAS principal.
 */
public class CASAuthenticationTest extends LuteceTestCase
{
    @Inject
    @Named( CASService.AUTHENTICATION_BEAN_NAME )
    private CASAuthentication _authentication;

    /**
     * A principal carrying the user name attribute gives a user with the default role, the CAS roles and the mapped
     * attributes.
     */
    @Test
    public void testUserFromPrincipal( )
    {
        Map<String, Object> attributes = new HashMap<>( );
        attributes.put( "uid", "jdupont" );
        attributes.put( "service", List.of( "DSIN", "DAC" ) );
        attributes.put( "prenom", "Jean" );
        attributes.put( "nom", "Dupont" );
        attributes.put( "mail", "jean.dupont@paris.fr" );

        LuteceUser user = _authentication.getHttpAuthenticatedUser( requestWith( new AttributePrincipalImpl( "cas-jdupont", attributes ) ) );

        assertEquals( "jdupont", user.getName( ), "user name read from the uid attribute" );
        assertArrayEquals( new String [ ] {
                "parisien", "DSIN", "DAC"
        }, user.getRoles( ), "default role then the CAS roles" );
        assertEquals( "Jean", user.getUserInfo( LuteceUser.NAME_GIVEN ), "prenom mapped to user.name.given" );
        assertEquals( "Dupont", user.getUserInfo( LuteceUser.NAME_FAMILY ), "nom mapped to user.name.family" );
        assertEquals( "DSIN,DAC", user.getUserInfo( "user.business-info.organizationUnit" ), "multivalued attribute joined" );
        assertEquals( "jean.dupont@paris.fr", user.getUserInfo( "mail" ), "unmapped attribute kept under its CAS name" );
        assertEquals( "Lutece CAS Authentication Service", user.getAuthenticationService( ), "user bound to the CAS authentication" );
    }

    /**
     * A principal without the user name attribute gives no user.
     */
    @Test
    public void testPrincipalWithoutUserName( )
    {
        Map<String, Object> attributes = new HashMap<>( );
        attributes.put( "prenom", "Jean" );

        assertNull( _authentication.getHttpAuthenticatedUser( requestWith( new AttributePrincipalImpl( "cas-jdupont", attributes ) ) ),
                "no user without the uid attribute" );
    }

    /**
     * A request without principal gives no user.
     */
    @Test
    public void testNoPrincipal( )
    {
        assertNull( _authentication.getHttpAuthenticatedUser( requestWith( null ) ), "no user without CAS principal" );
    }

    /**
     * The anonymous user and the names of the authentication.
     */
    @Test
    public void testAnonymousAndNames( )
    {
        assertEquals( LuteceUser.ANONYMOUS_USERNAME, _authentication.getAnonymousUser( ).getName( ), "anonymous user name" );
        assertEquals( CASService.PLUGIN_NAME, _authentication.getName( ), "authentication name" );
        assertEquals( "Lutece CAS Authentication Service", _authentication.getAuthServiceName( ), "service name from the properties" );
        assertTrue( _authentication.isExternalAuthentication( ), "CAS is an external authentication" );
    }

    /**
     * Builds a request carrying a principal.
     *
     * @param principal
     *            the principal, or null
     * @return the request
     */
    private static HttpServletRequest requestWith( Principal principal )
    {
        return new HttpServletRequestWrapper( new MockHttpServletRequest( ) )
        {
            @Override
            public Principal getUserPrincipal( )
            {
                return principal;
            }
        };
    }
}
