package fr.paris.lutece.plugins.mylutece.modules.cas.web;

import java.io.IOException;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import fr.paris.lutece.plugins.mylutece.modules.cas.authentication.CASAuthentication;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.security.SecurityService;
import fr.paris.lutece.portal.service.spring.SpringContextService;
import fr.paris.lutece.portal.service.util.AppLogService;

/**
 * LuteceCASFilter.
 */
public class LuteceCASFilter implements Filter
{

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
    public void doFilter( ServletRequest servletRequest, ServletResponse response, FilterChain chain ) throws IOException, ServletException
    {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        LuteceUser user = SecurityService.getInstance( ).getRegisteredUser( request );
        if (user == null)
        {
            CASAuthentication casAuthentication = (CASAuthentication) SpringContextService.getBean( "mylutece-cas.authentication" );
            try
            {
                user = casAuthentication.login( "", "", request );
            } catch (LoginException e)
            {
                AppLogService.error( e.getMessage( ), e );
            } catch (LoginRedirectException e)
            {
                AppLogService.error( e.getMessage( ), e );
            }

            if (AppLogService.isDebugEnabled( ))
            {
                AppLogService.debug( "User " + user + " logged" );
            }

            SecurityService.getInstance( ).registerUser( request, user );
        }

        chain.doFilter( servletRequest, response );
    }

    /**
     * 
     * {@inheritDoc}
     */
    @Override
    public void init( FilterConfig config ) throws ServletException
    {
        // nothing
    }

}
