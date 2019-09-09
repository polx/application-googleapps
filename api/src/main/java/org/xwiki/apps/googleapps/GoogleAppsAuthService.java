/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.apps.googleapps;


import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.*;
import com.xpn.xwiki.web.XWikiRequest;

import java.net.URLEncoder;
import java.security.Principal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;

import org.apache.fontbox.encoding.StandardEncoding;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.text.StringUtils;

/**
 * An authenticator that can include a negotiation with the Google Cloud (e.g. Google Drive) services.
 * This authenticator is created, configured and maintained by the GoogleAppsScriptService.
 */
public class GoogleAppsAuthService extends XWikiAuthServiceImpl
{

    GoogleAppsAuthService(GoogleAppsScriptService father) {
        Logger logger = loggerProvider!=null ? loggerProvider.get() : null;
        this.scriptService = father;
        if(logger!=null) logger.info("GoogleApps authentificator - constructed (" + father + ")." );
    }

    @NotNull
    private GoogleAppsScriptService scriptService;

    @Inject
    private Provider<Logger> loggerProvider;

    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        try {
            Logger logger = loggerProvider!=null ? loggerProvider.get() : null;
            if(logger!=null) logger.info("GoogleApps authentificator - checkAuth" );
            if(isLogoutRequest(context)) {
                if(logger!=null) logger.info("caught a logout request" );
                CookieAuthenticationPersistenceStoreTools cookieTools = new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                cookieTools.clear();
                if(logger!=null)  logger.info("cleared cookie" );
            }
            return super.checkAuth(context);
        } catch (InitializationException e) {
            e.printStackTrace();
            throw new XWikiException(e.getMessage(), e);
        }
    }

    /**
     * We cannot authenticate locally since we need to trust the app server for
     * authentication
     *
     * @param username
     * @param password
     * @param context
     * @return
     * @throws XWikiException
     */
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context) throws XWikiException  {
        return super.checkAuth(username, password, rememberme, context);
    }



    /**
     * Redirect user to the login.
     *
     * @param context the xwiki-context of the request
     * @throws XWikiException a wrapped exception
     */
    public void showLogin(XWikiContext context) throws XWikiException {
        Logger logger = loggerProvider!=null ? loggerProvider.get() : null;
        logger.info("GoogleApps authentificator - showLogin" );
        if(!scriptService.isActive(context)) return;
        boolean redirected = false;
        try {
            String url = context.getWiki().getURL("GoogleApps.Login", "view", context);
            if (scriptService.useCookies && scriptService.skipLoginPage) {
                logger.info("skip the login page ");
                XWikiRequest request = context.getRequest();
                CookieAuthenticationPersistenceStoreTools cookieTools = new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                String userCookie = cookieTools.retrieve();
                logger.info("retrieved user from cookie : " + userCookie);
                String savedRequestId = request.getParameter(SavedRequestManager.getSavedRequestIdentifier());
                if (StringUtils.isEmpty(savedRequestId)) {
                    // Save this request
                    savedRequestId = SavedRequestManager.saveRequest(request);
                }
                String sridParameter = SavedRequestManager.getSavedRequestIdentifier() + "=" + savedRequestId;

                StringBuilder redirectBack = new StringBuilder(request.getRequestURI());
                redirectBack.append('?');
                String delimiter = "";
                if (StringUtils.isNotEmpty(request.getQueryString())) {
                    redirectBack.append(request.getQueryString());
                    delimiter = "&";
                }
                if (!request.getParameterMap().containsKey(SavedRequestManager.getSavedRequestIdentifier())) {
                    redirectBack.append(delimiter);
                    redirectBack.append(sridParameter);
                }

                String finalURL = url + "?" + sridParameter + "&xredirect=" +
                        URLEncoder.encode(redirectBack.toString(), "UTF-8");
                logger.info("Redirecting to "  + finalURL);
                redirected = true;
                context.getResponse().sendRedirect(finalURL);
            }
        } catch (Exception e) {
            logger.error("Exception in showLogin : " + e);
        } finally {
            if (!redirected)
                super.showLogin(context);
            logger.info("GoogleApps authentificator - showLogin end" );
        }
    }

    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException {
        try {
            Logger logger = loggerProvider!=null ? loggerProvider.get() : null;
            if(logger!=null) logger.info("GoogleApps authentificator - authenticate" );
            else System.err.println("GoogleApps authentificator - authenticate without logger (" + scriptService + ") !");

            // case of a too early call or deactivated... can only count on local users
            if(scriptService==null || !scriptService.isActive(context)) {
                return super.authenticate(username, password, context);
            }

            HttpSession session = context.getRequest().getSession();
            String xwikiUser = (String) session.getAttribute("googleappslogin");
            if(logger!=null) logger.info("xwikiUser from session : " + xwikiUser);
            // get configuration for authentification with cookies

            // authenticate user from cookie value
            if (xwikiUser == null && scriptService.useCookies && scriptService.authWithCookies) {
                if(logger!=null) logger.info("Authenticate with cookie");
                CookieAuthenticationPersistenceStoreTools cookieTools = new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                String userCookie = cookieTools.retrieve();
                if(logger!=null) logger.info("retrieved user from cookie : " + userCookie);
                String userFullName = "xwiki:" + userCookie;
                XWikiDocument userDoc = context.getWiki().getDocument(userFullName, context);
                xwikiUser = (userCookie == null || userDoc.isNew()) ? null : userFullName ;
                if(logger!=null) logger.info("xwikiUser from cookie : " + xwikiUser);
            }
            if (xwikiUser!=null) {
                if(logger!=null) logger.info("Authenticating user " + xwikiUser);
                return new SimplePrincipal(xwikiUser);
            } else {
                if(logger!=null) logger.info("use default authenticate method for user : " + username);
                return super.authenticate(username, password, context);
            }
        } catch (InitializationException e) {
            e.printStackTrace();
            throw new XWikiException("Trouble at authenticating", e);
        }
    }

    /**
     * @return true if the current request match the configured logout page pattern.
     */
    private boolean isLogoutRequest(XWikiContext context) {
       /* TODO
        def logoutMatcher = context.getWiki().parseGroovyFromPage("xwiki:GoogleApps.RequestMatcherTools", context)
        logoutMatcher.initRequestMatcher(context.getWiki().Param("xwiki.authentication.logoutpage"))
        return logoutMatcher.match(context.getRequest());
        */
       return false;
    }
}
