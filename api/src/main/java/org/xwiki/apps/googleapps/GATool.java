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

import org.xwiki.script.service.ScriptServiceManager;

import com.xpn.xwiki.api.Context;
import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.api.XWiki;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;

public class GATool
{
    public boolean useCookies = false;
    public boolean skipLoginPage = false;
    public boolean authWithCookies = false;
    public int cookiesTTL = 0;

    public String APPNAME,
            CLIENTID,
            SECRET,
            SCOPE,
            DOMAIN,
            AUTH_PAGE = "GoogleApps.OAuth",
            DATA_DIR = "googleapps",
            REDIRECT_URI;

    // xwiki variables
    public XWiki xwiki;
    public Context context;
    public Document doc;
    public XWikiRequest request;
    public XWikiResponse response;
    public ScriptServiceManager services;
    public String googleUser;

    private GoogleAppsScriptService scriptService;


    public GATool(GoogleAppsScriptService scriptService) {
        this.scriptService = scriptService;
    }

    // TODO keep refactoring




}
