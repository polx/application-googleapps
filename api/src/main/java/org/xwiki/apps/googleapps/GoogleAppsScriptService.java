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

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.component.manager.ComponentLifecycleException;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.Event;

import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.script.service.ScriptService;
import org.xwiki.configuration.ConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Set of methods accessible to the scripts using the GoogleApps functions.
 * @version $Id$
 */
@Component
@Named("GAScriptService")
@Singleton
public class GoogleAppsScriptService implements ScriptService, EventListener, Initializable, Disposable
{





    //  -----------------------------  Lifecycle ---------------------------

    @Inject
    private Provider<XWikiContext> xwikiContextProvider;

    private GoogleAppsAuthService authService = new GoogleAppsAuthService(this);

    @Inject
    private Logger log;

    @Override
    public String getName()
    {
        return "googleapps.scriptservice";
    }

    @Override
    public void initialize() throws InitializationException
    {
        log.info("GoogleAppsScriptService initting.");
        XWiki xwiki = getXWiki();

        // We do not verify with the context if the plugin is active and if the license is active
        // this will be done by the GoogleAppsAuthService later on, when it is called within a request

        if (xwiki != null) {
            setAuthService(xwiki);
        }
    }

    @Override
    public List<Event> getEvents()
    {
        return Arrays.asList(new ApplicationReadyEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // called on ApplicationReadyEvent
        log.info("Event triggered (ApplicationReadyEvent?): " + event);
        try {
            initialize();
        } catch (InitializationException e) {
            e.printStackTrace();
        }
    }

    BaseObject getConfigDoc(XWikiContext context) throws XWikiException
    {
        DocumentReference ref = new DocumentReference("wiki",
                "GoogleApps","GoogleAppsConfig");
        return context.getWiki().getDocument(ref, context)
                .getFirstObject("GoogleApps.GoogleAppsConfigClass", context);
    }


    public boolean isActive(XWikiContext context) throws XWikiException
    {
        // read GoogleApps.GoogleAppsConfig's first GoogleApps.GoogleAppsConfigClass object
        return 0 != getConfigDoc(context).getIntValue("activate");
    }



    private void setAuthService(XWiki xwiki)
    {
        xwiki.setAuthService(authService);
    }

    // from ActiveDirectorySetupListener

    /**
     * Note that this dispose() will get called when this Extension is uninstalled which is the use case we want to
     * serve. The fact that it'll also be called when XWiki stops is a side effect that is ok.
     *
     * @throws ComponentLifecycleException if things go wrong.
     */
    @Override
    public void dispose() throws ComponentLifecycleException
    {
        XWiki xwiki = getXWiki();
        // XWiki can be null in the case when XWiki has been started and not accessed (no first request done and thus
        // no XWiki object initialized) and then stopped.
        if (xwiki != null) {
            // Unset the Authentication Service (next time XWiki.getAuthService() is called it'll be re-initialized)
            xwiki.setAuthService(null);
        }
    }

    private XWiki getXWiki()
    {
        XWiki result = null;
        XWikiContext xc = this.xwikiContextProvider.get();
        // XWikiContext could be null at startup when the Context Provider has not been initialized yet (it's
        // initialized after the first request).
        if (xc != null) {
            result = xc.getWiki();
        }
        return result;
    }


    // ----------------------------- Google Apps Groovy Tool (request specific) -----------------------------------

    public GATool createTool() {
        GATool gaTool = new GATool(this);
        return gaTool;
    }
}
