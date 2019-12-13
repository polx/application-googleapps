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
package org.xwiki.apps.googleapps.internal;

import java.util.Arrays;
import java.util.List;

import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.doc.XWikiDocument;

public class GoogleAppsEventListener implements EventListener
{
    void GoogleAppsEventListener(GoogleAppsManagerImpl manager)
    {
        this.manager = manager;
    }

    GoogleAppsManagerImpl manager;

    @Override
    public String getName()
    {
        return "googleapps.scriptservice";
    }

    @Override
    public List<Event> getEvents()
    {
        return Arrays.asList(new ApplicationReadyEvent(), new DocumentUpdatedEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        boolean applicationStarted = false, configChanged = false;
        if (event instanceof ApplicationReadyEvent) {
            applicationStarted = true;
        }
        if (event instanceof DocumentUpdatedEvent) {
            XWikiDocument document = (XWikiDocument) source;
            DocumentReference configDocRef = manager.getConfigDocRef();
            if (document != null && document.getDocumentReference().compareTo(configDocRef) == 0) {
                configChanged = true;
            }
        }

        if (configChanged) {
            manager.readConfigDoc(null);
        }

        if (applicationStarted || configChanged) {
            try {
                manager.initialize();
            } catch (InitializationException e) {
                e.printStackTrace();
            }
        }
    }
}