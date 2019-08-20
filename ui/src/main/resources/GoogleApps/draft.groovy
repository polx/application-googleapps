package GoogleApps

import com.xpn.xwiki.api.XWiki

class draft
{

    XWiki xwiki;

    def l = xwiki.getDocument("xx").getxWikiObjects()getObject("GoogleApps.GoogleAppsConfigClass").get("activate");
}
