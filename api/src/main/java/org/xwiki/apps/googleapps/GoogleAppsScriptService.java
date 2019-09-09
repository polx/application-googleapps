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

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.Person;
import com.google.gdata.client.docs.DocsService;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.component.manager.ComponentLifecycleException;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.Event;

import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.inject.Inject;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.script.service.ScriptService;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

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

    @Inject
    private QueryManager queryManager;

    @Inject
    private Environment environment;

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

        try {
            jacksonFactory = JacksonFactory.getDefaultInstance();
            httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        } catch (Exception  e) {
            e.printStackTrace();
            throw new InitializationException("Trouble at initializing", e);
        }
    }

    @Override
    public List<Event> getEvents()
    {
        return Arrays.asList(new ApplicationReadyEvent(), new DocumentUpdatedEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        log.info("Event triggered: " + event);
        if(event instanceof ApplicationReadyEvent) {
            try {
                initialize();
            } catch (InitializationException e) {
                e.printStackTrace();
            }
        } else if(event instanceof DocumentUpdatedEvent) {
            configActiveFlag = null;
        }
    }


    // internals
    private GoogleAppsAuthService authService = null;

    private DocumentReference configDocRef = null, oauthReference = null;
    private ObjectReference configObjRef = null;

    /** A map of hash to full redirects. */
    private Map<String,String> storedStates = new HashMap<String,String>();

    private FileDataStoreFactory dsFactory = null;

    private JacksonFactory jacksonFactory = null;

    private NetHttpTransport httpTransport = null;

    private CloseableHttpClient httpclient = HttpClients.createDefault();


    private BaseObject getConfigDoc(XWikiContext context) throws XWikiException
    {
        if(configDocRef==null) {
            configDocRef = new DocumentReference(context.getWikiId(),
                    "GoogleApps","GoogleAppsConfig");
            configObjRef = new ObjectReference("GoogleApps.GoogleAppsConfigClass", configDocRef);
        }
        XWikiDocument doc = context.getWiki().getDocument(configObjRef, context);
        BaseObject result = doc.getXObject(configObjRef, false, context);
        if(result==null) log.warn("Can't access Config document.");
        return result;
    }

    Boolean configActiveFlag = null;
    Boolean useCookies = null,
            skipLoginPage = null,
            authWithCookies = null;
    String configAppName = null,
            configClientId = null,
            configClientSecret = null,
            configDomain = null;
    List<String> configScopes = null;
    Boolean configScopeUseAvatar = null, configScopeUseDrive = null;
    Long configCookiesTTL = null;



    /** Indicates wether the application is active and licensed.
     * Within a request, this method should always be the first to be called so that the config-object
     * is read and other properties are cached if need be.
     *
     * @param context The context (a page request). */
    public boolean isActive(XWikiContext context) throws XWikiException
    {
        if(configActiveFlag !=null) return configActiveFlag.booleanValue();
            if(log!=null) log.warn("Attempting to fetch Config doc");
            readConfigDoc(context);
            if(configActiveFlag !=null) {
                return configActiveFlag;
            } else
                return false;
    }

    private void readConfigDoc(XWikiContext context) {

        try {
            if(log!=null) log.warn("Attempting to fetch Config doc");
            BaseObject config = getConfigDoc(context);
            if(config!=null) {
                configActiveFlag   = new Boolean(0 != config.getIntValue("activate"));
                useCookies         = new Boolean(0 != config.getIntValue("useCookies"));
                skipLoginPage      = new Boolean(0 != config.getIntValue("skipLoginPage"));
                authWithCookies    = new Boolean(0 != config.getIntValue("authWithCookies"));
                configAppName      = config.getStringValue("appname");
                configClientId     = config.getStringValue("clientid");
                configClientSecret = config.getStringValue("secret");
                configDomain       = config.getStringValue("domain");
                if(configDomain!=null && configDomain.length()==0) configDomain = null;
                configScopes       = Arrays.asList(config.getStringValue("scope").split("\\s"));
                configScopeUseAvatar = configScopes.contains("avatar");
                configScopeUseDrive = configScopes.contains("drive");
                configCookiesTTL = config.getLongValue  ("cookiesTTL");
            }
        } catch (XWikiException e) {
            e.printStackTrace();
            if(log!=null) log.warn("can't fetch Config doc");
        }
    }

    public Date getBuildTime() {
        try {
            Class clazz = getClass();
            String className = clazz.getSimpleName() + ".class";
            String classPath = clazz.getResource(className).toString();
            String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) +
                    "/META-INF/MANIFEST.MF";
            Manifest manifest = new Manifest(new URL(manifestPath).openStream());
            Attributes attr = manifest.getMainAttributes();
            return new Date(Long.parseLong(attr.getValue("Bnd-LastModified")));
        } catch (IOException e) {
            log.warn("Can't read build time.", e);
            throw new RuntimeException("Can't read build time.", e);
        }
    }


    private void setAuthService(XWiki xwiki)
    {
        if(authService==null) authService = new GoogleAppsAuthService(this);
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


    // ----------------------------- Google Apps Tool (mostly request specific) -----------------------------------

    private  String getOAuthUrl() throws XWikiException {
        XWikiContext context = xwikiContextProvider.get();
        DocumentReference oauthReference = new DocumentReference(context.getWikiId(), "GoogleApps","OAuth");
        return getXWiki().getDocument(oauthReference, context).getExternalURL("view", context);
    }

    private DocumentReference getXWikiUserClassRef() {
        XWikiContext context = xwikiContextProvider.get();
        DocumentReference docRef = new DocumentReference("XWiki", "XWiki","XWikiUsers");
        return docRef;
    }

    private String getCurrentXWikiUserName() {
        return xwikiContextProvider.get().getUserReference().getName();
    }

    private DocumentReference createUserReference(String userName) {
        if(userName.startsWith("XWiki.")) userName = userName.substring("XWiki.".length());
        return new DocumentReference("xwiki", "XWiki", userName);
    }

    private DocumentReference gauthClassRef = null;
    private DocumentReference getGoogleAuthClassReference() {
        if(gauthClassRef == null)
            gauthClassRef = new DocumentReference("XWiki", "GoogleApps", "GoogleAppsAuthClass");
        return gauthClassRef;
    }

    public GATool createTool() {
        GATool gaTool = new GATool(this);
        return gaTool;
    }

    /**
     * Build flow and trigger user authorization request.
     * @return the configured flow
     * @throws IOException in case something can't be built
     */
    private GoogleAuthorizationCodeFlow getFlow() throws IOException
    {
        try {
            if(dsFactory==null)
                dsFactory = new FileDataStoreFactory(new File(environment.getPermanentDirectory(), "googleapps"));
            GoogleAuthorizationCodeFlow flow =
                    new GoogleAuthorizationCodeFlow.Builder(
                            httpTransport,
                            jacksonFactory, configClientId, configClientSecret, configScopes)
                            .setDataStoreFactory(dsFactory)
                            .setAccessType("online").setApprovalPrompt("auto")
                            .build();
            return flow;
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("Issue at building Google Authorization Flow.", e);
        }
    }


    /**
     * Exchange an authorization code for OAuth 2.0 credentials.
     *
     * @param authorizationCode Authorization code to exchange for OAuth 2.0
     *     credentials.
     * @return OAuth 2.0 credentials.
     */
    Credential exchangeCode(String authorizationCode) {
        try {
            GoogleAuthorizationCodeFlow flow = getFlow();
            GoogleTokenResponse tokenResponse = flow
                    .newTokenRequest(authorizationCode)
                    .setRedirectUri(getOAuthUrl())
                    .execute();
            log.info("Token: " + tokenResponse);
            return flow.createAndStoreCredential(tokenResponse, getCurrentXWikiUserName());
        } catch (Exception ex) {
            log.warn("An error occurred: ", ex);
            ex.printStackTrace();
            return null;
        }
    }

    private Map<String, Credential> getCredentialStore() {
        final String KEY = "GoogleAppsCredentialStore";
        HttpSession session = xwikiContextProvider.get().getRequest().getSession(true);
        Map<String,Credential> store = (Map<String,Credential>) (session.getAttribute(KEY));
        if(store == null) {
            store = new HashMap<String,Credential>();
            session.setAttribute(KEY, store);
        }
        return store;
    }

    private void storeCredentials(String userId, Credential credentials) throws XWikiException  {
        try {
            if (userId.contains("XWiki.XWikiGuest")) {
                userId = userId + "-" + xwikiContextProvider.get().getRequest().getSession().hashCode();
            }
            else {
                if (useCookies) {
                    // create a cookie
                    CookieAuthenticationPersistenceStoreTools cookieTools =
                            new CookieAuthenticationPersistenceStoreTools();
                    cookieTools.initialize(xwikiContextProvider.get(), configCookiesTTL);

                    cookieTools.store(userId);
                    log.info("Store cookie for user " + userId);
                }
            }
            log.info("Storing credentials for user " + userId);
            getCredentialStore().put(userId, credentials);
        } catch (Exception e) {
            e.printStackTrace();
            throw new XWikiException("Issue at storing credential.", e);
        }
    }

    private Credential getStoredCredentials(String userId) {
        if (userId.contains("XWiki.XWikiGuest")) {
            userId = userId + "-" + xwikiContextProvider.get().getRequest().getSession().hashCode();
        }
        log.debug("Getting credentials for user " + userId);
        return getCredentialStore().get(userId);
    }


    /**
     * Retrieve credentials using the provided authorization code.
     *
     * This function exchanges the authorization code for an access token and
     * queries the UserInfo API to retrieve the user's e-mail address. If a
     * refresh token has been retrieved along with an access token, it is stored
     * in the application database using the user's e-mail address as key. If no
     * refresh token has been retrieved, the function checks in the application
     * database for one and returns it if found or throws a NoRefreshTokenException
     * with the authorization URL to redirect the user to.
     *
     * @param authorizationCode Authorization code to use to retrieve an access
     *     token.
     * @return OAuth 2.0 credentials instance containing an access and refresh
     *     token.
     * @throws IOException Unable to load client_secret.json.
     */
    private Credential retrieveCredentials(String authorizationCode) throws XWikiException, IOException {
        return retrieveCredentials(authorizationCode, true);
    }

    private Credential retrieveCredentials(String authorizationCode, boolean redirect)
            throws XWikiException, IOException {
        Credential credentials = null;
        String user = getCurrentXWikiUserName();

        if (authorizationCode!=null && authorizationCode!="") {
            log.debug("Trying to get credentials from authorization code: ${authorizationCode}");
            credentials = (authorizationCode==null) ? null : exchangeCode(authorizationCode);
            if (credentials!=null) {
                String rtoken = credentials.getRefreshToken();
                if (rtoken != null) {
                    log.debug("Refresh token has been created: " + rtoken);
                    storeCredentials(user, credentials);
                    return credentials;
                } else {
                    log.debug("Failure to create refresh token");
                    storeCredentials(user, credentials);
                    return credentials;
                }
            }
        }

        if (credentials==null) {
            log.debug("No credentials found. Checking stored credentials for user " + user);
            credentials = getStoredCredentials(user);
            if (credentials != null) {
                log.debug("Retrieved stored credentials");
                return credentials;
            }
            log.debug("Could not find stored credentials");
        }

        log.debug("No credentials retrieved.");
        // No refresh token has been retrieved.
        if (redirect) {
            log.debug("Redirecting to authorization URL.");
            xwikiContextProvider.get().getResponse().sendRedirect(getAuthorizationURL());
        }
        return credentials;
    }

    private String getAuthorizationURL() throws XWikiException, IOException {
        String state = "";
        XWikiRequest request = xwikiContextProvider.get().getRequest();
        if (!xwikiContextProvider.get().getDoc().getFullName().equals("GoogleApps.OAuth")) {
            String finalRedirect = request.getRequestURL().toString();
            String qs = request.getQueryString();
            if (qs!=null & qs.length()>0)
                finalRedirect += "?" + qs;
            state = Integer.toHexString(finalRedirect.hashCode());
            storedStates.put(state, finalRedirect);
        }

        GoogleAuthorizationCodeRequestUrl urlBuilder = getFlow()
                .newAuthorizationUrl()
                .setRedirectUri(getOAuthUrl())
                .setState(state);
        // Add user email to filter account if the user is logged with multiple account
        if (useCookies) {
            CookieAuthenticationPersistenceStoreTools cookieTools =
                    new CookieAuthenticationPersistenceStoreTools();
            cookieTools.initialize(xwikiContextProvider.get(), configCookiesTTL);
            String userId = cookieTools.retrieve();
            XWikiDocument userDoc = getXWiki().getDocument(createUserReference(userId), xwikiContextProvider.get());
            String userEmail = null;
            BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef(), false, xwikiContextProvider.get());
            // userclass "XWiki.XWikiUsers"

            if (userObj!=null) {
                userEmail = userDoc.getStringValue("email");
            }
            if(userEmail!=null)
                urlBuilder = urlBuilder.set("login_hint", userEmail);
        }
        String authurl = urlBuilder.build();
        log.debug("google authentication url : " + authurl);
        return authurl;
    }

    private Credential authorize() throws XWikiException, IOException {
        return authorize(true);
    }

    private Credential authorize(boolean redirect) throws XWikiException, IOException {
        log.debug("In authorize");
        GoogleAuthorizationCodeFlow flow = getFlow();
        XWikiRequest request = xwikiContextProvider.get().getRequest();
        String state = request.getParameter("state");
        XWikiResponse response = xwikiContextProvider.get().getResponse();
        Credential creds = retrieveCredentials(request.getParameter("code"), redirect);
        log.debug("Got credentials: " + creds);
        if (state!=null && state.length()>0) {
            String url = storedStates.get(state);
            if (url!=null) {
                log.debug("Redirecting to final destination after authorization: " + url);
                response.sendRedirect(url);
            }
        }
        return creds;
    }

    /**
     * Build and return an authorized Google Plus client service.
     * @return an authorized Drive client service
     * @throws IOException
     * @throws XWikiException
     */
    private Plus getPlusService() throws XWikiException, IOException {
        Credential credential = authorize();
        return new Plus.Builder(
                httpTransport, jacksonFactory, credential)
                .setApplicationName(configAppName)
                .build();
    }

    /**
     *
     * @return -1 if failed, 0 if successful
     * @throws XWikiException
     * @throws IOException
     */
    private int updateUser() throws XWikiException,  IOException {
        String xwikiUser = null;
        Credential credential = authorize();
        Plus plus = getPlusService();
        Person user = plus.people().get("me").execute();
        XWikiContext context = xwikiContextProvider.get();
        log.debug("user: " + user);
        // GOOGLEAPPS: User: [displayName:..., emails:[[type:account, value:...]], etag:"...", id:...., image:[isDefault:false, url:https://...], kind:plus#person, language:en, name:[familyName:..., givenName:...]]
        if (user==null) {
            return -1;
        } else if (configDomain!=null && !configDomain.equals(user.getDomain())) {
            String userId = getCurrentXWikiUserName() + "-" + context.getRequest().getSession().hashCode();
            getCredentialStore().remove(userId);
            log.debug("Wrong domain: Removed credentials for userid " + userId);
            return -1;
        } else {
            String id = user.getId();
            String email = "";
            String currentWiki = context.getWikiId();
            try {
                // Force main wiki database to create the user as global
                context.setMainXWiki("xwiki");
                email = (user.getEmails() != null && user.getEmails().size() > 0) ? user.getEmails().get(0).getValue() :
                        "";
                List<Object[]> wikiUserList = queryManager.createQuery(
                        "from doc.object(GoogleApps.GoogleAppsAuthClass) as auth where auth.id=:id",
                        Query.XWQL).bindValue("id", id).execute();
                if ((wikiUserList == null) || (wikiUserList.size() == 0))
                    wikiUserList = queryManager.createQuery(
                            "from doc.object(XWiki.XWikiUsers) as user where user.email=:email", Query.XWQL)
                            .bindValue("email", email).execute();

                if ((wikiUserList == null) || (wikiUserList.size() == 0)) {
                    // user not found.. need to create new user
                    xwikiUser = email.substring(0, email.indexOf("@"));
                    // make sure user is unique
                    xwikiUser = getXWiki().getUniquePageName("XWiki", xwikiUser, context);
                    // create user
                    DocumentReference userDirRef = new DocumentReference(context.getWikiId(), "Main", "UserDirectory");
                    String randomPassword = RandomStringUtils.randomAlphanumeric(8);
                    Map<String, String> userAttributes = new HashMap<String, String>();

                    if (user.getName() != null) {
                        userAttributes.put("first_name", user.getName().getGivenName());
                        userAttributes.put("last_name", user.getName().getFamilyName());
                    }
                    userAttributes.put("email", email);
                    userAttributes.put("password", randomPassword);
                    int isCreated = getXWiki().createUser(xwikiUser, userAttributes,
                            userDirRef, null, null, "edit", context);
                    // Add google apps id to the user
                    if (isCreated == 1) {
                        log.debug("Creating user " + xwikiUser);
                        XWikiDocument userDoc = getXWiki()
                                .getDocument(createUserReference(xwikiUser), context);
                        BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());

                        // TODO: is this not redundant when having used createUser (map) ?
                        if (user.getName() != null) {
                            userObj.set("first_name", user.getName().getGivenName(), context);
                            userObj.set("last_name", user.getName().getFamilyName(), context);
                        }
                        if (configScopeUseAvatar && user.getImage() != null && user.getImage().getUrl() != null) {
                            log.debug("Adding avatar " + user.getImage().getUrl());
                            URL u = new URL(user.getImage().getUrl());
                            InputStream b = u.openStream();
                            String fileName = u.getFile().substring(u.getFile().lastIndexOf('/') + 1);
                            userDoc.addAttachment(fileName, u.openStream(), context);
                            userObj.set("avatar", fileName, context);
                            b.close();
                        }

                        int place = userDoc.createXObject(getGoogleAuthClassReference(), context);
                        BaseObject gAppsAuthClass = userDoc.getXObject(getGoogleAuthClassReference());
                        gAppsAuthClass.set("id", id, context);
                        getXWiki().saveDocument(userDoc, "Google Apps login user creation", false, context);
                    } else {
                        log.debug("User creation failed");
                        return -1;
                    }
                } else {
                    // user found.. we should update it if needed
                    xwikiUser = (String) (wikiUserList.get(0)[0]);
                    log.debug("Found user " + xwikiUser);
                    boolean changed = false;
                    XWikiDocument userDoc = getXWiki().getDocument(createUserReference(xwikiUser), context);
                    BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());
                    if (userObj == null) {
                        log.debug("User found is not a user");
                        return -1;
                    } else {
                        if (! userObj.getStringValue("email").equals(email)) {
                            userObj.set("email", email, context);
                            changed = true;
                        }
                        if (!userObj.getStringValue("first_name").equals(user.getName().getGivenName())) {
                            userObj.set("first_name", user.getName().getGivenName(), context);
                            changed = true;
                        }
                        if (!userObj.getStringValue("last_name").equals(user.getName().getFamilyName())) {
                            userObj.set("last_name", user.getName().getFamilyName(), context);
                            changed = true;
                        }
                        if (configScopeUseAvatar && user.getImage()!=null  && user.getImage().getUrl()!=null) {
                            String imageUrl = user.getImage().getUrl();
                            log.debug("Pulling avatar " + imageUrl);
                            HttpGet httpget = new HttpGet(imageUrl);
                            // TODO: add an if-modified-since
                            CloseableHttpResponse response = httpclient.execute(httpget);
                            HttpEntity entity = response.getEntity();
                            if(entity!=null) {
                                ByteArrayOutputStream bOut = new ByteArrayOutputStream((int) entity.getContentLength());
                                IOUtils.copy(entity.getContent(), bOut);
                                byte[] bytesFromGoogle = bOut.toByteArray();

                                XWikiAttachment attachment =
                                        userObj.getStringValue("avatar") == null ? null :
                                                userDoc.getAttachment(userObj.getStringValue("avatar"));
                                boolean fileChanged = attachment == null || attachment.getFilesize() != bytesFromGoogle.length;
                                if (!fileChanged) {
                                    byte[] b = attachment.getContent(context);
                                    for (int i = 0; i < b.length; i++)
                                        if (b[i] != bytesFromGoogle[i]) {
                                            fileChanged = true;
                                            break;
                                        }
                                }
                                if (fileChanged) {
                                    String fileName = new URL(imageUrl).getFile().substring(imageUrl.lastIndexOf('/') + 1);
                                    log.debug("Avatar changed " + fileName);
                                    userObj.set("avatar", fileName, context);
                                    userDoc.addAttachment(fileName, bytesFromGoogle, context);
                                    changed = true;
                                }
                            }

                        }

                        BaseObject googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                        if (googleAppsAuth == null) {
                            userDoc.createXObject(getGoogleAuthClassReference(), context);
                            googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                            changed = true;
                        }

                        if (!googleAppsAuth.getStringValue("id").equals(id)) {
                            googleAppsAuth.set("id", id, context);
                            changed = true;
                        }

                        if (changed) {
                            log.info("User changed.");
                            getXWiki().saveDocument(userDoc, "Google Apps login user updated.", context);
                        } else {
                            log.info("User unchanged.");
                        }
                    }
                }
            } catch (QueryException qe) {
                log.warn("Can't query for users.", qe);
                throw new XWikiException("Can't query for users.", qe);
            } finally {
                // Restore database
                context.setMainXWiki(currentWiki);
            }

            // we need to restore the credentials as the user will now be logged-in
            storeCredentials(xwikiUser, credential);

            // store the validated xwiki user for the authentication module
            context.getRequest().getSession().setAttribute("googleappslogin", "xwiki:" + xwikiUser);

            return 0;
        }
    }

    /**
     * Build and return an authorized Drive client service.
     * @return an authorized Drive client service
     * @throws IOException
     */
    private Drive getDriveService() throws XWikiException, IOException {
        Credential credential = authorize();
        return new Drive.Builder(
                httpTransport, jacksonFactory, credential)
                .setApplicationName(configAppName)
                .build();
    }

    /**
     * Build and return an authorized Drive client service.
     * @return an authorized Drive client service
     * @throws IOException
     */
    private DocsService getDocsService() throws XWikiException, IOException {
        Credential credential = authorize();
        DocsService service = new DocsService(configAppName);
        service.setOAuth2Credentials(credential);
        return service;
    }


    private FileList getDocumentList() throws XWikiException, IOException {
        Drive drive = getDriveService();
        FileList result = drive.files().list().setMaxResults(10).execute();
        return result;
    }

    // TODO: this is the same function as listDocuments! One of them must be wrong
    public FileList importFromGoogleApps(String query, int nbResults) throws XWikiException, IOException {
        Drive drive = getDriveService();
        Drive.Files.List req = drive.files().list().setQ(query).setFields("items(id,mimeType,title,exportLinks,selfLink,version,alternateLink)").setMaxResults(nbResults);
        FileList result = req.execute();
        return result;
    }

    public FileList listDocuments(String query, int nbResults) throws XWikiException, IOException {
        Drive drive = getDriveService();
        Drive.Files.List req = drive.files().list().setQ(query).setMaxResults(nbResults);
        FileList result = req.execute();
        return result;
    }


}
