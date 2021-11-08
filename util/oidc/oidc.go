package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/argoproj/argo-cd/v2/common"
	"github.com/argoproj/argo-cd/v2/server/settings/oidc"
	appstatecache "github.com/argoproj/argo-cd/v2/util/cache/appstate"
	"github.com/argoproj/argo-cd/v2/util/dex"
	httputil "github.com/argoproj/argo-cd/v2/util/http"
	"github.com/argoproj/argo-cd/v2/util/rand"
	"github.com/argoproj/argo-cd/v2/util/settings"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeImplicit          = "implicit"
	ResponseTypeCode           = "code"
)

// OIDCConfiguration holds a subset of interested fields from the OIDC configuration spec
type OIDCConfiguration struct {
	Issuer                 string   `json:"issuer"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
}

type ClaimsRequest struct {
	IDToken map[string]*oidc.Claim `json:"id_token"`
}

type OIDCState struct {
	// ReturnURL is the URL in which to redirect a user back to after completing an OAuth2 login
	ReturnURL string `json:"returnURL"`
}

type OIDCStateStorage interface {
	GetOIDCState(key string) (*OIDCState, error)
	SetOIDCState(key string, state *OIDCState) error
}

type ClientApp struct {
	// OAuth2 client ID of this application (e.g. argo-cd)
	clientID string
	// OAuth2 client secret of this application
	clientSecret string
	// Callback URL for OAuth2 responses (e.g. https://argocd.example.com/auth/callback)
	redirectURI string
	// URL of the issuer (e.g. https://argocd.example.com/api/dex)
	issuerURL string
	// The URL endpoint at which the ArgoCD server is accessed.
	baseHRef string
	// client is the HTTP client which is used to query the IDp
	client *http.Client
	// secureCookie indicates if the cookie should be set with the Secure flag, meaning it should
	// only ever be sent over HTTPS. This value is inferred by the scheme of the redirectURI.
	secureCookie bool
	// settings holds Argo CD settings
	settings *settings.ArgoCDSettings
	// provider is the OIDC provider
	provider Provider
	// cache holds temporary nonce tokens to which hold application state values
	// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
	cache OIDCStateStorage
}

func GetScopesOrDefault(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email", "groups"}
	}
	return scopes
}

// NewClientApp will register the Argo CD client app (either via Dex or external OIDC) and return an
// object which has HTTP handlers for handling the HTTP responses for login and callback
func NewClientApp(settings *settings.ArgoCDSettings, cache OIDCStateStorage, dexServerAddr, baseHRef string) (*ClientApp, error) {
	redirectURL, err := settings.RedirectURL()
	if err != nil {
		return nil, err
	}
	a := ClientApp{
		clientID:     settings.OAuth2ClientID(),
		clientSecret: settings.OAuth2ClientSecret(),
		redirectURI:  redirectURL,
		issuerURL:    settings.IssuerURL(),
		baseHRef:     baseHRef,
		cache:        cache,
	}
	log.Infof("Creating client app (%s)", a.clientID)
	u, err := url.Parse(settings.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect-uri: %v", err)
	}
	tlsConfig := settings.TLSConfig()
	if tlsConfig != nil {
		tlsConfig.InsecureSkipVerify = true
	}
	a.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	if settings.DexConfig != "" && settings.OIDCConfigRAW == "" {
		a.client.Transport = dex.NewDexRewriteURLRoundTripper(dexServerAddr, a.client.Transport)
	}
	if os.Getenv(common.EnvVarSSODebug) == "1" {
		a.client.Transport = httputil.DebugTransport{T: a.client.Transport}
	}

	a.provider = NewOIDCProvider(a.issuerURL, a.client)
	// NOTE: if we ever have replicas of Argo CD, this needs to switch to Redis cache
	a.secureCookie = bool(u.Scheme == "https")
	a.settings = settings
	return &a, nil
}

func (a *ClientApp) oauth2Config(scopes []string) (*oauth2.Config, error) {
	endpoint, err := a.provider.Endpoint()
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     *endpoint,
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}, nil
}

// generateAppState creates an app state nonce
func (a *ClientApp) generateAppState(returnURL string) string {
	randStr := rand.RandString(10)
	if returnURL == "" {
		returnURL = a.baseHRef
	}
	err := a.cache.SetOIDCState(randStr, &OIDCState{ReturnURL: returnURL})
	if err != nil {
		// This should never happen with the in-memory cache
		log.Errorf("Failed to set app state: %v", err)
	}
	return randStr
}

func (a *ClientApp) verifyAppState(state string) (*OIDCState, error) {
	res, err := a.cache.GetOIDCState(state)
	if err != nil {
		if err == appstatecache.ErrCacheMiss {
			return nil, fmt.Errorf("unknown app state %s", state)
		} else {
			return nil, fmt.Errorf("failed to verify app state %s: %v", state, err)
		}
	}

	_ = a.cache.SetOIDCState(state, nil)
	return res, nil
}

// isValidRedirectURL checks whether the given redirectURL matches on of the
// allowed URLs to redirect to.
//
// In order to be considered valid,the protocol and host (including port) have
// to match and if allowed path is not "/", redirectURL's path must be within
// allowed URL's path.
func isValidRedirectURL(redirectURL string, allowedURLs []string) bool {
	if redirectURL == "" {
		return true
	}
	r, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	// We consider empty path the same as "/" for redirect URL
	if r.Path == "" {
		r.Path = "/"
	}
	// Prevent CRLF in the redirectURL
	if strings.ContainsAny(r.Path, "\r\n") {
		return false
	}
	for _, baseURL := range allowedURLs {
		b, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		// We consider empty path the same as "/" for allowed URL
		if b.Path == "" {
			b.Path = "/"
		}
		// scheme and host are mandatory to match.
		if b.Scheme == r.Scheme && b.Host == r.Host {
			// If path of redirectURL and allowedURL match, redirectURL is allowed
			//if b.Path == r.Path {
			//	return true
			//}
			// If path of redirectURL is within allowed URL's path, redirectURL is allowed
			if strings.HasPrefix(path.Clean(r.Path), b.Path) {
				return true
			}
		}
	}
	// No match - redirect URL is not allowed
	return false
}

// HandleLogin formulates the proper OAuth2 URL (auth code or implicit) and redirects the user to
// the IDp login & consent page
func (a *ClientApp) HandleLogin(w http.ResponseWriter, r *http.Request) {
	oidcConf, err := a.provider.ParseConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scopes := make([]string, 0)
	var opts []oauth2.AuthCodeOption
	if config := a.settings.OIDCConfig(); config != nil {
		scopes = config.RequestedScopes
		opts = AppendClaimsAuthenticationRequestParameter(opts, config.RequestedIDTokenClaims)
	}
	oauth2Config, err := a.oauth2Config(GetScopesOrDefault(scopes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	returnURL := r.FormValue("return_url")
	// Check if return_url is valid, otherwise abort processing (see #2707)
	if !isValidRedirectURL(returnURL, []string{a.settings.URL}) {
		http.Error(w, "Invalid return_url", http.StatusBadRequest)
		return
	}
	stateNonce := a.generateAppState(returnURL)
	grantType := InferGrantType(oidcConf)
	var url string
	switch grantType {
	case GrantTypeAuthorizationCode:
		url = oauth2Config.AuthCodeURL(stateNonce, opts...)
	case GrantTypeImplicit:
		url = ImplicitFlowURL(oauth2Config, stateNonce, opts...)
	default:
		http.Error(w, fmt.Sprintf("Unsupported grant type: %v", grantType), http.StatusInternalServerError)
		return
	}
	log.Infof("Performing %s flow login: %s", grantType, url)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// HandleCallback is the callback handler for an OAuth2 login flow
func (a *ClientApp) HandleCallback(w http.ResponseWriter, r *http.Request) {
	oauth2Config, err := a.oauth2Config(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Infof("Callback: %s", r.URL)
	if errMsg := r.FormValue("error"); errMsg != "" {
		errorDesc := r.FormValue("error_description")
		http.Error(w, html.EscapeString(errMsg)+": "+html.EscapeString(errorDesc), http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" {
		// If code was not given, it implies implicit flow
		a.handleImplicitFlow(w, state)
		return
	}
	appState, err := a.verifyAppState(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := gooidc.ClientContext(r.Context(), a.client)
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}
	idTokenRAW, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}
	idToken, err := a.provider.Verify(a.clientID, idTokenRAW)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid session token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims jwt.MapClaims
	err = idToken.Claims(&claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	claimsJSON, _ := json.Marshal(claims)
	_, err = a.FetchDistributedClaims(r.Context(), idToken, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s\n%s", claimsJSON, err.Error()), http.StatusInternalServerError)
		return
	}
	// TODO: now that we have the distributed claims, need to figure out a storage strategy
	// (e.g. appended to existing cookie, redis, etc...)

	// Set cookie
	path := "/"
	if a.baseHRef != "" {
		path = strings.TrimRight(strings.TrimLeft(a.baseHRef, "/"), "/")
	}
	cookiePath := fmt.Sprintf("path=/%s", path)
	flags := []string{cookiePath, "SameSite=lax", "httpOnly"}
	if a.secureCookie {
		flags = append(flags, "Secure")

	}
	if idTokenRAW != "" {
		cookies, err := httputil.MakeCookieMetadata(common.AuthCookieName, idTokenRAW, flags...)
		if err != nil {
			claimsJSON, _ := json.Marshal(claims)
			http.Error(w, fmt.Sprintf("claims=%s, err=%v", claimsJSON, err), http.StatusInternalServerError)
			return
		}

		for _, cookie := range cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
	}

	log.Infof("Web login successful. Claims: %s", claimsJSON)
	if os.Getenv(common.EnvVarSSODebug) == "1" {
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		renderToken(w, a.redirectURI, idTokenRAW, token.RefreshToken, claimsJSON)
	} else {
		http.Redirect(w, r, appState.ReturnURL, http.StatusSeeOther)
	}
}

var implicitFlowTmpl = template.Must(template.New("implicit.html").Parse(`<script>
var hash = window.location.hash.substr(1);
var result = hash.split('&').reduce(function (result, item) {
	var parts = item.split('=');
	result[parts[0]] = parts[1];
	return result;
}, {});
var idToken = result['id_token'];
var state = result['state'];
var returnURL = "{{ .ReturnURL }}";
if (state != "" && returnURL == "") {
	window.location.href = window.location.href.split("#")[0] + "?state=" + result['state'] + window.location.hash;
} else if (returnURL != "") {
	document.cookie = "{{ .CookieName }}=" + idToken + "; path=/";
	window.location.href = returnURL;
}
</script>`))

// handleImplicitFlow completes an implicit OAuth2 flow. The id_token and state will be contained
// in the URL fragment. The javascript client first redirects to the callback URL, supplying the
// state nonce for verification, as well as looking up the return URL. Once verified, the client
// stores the id_token from the fragment as a cookie. Finally it performs the final redirect back to
// the return URL.
func (a *ClientApp) handleImplicitFlow(w http.ResponseWriter, state string) {
	type implicitFlowValues struct {
		CookieName string
		ReturnURL  string
	}
	vals := implicitFlowValues{
		CookieName: common.AuthCookieName,
	}
	if state != "" {
		appState, err := a.verifyAppState(state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		vals.ReturnURL = appState.ReturnURL
	}
	renderTemplate(w, implicitFlowTmpl, vals)
}

// ImplicitFlowURL is an adaptation of oauth2.Config::AuthCodeURL() which returns a URL
// appropriate for an OAuth2 implicit login flow (as opposed to authorization code flow).
func ImplicitFlowURL(c *oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string {
	opts = append(opts, oauth2.SetAuthURLParam("response_type", "id_token"))
	opts = append(opts, oauth2.SetAuthURLParam("nonce", rand.RandString(10)))
	return c.AuthCodeURL(state, opts...)
}

// OfflineAccess returns whether or not 'offline_access' is a supported scope
func OfflineAccess(scopes []string) bool {
	if len(scopes) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		return true
	}
	// See if scopes_supported has the "offline_access" scope.
	for _, scope := range scopes {
		if scope == gooidc.ScopeOfflineAccess {
			return true
		}
	}
	return false
}

// InferGrantType infers the proper grant flow depending on the OAuth2 client config and OIDC configuration.
// Returns either: "authorization_code" or "implicit"
func InferGrantType(oidcConf *OIDCConfiguration) string {
	// Check the supported response types. If the list contains the response type 'code',
	// then grant type is 'authorization_code'. This is preferred over the implicit
	// grant type since refresh tokens cannot be issued that way.
	for _, supportedType := range oidcConf.ResponseTypesSupported {
		if supportedType == ResponseTypeCode {
			return GrantTypeAuthorizationCode
		}
	}

	// Assume implicit otherwise
	return GrantTypeImplicit
}

// AppendClaimsAuthenticationRequestParameter appends a OIDC claims authentication request parameter
// to `opts` with the `requestedClaims`
func AppendClaimsAuthenticationRequestParameter(opts []oauth2.AuthCodeOption, requestedClaims map[string]*oidc.Claim) []oauth2.AuthCodeOption {
	if len(requestedClaims) == 0 {
		return opts
	}
	log.Infof("RequestedClaims: %s\n", requestedClaims)
	claimsRequestParameter, err := createClaimsAuthenticationRequestParameter(requestedClaims)
	if err != nil {
		log.Errorf("Failed to create OIDC claims authentication request parameter from config: %s", err)
		return opts
	}
	return append(opts, claimsRequestParameter)
}

func createClaimsAuthenticationRequestParameter(requestedClaims map[string]*oidc.Claim) (oauth2.AuthCodeOption, error) {
	claimsRequest := ClaimsRequest{IDToken: requestedClaims}
	claimsRequestRAW, err := json.Marshal(claimsRequest)
	if err != nil {
		return nil, err
	}
	return oauth2.SetAuthURLParam("claims", string(claimsRequestRAW)), nil
}

// DistributedClaims is the object representation of OIDC distributed claims. e.g.:
// {
//   "_claim_names": {
//	   "address": "src1",
//	   "phone_number": "src1"
//   }
// 	 "_claim_sources": {
// 	   "src1": {
// 	     "endpoint": "https://bank.example.com/claim_source"
//     },
// 	   "src2": {
//       "endpoint": "https://creditagency.example.com/claims_here",
//       "access_token": "ksj3n283dke"
//     },
//   }
// }
type DistributedClaims struct {
	ClaimNames   map[string]string      `json:"_claim_names,omitempty"`
	ClaimSources map[string]ClaimSource `json:"_claim_sources,omitempty"`
}

type ClaimSource struct {
	// Endpoint URL to use to request the distributed claim.  This URL is expected to be
	// prefixed by one of the known issuer URLs.
	Endpoint string `json:"endpoint,omitempty"`
	// AccessToken is the bearer token to use for access.  If empty, it is
	// not used.  Access token is optional per the OIDC distributed claims
	// specification.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#DistributedExample
	AccessToken string `json:"access_token,omitempty"`
}

// FetchDistributedClaims performs the additional HTTP requests to retrieve distributed claims
func (a *ClientApp) FetchDistributedClaims(ctx context.Context, idToken *gooidc.IDToken, token *oauth2.Token) (map[string]jwt.MapClaims, error) {
	var distClaimsSources DistributedClaims
	err := idToken.Claims(&distClaimsSources)
	if err != nil {
		return nil, err
	}

	distClaims := make(map[string]jwt.MapClaims)
	for claimName, srcName := range distClaimsSources.ClaimNames {
		source := distClaimsSources.ClaimSources[srcName]
		req, err := newDistributedClaimsRequest(source, token)
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read distributed claim response: %v", err)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return nil, fmt.Errorf("failed to fetch distributed claim %s JWT from '%s' (status: %v, body: %s)", claimName, req.URL, resp.Status, string(respBytes))
		}
		// TODO: validate the claim. Response should be a JWT in the case of Azure, it is plain JSON
		distClaims[claimName] = jwt.MapClaims{}
		log.Info(string(respBytes))
	}
	return distClaims, nil
}

const (
	// Legacy (Deprecated) ADAL and Azure AD Graph API. Used to detect and upgrade to newer Microsoft Graph API endpoint
	legacyAzureADGraphHost = "graph.windows.net"
	// The host and version of the Microsoft Graph API
	microsoftGraphHost       = "graph.microsoft.com"
	microsoftGraphAPIVersion = "/v1.0"
)

// newDistributedClaimsRequest returns an HTTP request to perform a distributed claims request
func newDistributedClaimsRequest(source ClaimSource, token *oauth2.Token) (*http.Request, error) {
	parsedURL, err := url.Parse(source.Endpoint)
	if err != nil {
		return nil, err
	}
	// As of 11/2021, claims endpoint returned by Azure still references the deprecated
	// Azure Graph API (graph.windows.net). This transparently switches the request to use the
	// Microsoft Graph API v1.0 Graph API.
	// * https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0
	if parsedURL.Host == legacyAzureADGraphHost {
		parsedURL.Host = microsoftGraphHost
		parsedURL.Path = microsoftGraphAPIVersion + parsedURL.Path
	}

	var req *http.Request
	if parsedURL.Host == microsoftGraphHost {
		// Microsoft Graph API is not compliant OIDC. To fetch their version of "distributed claims"
		// it requires a POST on the endpoint with securityEnabledOnly payload.
		// * https://github.com/kubernetes/kubernetes/issues/62920
		// * https://github.com/oauth2-proxy/oauth2-proxy/issues/1231
		// * https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison
		req, err = http.NewRequest("POST", parsedURL.String(), strings.NewReader(`{"securityEnabledOnly": false}`))
		if err != nil {
			return nil, err
		}
		req.Header.Add("content-type", "application/json")
	} else {
		req, err = http.NewRequest("GET", parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
	}
	// Use the specified access_token if returned. Otherwise use pre-negotiated token.
	if source.AccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", source.AccessToken))
	} else {
		// https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
		// If the Access Token is not available, RPs MAY need to retrieve the Access Token out of band
		// or use an Access Token that was pre-negotiated between the Claims Provider and RP,
		// or the Claims Provider MAY reauthenticate the End-User and/or reauthorize the RP.
		token.SetAuthHeader(req)
	}
	return req, nil
}
