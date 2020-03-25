package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bmizerany/assert"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
)

const azureOIDCaccessToken = "access_token"
const azureOIDCrefreshToken = "refresh_token"
const azureOIDCclientID = "https://test.myapp.com"
const azureOIDCsecret = "secret"

type azureOIDCidTokenClaims struct {
	Name              string   `json:"name,omitempty"`
	Email             string   `json:"email,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	jwt.StandardClaims
}

type azureOIDCredeemTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

var azureOIDCdefaultIDToken azureOIDCidTokenClaims = azureOIDCidTokenClaims{
	"Jane Dobbs",
	"janed@me.com",
	"http://mugbook.com/janed/me.jpg",
	"11223344",
	[]string{"MyRole"},
	[]string{"MyGroup"},
	jwt.StandardClaims{
		Audience:  "https://test.myapp.com",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "123456789",
	},
}

type azureOIDCfakeKeySetStub struct{}

func (azureOIDCfakeKeySetStub) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	tokenClaims := &azureOIDCidTokenClaims{}
	err = json.Unmarshal(decodeString, tokenClaims)

	if err != nil || tokenClaims.Id == "this-id-fails-validation" {
		return nil, fmt.Errorf("the validation failed for subject [%v]", tokenClaims.Subject)
	}

	return decodeString, err
}

func newAzureOIDCProvider(serverURL *url.URL) *AzureOIDCProvider {

	providerData := &ProviderData{
		ProviderName: "oidc",
		ClientID:     azureOIDCclientID,
		ClientSecret: azureOIDCsecret,
		LoginURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/authorize"},
		RedeemURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/access_token"},
		ProfileURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/profile"},
		ValidateURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/api"},
		Scope: "openid profile offline_access"}

	p := &AzureOIDCProvider{
		OIDCProvider: &OIDCProvider{
			ProviderData: providerData,
			Verifier: oidc.NewVerifier(
				"https://issuer.example.com",
				azureOIDCfakeKeySetStub{},
				&oidc.Config{ClientID: azureOIDCclientID},
			),
		},
	}

	return p
}

func newAzureOIDCServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newAzureOIDCSignedTestIDToken(tokenClaims azureOIDCidTokenClaims) (string, error) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return standardClaims.SignedString(key)
}

func newAzureOIDCOauth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  azureOIDCaccessToken,
		TokenType:    "Bearer",
		RefreshToken: azureOIDCrefreshToken,
		Expiry:       time.Time{}.Add(time.Duration(5) * time.Second),
	}
}

func newAzureOIDCTestSetup(body []byte) (*httptest.Server, *AzureOIDCProvider) {
	redeemURL, server := newAzureOIDCServer(body)
	provider := newAzureOIDCProvider(redeemURL)
	return server, provider
}

func TestAzureOIDCProviderRedeem(t *testing.T) {

	idToken, _ := newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)
	body, _ := json.Marshal(azureOIDCredeemTokenResponse{
		AccessToken:  azureOIDCaccessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: azureOIDCrefreshToken,
		IDToken:      idToken,
	})

	server, provider := newAzureOIDCTestSetup(body)
	defer server.Close()

	session, err := provider.Redeem(provider.RedeemURL.String(), "code1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, azureOIDCdefaultIDToken.Email, session.Email)
	assert.Equal(t, azureOIDCaccessToken, session.AccessToken)
	assert.Equal(t, idToken, session.IDToken)
	assert.Equal(t, azureOIDCrefreshToken, session.RefreshToken)
	assert.Equal(t, "11223344", session.User)
}

func TestAzureOIDCProviderRefreshSessionIfNeededWithoutIdToken(t *testing.T) {

	idToken, _ := newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)
	body, _ := json.Marshal(azureOIDCredeemTokenResponse{
		AccessToken:  azureOIDCaccessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: azureOIDCrefreshToken,
	})

	server, provider := newAzureOIDCTestSetup(body)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      idToken,
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: azureOIDCrefreshToken,
		Email:        "janedoe@example.com",
		User:         "11223344",
	}

	refreshed, err := provider.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, "janedoe@example.com", existingSession.Email)
	assert.Equal(t, azureOIDCaccessToken, existingSession.AccessToken)
	assert.Equal(t, idToken, existingSession.IDToken)
	assert.Equal(t, azureOIDCrefreshToken, existingSession.RefreshToken)
	assert.Equal(t, "11223344", existingSession.User)
}

func TestAzureOIDCProviderRefreshSessionIfNeededWithIdToken(t *testing.T) {

	idToken, _ := newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)
	body, _ := json.Marshal(azureOIDCredeemTokenResponse{
		AccessToken:  azureOIDCaccessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: azureOIDCrefreshToken,
		IDToken:      idToken,
	})

	server, provider := newAzureOIDCTestSetup(body)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: azureOIDCrefreshToken,
		Email:        "changeit",
		User:         "changeit",
	}
	refreshed, err := provider.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, azureOIDCdefaultIDToken.Email, existingSession.Email)
	assert.Equal(t, azureOIDCdefaultIDToken.Subject, existingSession.User)
	assert.Equal(t, azureOIDCaccessToken, existingSession.AccessToken)
	assert.Equal(t, idToken, existingSession.IDToken)
	assert.Equal(t, azureOIDCrefreshToken, existingSession.RefreshToken)
}

func TestAzureOIDCProvider_findVerifiedIdToken(t *testing.T) {

	server, provider := newAzureOIDCTestSetup([]byte(""))

	defer server.Close()

	token := newAzureOIDCOauth2Token()
	signedIDToken, _ := newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)
	tokenWithIDToken := token.WithExtra(map[string]interface{}{
		"id_token": signedIDToken,
	})

	verifiedIDToken, err := provider.findVerifiedIDToken(context.Background(), tokenWithIDToken)
	assert.Equal(t, true, err == nil)
	assert.Equal(t, true, verifiedIDToken != nil)
	assert.Equal(t, azureOIDCdefaultIDToken.Issuer, verifiedIDToken.Issuer)
	assert.Equal(t, azureOIDCdefaultIDToken.Subject, verifiedIDToken.Subject)

	// When the validation fails the response should be nil
	azureOIDCdefaultIDToken.Id = "this-id-fails-validation"
	signedIDToken, _ = newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)
	tokenWithIDToken = token.WithExtra(map[string]interface{}{
		"id_token": signedIDToken,
	})

	verifiedIDToken, err = provider.findVerifiedIDToken(context.Background(), tokenWithIDToken)
	assert.Equal(t, errors.New("failed to verify signature: the validation failed for subject [123456789]"), err)
	assert.Equal(t, true, verifiedIDToken == nil)

	// When there is no id token in the oauth token
	verifiedIDToken, err = provider.findVerifiedIDToken(context.Background(), newAzureOIDCOauth2Token())
	assert.Equal(t, nil, err)
	assert.Equal(t, true, verifiedIDToken == nil)
}

func TestAzureOIDCProviderRolesAndGroups(t *testing.T) {
	signedIDToken, _ := newAzureOIDCSignedTestIDToken(azureOIDCdefaultIDToken)

	provider := newAzureOIDCProvider(&url.URL{})

	session := &sessions.SessionState{
		IDToken: signedIDToken,
	}

	res := provider.ValidateGroup(session)
	assert.Equal(t, true, res)

	provider.PermittedRoles = []string{"MyRole"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, true, res)

	provider.PermittedRoles = []string{"OtherRole"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, false, res)

	provider.PermittedRoles = []string{}

	provider.PermittedGroups = []string{"MyGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, true, res)

	provider.PermittedGroups = []string{"OtherGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, false, res)

	provider.PermittedRoles = []string{"OtherRole"}
	provider.PermittedGroups = []string{"MyGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, false, res)

	provider.PermittedRoles = []string{"MyRole"}
	provider.PermittedGroups = []string{"OtherGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, false, res)

	provider.PermittedRoles = []string{"OtherRole"}
	provider.PermittedGroups = []string{"OtherGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, false, res)

	provider.PermittedRoles = []string{"MyRole"}
	provider.PermittedGroups = []string{"MyGroup"}
	res = provider.ValidateGroup(session)
	assert.Equal(t, true, res)
}
