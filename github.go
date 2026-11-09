// Package github implements login with GitHub (OAuth2). gtr package:
// passport-github.
//
//	a.Use(github.New(clientID, clientSecret, "https://app.example.com/auth/github/callback"))
//
// GitHub's /user has an email only when the user made it public, and never
// says whether it is verified, so the strategy also reads /user/emails and
// takes the primary verified address (Identity.EmailVerified = true); with
// no verified address Email is empty. Link accounts by email only when
// EmailVerified is true.
package github

import (
	"context"
	"net/http"

	"passport"
	oauth2 "passport-oauth2"
)

// Default GitHub endpoints.
const (
	AuthURL     = "https://github.com/login/oauth/authorize"
	TokenURL    = "https://github.com/login/oauth/access_token"
	UserInfoURL = "https://api.github.com/user"
	EmailsURL   = "https://api.github.com/user/emails"
)

// Option changes strategy settings.
type Option func(*settings)

type settings struct {
	cfg       oauth2.Config
	emailsURL string
}

// WithScopes replaces the scopes (default: read:user, user:email).
func WithScopes(scopes ...string) Option { return func(s *settings) { s.cfg.Scopes = scopes } }

// WithHTTPClient sets the HTTP client for requests to GitHub.
func WithHTTPClient(h *http.Client) Option { return func(s *settings) { s.cfg.HTTPClient = h } }

// WithEndpoints overrides the endpoints (GitHub Enterprise, tests with oauth2test).
func WithEndpoints(auth, token, user, emails string) Option {
	return func(s *settings) {
		s.cfg.AuthURL, s.cfg.TokenURL, s.cfg.UserInfoURL, s.emailsURL = auth, token, user, emails
	}
}

// WithPKCE turns PKCE on (GitHub supports it); key is the StateKey shared
// by all instances (nil: one per process). Pass the state to Callback.
func WithPKCE(key []byte) Option {
	return func(s *settings) { s.cfg.PKCE, s.cfg.StateKey = true, key }
}

// New creates the "github" strategy; clientID and clientSecret come from a
// GitHub OAuth App (Settings → Developer settings), with redirectURL as its
// callback URL.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *oauth2.Strategy {
	s := settings{
		cfg: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			AuthURL: AuthURL, TokenURL: TokenURL, UserInfoURL: UserInfoURL,
			Scopes: []string{"read:user", "user:email"},
		},
		emailsURL: EmailsURL,
	}
	for _, o := range opts {
		o(&s)
	}
	emails := s.emailsURL
	s.cfg.Enrich = func(ctx context.Context, st *oauth2.Strategy, tok *oauth2.Token, profile map[string]any) error {
		var list []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := st.GetJSON(ctx, tok.AccessToken, emails, &list); err != nil {
			return err
		}
		profile["email"], profile["email_verified"] = "", false
		for _, e := range list {
			if e.Verified && (e.Primary || profile["email"] == "") {
				profile["email"], profile["email_verified"] = e.Email, true
			}
		}
		return nil
	}
	return oauth2.New("github", s.cfg, MapProfile)
}

// MapProfile maps GitHub's /user (plus the email Enrich added).
func MapProfile(p map[string]any) (*passport.Identity, error) {
	name := oauth2.String(p, "name")
	if name == "" {
		name = oauth2.String(p, "login")
	}
	return &passport.Identity{
		ProviderUserID: oauth2.String(p, "id"), // numeric; the login can be renamed
		Email:          oauth2.String(p, "email"),
		EmailVerified:  oauth2.Bool(p, "email_verified"),
		Name:           name,
		AvatarURL:      oauth2.String(p, "avatar_url"),
	}, nil
}
