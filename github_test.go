package github_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	github "passport-github"
	"passport-oauth2/oauth2test"
)

func emailsServer(t *testing.T, body string) string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-access-token" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func TestCallback(t *testing.T) {
	p := oauth2test.NewProvider(t, map[string]any{"id": float64(583231), "login": "octocat", "email": "public@x", "avatar_url": "a.png"})
	for name, c := range map[string]struct {
		emails, wantEmail string
		verified          bool
	}{
		"primary verified":   {`[{"email":"old@x","verified":true},{"email":"main@x","primary":true,"verified":true}]`, "main@x", true},
		"only unverified":    {`[{"email":"main@x","primary":true,"verified":false}]`, "", false},
		"verified secondary": {`[{"email":"main@x","primary":true},{"email":"alt@x","verified":true}]`, "alt@x", true},
	} {
		s := github.New(p.ClientID, p.ClientSecret, "https://app/cb",
			github.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL(), emailsServer(t, c.emails)))
		id, err := s.Callback(context.Background(), map[string]string{"code": p.Code})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id.ProviderUserID != "583231" || id.Name != "octocat" || id.Email != c.wantEmail || id.EmailVerified != c.verified || id.Provider != "github" {
			t.Errorf("%s: %+v", name, id)
		}
	}
	bad := github.New(p.ClientID, p.ClientSecret, "https://app/cb", github.WithEndpoints(p.AuthURL(), p.TokenURL(), p.UserInfoURL(), emailsServer(t, "nope")))
	if _, err := bad.Callback(context.Background(), map[string]string{"code": p.Code}); err == nil {
		t.Fatal("broken /user/emails ignored")
	}
}

func TestOptions(t *testing.T) {
	s := github.New("id", "sec", "https://app/cb", github.WithScopes("read:user"), github.WithHTTPClient(http.DefaultClient), github.WithPKCE([]byte("k")))
	c := s.Config()
	if len(c.Scopes) != 1 || c.HTTPClient != http.DefaultClient || !c.PKCE || c.AuthURL != github.AuthURL {
		t.Fatalf("%+v", c)
	}
	id, _ := github.MapProfile(map[string]any{"id": json.Number("1"), "login": "x", "name": "X Y"})
	if id.Name != "X Y" || id.ProviderUserID != "1" {
		t.Fatalf("MapProfile: %+v", id)
	}
}
