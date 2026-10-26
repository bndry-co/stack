package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceTokenSnapshot(t *testing.T) {
	guestOrSkip(t)
	var jwt string
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/authorise" {
			t.Errorf("unexpected auth request: %s %s", r.Method, r.URL.Path)
		}
		exchanges.Add(1)
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	claims := testClaims(server.URL, "CS|test", "ZVATKW3VHMFG27DY")
	claims["role_set"] = "admin"
	jwt = unsignedJWT(t, claims)
	ctx := context.Background()
	profile, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(ctx, testCRN, NewAccessKey([]byte("CSAKtestKeyId.testKeySecret")), WithBaseURL(server.URL), WithAcceptedRoles("admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	for i := 0; i < 2; i++ {
		token, err := strategy.Token(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if token.Bearer() != jwt || token.WorkspaceCRN() != testCRN || token.WorkspaceID() != "ZVATKW3VHMFG27DY" || token.Issuer() != server.URL+"/" || token.ZeroKMSURL() != "https://ap-southeast-2.aws.viturhosted.net/" {
			t.Fatal("snapshot differs from the acquired token's claims")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(verb, token), jwt) {
				t.Fatal("formatted token leaked")
			}
		}
		encoded, err := json.Marshal(token)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("token did not serialize as an empty object")
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("auth requests = %d, want one cached acquisition", exchanges.Load())
	}
	rejected, err := profile.AccessKey(ctx, testCRN, NewAccessKey([]byte("CSAKtestKeyId.testKeySecret")), WithBaseURL(server.URL), WithAcceptedRoles("control"))
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()
	if token, err := rejected.Token(ctx); !errors.Is(err, ErrConfig) || token.Bearer() != "" {
		t.Fatalf("access-key strategy ignored role policy: %v", err)
	}
}

func TestAccessKeyOwnedWipedOnSuccessAndFailure(t *testing.T) {
	guestOrSkip(t)
	ctx := context.Background()
	profile, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	for _, crn := range []string{"invalid", testCRN} {
		t.Run(crn, func(t *testing.T) {
			material := []byte("CSAKtestKeyId.testKeySecret")
			key := NewAccessKey(material)
			for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%s", "%d"} {
				if fmt.Sprintf(verb, key) != "AccessKey(***)" || fmt.Sprintf(verb, *key) != "AccessKey(***)" {
					t.Fatal("key did not redact")
				}
			}
			strategy, err := profile.AccessKey(ctx, crn, key)
			if strategy != nil {
				defer strategy.Close()
			}
			if crn == "invalid" {
				if !errors.Is(err, ErrConfig) || strategy != nil {
					t.Fatalf("invalid CRN: strategy %v, error %v", strategy, err)
				}
			} else if err != nil || strategy == nil {
				t.Fatalf("valid CRN: strategy %v, error %v", strategy, err)
			}
			if !key.IsZero() || strings.Trim(string(material), "\x00") != "" {
				t.Fatal("AccessKey did not consume owned bytes")
			}
			key.Wipe()
		})
	}
}

func TestServiceTokenZeroAndEmptyEnvelope(t *testing.T) {
	var zero ServiceToken
	if zero.Bearer() != "" || zero.WorkspaceID() != "" || zero.WorkspaceCRN() != "" || zero.Issuer() != "" || zero.ZeroKMSURL() != "" {
		t.Fatal("zero token contains credentials or metadata")
	}
	if _, err := decodeServiceToken([]byte(`{}`)); !errors.Is(err, ErrInternal) {
		t.Fatal("empty guest envelope accepted")
	}
}

func TestAcceptedRolesOnAcquiredAndCachedTokens(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			OIDCToken string `json:"oidcToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, body.OIDCToken, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	ctx := context.Background()
	profile, err := OpenWithoutProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	provider := OIDCProviderFunc(func(ctx context.Context) (string, error) {
		return ctx.Value(callerKey{}).(string), nil
	})
	roles := []string{"Control", "ADMIN"}
	option := WithAcceptedRoles(roles...)
	roles[0] = "Member" // The option must own its policy, not borrow this slice.
	strategy, err := profile.OIDC(ctx, testCRN, provider, WithBaseURL(server.URL), option)
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	unrestricted, err := profile.OIDC(ctx, testCRN, provider, WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer unrestricted.Close()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		accept bool
	}{
		{"scalar", map[string]any{"role_set": "control"}, true},
		{"list", map[string]any{"role_set": []string{"member", "admin"}}, true},
		{"legacy role", map[string]any{"role": "ADMIN"}, true},
		{"legacy roles", map[string]any{"roles": []string{"Member", "Control"}}, true},
		{"wrong role", map[string]any{"role_set": "member"}, false},
		{"missing", nil, false},
		{"null", map[string]any{"role_set": nil}, false},
		{"empty", map[string]any{"role_set": []string{}}, false},
		{"unknown", map[string]any{"role_set": []string{"admin", "secret-invalid-role"}}, false},
		{"malformed", map[string]any{"role_set": 123}, false},
		{"null member", map[string]any{"role_set": []any{"admin", nil}}, false},
		{"ambiguous aliases", map[string]any{"role_set": "admin", "role": "member"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := testClaims(server.URL, "CS|"+tc.name, "ZVATKW3VHMFG27DY")
			for key, value := range tc.claims {
				claims[key] = value
			}
			jwt := unsignedJWT(t, claims)
			ctx := context.WithValue(ctx, callerKey{}, jwt)
			for i := 0; i < 2; i++ {
				token, err := strategy.Token(ctx)
				if tc.accept {
					if err != nil || token.Bearer() != jwt {
						t.Fatalf("Token: %v", err)
					}
				} else {
					if !errors.Is(err, ErrConfig) || token.Bearer() != "" {
						t.Fatalf("expected empty token and ErrConfig, got %v", err)
					}
					if strings.Contains(err.Error(), jwt) || strings.Contains(err.Error(), "secret-invalid-role") {
						t.Fatal("role error leaked token data")
					}
				}
			}
			if token, err := unrestricted.Token(ctx); err != nil || token.Bearer() != jwt {
				t.Fatalf("omitted policy inspected roles: %v", err)
			}
		})
	}
	for _, roles := range [][]string{nil, {}, {""}, {"admin", "other"}} {
		key := NewAccessKey([]byte("CSAKtestKeyId.testKeySecret"))
		strategy, err := profile.AccessKey(ctx, testCRN, key, WithAcceptedRoles(roles...))
		if strategy != nil {
			strategy.Close()
		}
		if !errors.Is(err, ErrConfig) || strategy != nil || !key.IsZero() {
			t.Fatalf("invalid role policy did not fail construction and consume key: %v", err)
		}
	}
}

func TestAcceptedRolesAfterDeviceRefresh(t *testing.T) {
	guestOrSkip(t)
	dir, workspaceDir := expiredDeviceProfile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := testClaims("http://"+r.Host, "CS|refreshed", wsA)
		claims["role_set"] = "member"
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`, unsignedJWT(t, claims))
	}))
	defer server.Close()
	ctx := context.Background()
	profile, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	workspace, err := profile.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := workspace.DeviceSession(ctx, WithBaseURL(server.URL), WithAcceptedRoles("admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	claims := testClaims(server.URL, "CS|before-refresh", wsA)
	claims["role_set"] = "admin"
	jwt := unsignedJWT(t, claims)
	path := filepath.Join(workspaceDir, "auth.json")
	for _, expiry := range []time.Time{time.Now().Add(time.Hour), time.Now().Add(-time.Hour)} {
		write(t, path, fmt.Sprintf(`{"access_token":%q,"refresh_token":"refresh-1","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws","client_id":"client-1"}`, jwt, expiry.Unix()))
		token, err := strategy.Token(ctx)
		if expiry.After(time.Now()) {
			if err != nil || token.Bearer() != jwt {
				t.Fatalf("fresh admin token: %v", err)
			}
		} else if !errors.Is(err, ErrConfig) || token.Bearer() != "" {
			t.Fatalf("refreshed member token must fail: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.RefreshToken != "refresh-2" {
		t.Fatal("role rejection lost the rotated refresh token")
	}
	if token, err := strategy.Token(ctx); !errors.Is(err, ErrConfig) || token.Bearer() != "" {
		t.Fatalf("saved member token must also fail: %v", err)
	}
}
