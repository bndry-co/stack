package control_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/control"
)

const workspace = "ZVATKW3VHMFG27DY"
const crn = "crn:ap-southeast-2.aws:" + workspace

func serviceJWT(t *testing.T, issuer, subject, zerokms string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"iss": issuer + "/", "sub": subject, "workspace": workspace,
		"services": map[string]string{"zerokms": zerokms + "/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))

	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "."
}

// Exercise the public client through real guest acquisition and TLS HTTP.
// Distinct tokens catch accidentally using CTS credentials for ZeroKMS.
func authenticatedClient(t *testing.T, handler http.HandlerFunc) *control.Client {
	t.Helper()
	tokens := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/authorise":
			var input struct {
				AccessKey string `json:"accessKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}

			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": tokens[input.AccessKey], "expiry": time.Now().Add(time.Hour).Unix()})
		default:
			credential := "CSAKkms.secret"
			if strings.HasPrefix(r.URL.Path, "/api/") {
				credential = "CSAKcts.secret"
				if r.Header.Get("x-cs-workspace-id") != workspace {
					t.Error("CTS workspace header missing")
				}
			}

			if r.Header.Get("Authorization") != "Bearer "+tokens[credential] {
				t.Error("wrong service credential")
			}

			handler(w, r)
		}
	}))
	t.Cleanup(server.Close)
	for _, credential := range []string{"CSAKcts.secret", "CSAKkms.secret"} {
		tokens[credential] = serviceJWT(t, server.URL, credential, server.URL)
	}

	ctx := context.Background()
	store, err := auth.OpenWithoutProfile(ctx, auth.WithRoundTripper(server.Client().Transport))
	if errors.Is(err, auth.ErrGuestNotBuilt) {
		t.Skip(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })
	strategies := make([]*auth.Strategy, 0, 2)
	for _, credential := range []string{"CSAKcts.secret", "CSAKkms.secret"} {
		strategy, err := store.AccessKey(ctx, crn, auth.NewAccessKey([]byte(credential)), auth.WithBaseURL(server.URL))
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = strategy.Close() })
		strategies = append(strategies, strategy)
	}

	if _, err := control.NewClient(ctx, "crn:ap-southeast-2.aws:2JTSJCX24VP2WCBC", control.WithCTSAuth(strategies[0])); !errors.Is(err, control.ErrAuthentication) {
		t.Fatalf("cross-workspace client accepted: %v", err)
	}

	if _, err := control.NewClient(ctx, "crn:us-east-1.aws:"+workspace, control.WithCTSAuth(strategies[0])); !errors.Is(err, control.ErrAuthentication) {
		t.Fatalf("cross-region client accepted: %v", err)
	}

	client, err := control.NewClient(ctx, crn, control.WithCTSAuth(strategies[0]), control.WithZeroKMSAuth(strategies[1]), control.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestControlFailuresDoNotLeakRetryOrRedirect(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(int(status.Load()))
		fmt.Fprint(w, `{"error":"CSAKsecret.must-not-leak"}`)
	})
	for _, tc := range []struct {
		status int
		target error
	}{
		{401, control.ErrAuthentication}, {403, control.ErrForbidden}, {404, control.ErrNotFound},
		{409, control.ErrConflict}, {500, control.ErrResponse}, {307, control.ErrResponse},
	} {
		status.Store(int32(tc.status))
		before := calls.Load()
		err := client.DeleteClient(context.Background(), "disposable")
		if !errors.Is(err, tc.target) || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("unsafe or incorrect error: %v", err)
		}

		var httpErr *control.HTTPError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != tc.status || httpErr.Service != "zerokms" {
			t.Fatal("missing HTTP status")
		}

		if calls.Load() != before+1 {
			t.Fatal("write retried or redirected")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := calls.Load()
	if err := client.DeleteClient(ctx, "disposable"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}

	if calls.Load() != before {
		t.Fatal("canceled request reached service")
	}
}
