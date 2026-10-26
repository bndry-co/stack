package control_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
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

func TestActorClientContractsAndOneShotSecrets(t *testing.T) {
	client := authenticatedClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/actors":
			if r.Method == http.MethodPost {
				var input control.CreateActorOptions
				_ = json.NewDecoder(r.Body).Decode(&input)
				if input.Name != "worker" || input.Kind != "app" || input.Role != "control" {
					t.Error("actor request differs")
				}

				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, `{"actorId":"actor-1","name":"worker","kind":"app","createdAt":"today","role":"control","accessKey":"CSAKone.secret"}`)
			} else {
				if r.URL.Query().Get("cursor") != "a+/=" || r.URL.Query().Get("limit") != "7" {
					t.Error("pagination changed")
				}

				fmt.Fprint(w, `{"items":[{"actorId":"actor-1","name":"worker","kind":"app"}],"nextCursor":"second"}`)
			}
		case "/api/access-keys":
			fmt.Fprint(w, `[{"keyId":"key-1","keyName":"worker","workspaceId":"ZVATKW3VHMFG27DY","role":"control","createdAt":"today","lastUsedAt":null}]`)
		case "/create-client":
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if !reflect.DeepEqual(input, map[string]any{"name": "app", "description": "test", "keyset_id": "keyset-1"}) {
				t.Error("create client request differs")
			}

			fmt.Fprint(w, `{"id":"client-1","name":"app","description":"test","dataset_id":"keyset-1","client_key":"encoded-client-key"}`)
		case "/list-clients":
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if !reflect.DeepEqual(input, map[string]any{"keyset_id": map[string]any{"Uuid": "keyset-1"}}) {
				t.Error("client filter differs")
			}

			fmt.Fprint(w, `[{"id":"one","name":"single","keyset_id":"keyset-1"},{"id":"two","name":"multiple","keyset_id":["keyset-2","keyset-1"]}]`)
		case "/api/actors/actor-1":
			if r.Method != http.MethodDelete {
				t.Error("actor delete method")
			}

			fmt.Fprint(w, `{}`)
		case "/delete-client":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if r.Method != http.MethodPost || input["client_id"] != "client-1" {
				t.Error("client delete request")
			}

			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected operation %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	actor, err := client.CreateActor(ctx, control.CreateActorOptions{Name: "worker", Kind: "app", Role: "control"})
	if err != nil {
		t.Fatal(err)
	}

	if actor.ID != "actor-1" || actor.CreatedAt != "today" || actor.Role != "control" {
		t.Fatal("actor metadata lost")
	}

	copyActor := *actor
	key, err := actor.TakeAccessKey()
	if err != nil || key.IsZero() {
		t.Fatal("typed secret transfer failed")
	}

	key.Wipe()
	if _, err := copyActor.ExportAccessKey(); !errors.Is(err, control.ErrSecretConsumed) {
		t.Fatal("copied result exported secret twice")
	}

	page, err := client.ListActors(ctx, control.ListActorsOptions{Limit: 7, Cursor: "a+/="})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "actor-1" || page.NextCursor != "second" {
		t.Fatalf("actor page: %v", err)
	}

	keys, err := client.ListAccessKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID != "key-1" || keys[0].LastUsedAt != nil {
		t.Fatalf("key metadata: %v", err)
	}

	created, err := client.CreateClient(ctx, control.CreateClientOptions{Name: "app", Description: "test", KeysetID: "keyset-1"})
	if err != nil {
		t.Fatal(err)
	}

	if created.ID != "client-1" || created.KeysetID != "keyset-1" {
		t.Fatal("client metadata lost")
	}

	encoded, _ := json.Marshal(created)
	if strings.Contains(string(encoded), "encoded-client-key") || strings.Contains(fmt.Sprintf("%#v", created), "encoded-client-key") {
		t.Fatal("secret leaked")
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			copyClient := *created
			b, err := copyClient.ExportClientKey()
			if err == nil {
				wins.Add(1)
				if string(b) != "encoded-client-key" {
					t.Error("encoded secret changed")
				}

				clear(b)
			} else if !errors.Is(err, control.ErrSecretConsumed) {
				t.Error(err)
			}
		})
	}

	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("secret transfer was not exclusive")
	}

	listed, err := client.ListClients(ctx, control.ListClientsOptions{KeysetID: "keyset-1"})
	if err != nil || len(listed) != 2 || !reflect.DeepEqual(listed[0].KeysetIDs, []string{"keyset-1"}) || !reflect.DeepEqual(listed[1].KeysetIDs, []string{"keyset-2", "keyset-1"}) {
		t.Fatalf("client grants: %v", err)
	}

	if err := client.DeleteActor(ctx, actor.ID); err != nil {
		t.Fatal(err)
	}

	if err := client.DeleteClient(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
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
