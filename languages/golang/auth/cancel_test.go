package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// A profile serves every strategy, and through them every encrypt client,
// in a process: a request cancelled while its token is fetched must fail
// on its own and leave the profile open for the next.

// tokenServer answers the access-key exchange, holding each request until
// the client gives up while hold is set.
func tokenServer(t *testing.T, hold *atomic.Bool) *httptest.Server {
	t.Helper()
	var jwt string
	// A request the client never cancels is let go at the end, so a
	// failure reports itself rather than hanging the server's Close.
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hold.Load() {
			// The server notices a client that hung up only once the body
			// is read.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-done:
				t.Error("a held request was never cancelled")
			}
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(done) })
	jwt = testJWT(t, server.URL)
	return server
}

func TestATokenFetchCancelledFailsOnlyItself(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Token: %v, want the deadline", err)
	}
	if profile.root.closed || profile.root.inst.module.IsClosed() {
		t.Fatal("the profile was closed")
	}
	hold.Store(false)
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// A refresh runs on after its caller gives up, so the guest call under it
// can succeed after the caller's context ended. It still fails with the
// context's error; what the refresh brought is kept for the next call.
func TestARefreshThatSucceedsAfterItsContextEndsFailsWithIt(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	t.Cleanup(server.Close)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	out, err := strategy.store.callArgs(withRefresh(ctx), func(i *instance) api.Function { return i.authRefresh }, guest.BufArg([]byte(strategy.handle)))
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatalf("refresh: %q, %v, want no token and context.Canceled", out, err)
	}
	if token, err := strategy.Token(context.Background()); err != nil || token != "fresh" {
		t.Fatalf("the next Token: %q, %v, want the refreshed token", token, err)
	}
}

func TestATokenRequestWhoseContextEndsInTheQueueNeverReachesTheGuest(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	for name, lock := range map[string]interface {
		Acquire(context.Context) error
		Unlock()
	}{"the strategy's": &strategy.mu, "the profile's": &profile.root.mu} {
		t.Run(name, func(t *testing.T) {
			if err := lock.Acquire(context.Background()); err != nil {
				t.Fatal(err)
			}
			released := make(chan struct{})
			time.AfterFunc(200*time.Millisecond, func() { lock.Unlock(); close(released) })
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued Token: %v, want the deadline", err)
			}
			<-released
		})
	}
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", token, err)
	}
}

// The backstop: a call still running long after its caller gave up closes
// the profile, and says so.
func TestATokenFetchThatRunsOnAfterItsContextEndsClosesTheProfile(t *testing.T) {
	guestOrSkip(t)
	profile, err := Open(context.Background(), t.TempDir(), WithRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		// A RoundTripper that ignores the request's context.
		time.Sleep(300 * time.Millisecond)
		return nil, errors.New("too late")
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	strategy, err := profile.AccessKey(context.Background(), testCRN, "CSAKtestKeyId.testKeySecret", WithBaseURL("https://cts.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()
	profile.root.stuck = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := strategy.Token(ctx); err == nil || !strings.Contains(err.Error(), "the profile is closed") {
		t.Fatalf("stuck Token: %v, want the profile closed", err)
	}
	if _, err := strategy.Token(context.Background()); !errors.Is(err, ErrState) {
		t.Fatalf("a Token after the close: %v, want ErrState", err)
	}
}
