package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// StrategyOption configures an auth strategy.
type StrategyOption func(*strategyOptions)

type strategyOptions struct {
	baseURL       string
	cacheCapacity *uint32
	acceptedRoles []string
}

// WithAcceptedRoles requires each token, including cached and refreshed tokens,
// to contain at least one of the given roles.
// Roles are admin, control and member (case-insensitive). An empty list or an
// unknown role is ErrConfig. Without this option, roles are not inspected.
func WithAcceptedRoles(roles ...string) StrategyOption {
	owned := append([]string{}, roles...)
	return func(o *strategyOptions) { o.acceptedRoles = slices.Clone(owned) }
}

// WithBaseURL overrides CTS service discovery for one strategy.
func WithBaseURL(url string) StrategyOption {
	return func(o *strategyOptions) { o.baseURL = url }
}

// WithCacheCapacity sets how many distinct IdP JWTs an OIDC strategy keeps
// a CTS token for (1024 unless set). When the cache is full the least
// recently used JWT's token is dropped and that user is exchanged again on
// their next call, so size it to the users one strategy serves within a CTS
// token's lifetime (about 15 minutes); each entry holds that user's JWT and
// CTS token. Zero caches nothing. Only [ProfileStore.OIDC] reads it.
func WithCacheCapacity(n uint32) StrategyOption {
	return func(o *strategyOptions) { o.cacheCapacity = &n }
}

func strategyConfig(opts []StrategyOption) (strategyOptions, error) {
	var o strategyOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.acceptedRoles != nil {
		if len(o.acceptedRoles) == 0 {
			return o, fmt.Errorf("%w: accepted roles must not be empty", ErrConfig)
		}
		for i, role := range o.acceptedRoles {
			role = strings.ToLower(role)
			if role != "admin" && role != "control" && role != "member" {
				return o, fmt.Errorf("%w: unknown accepted role", ErrConfig)
			}
			o.acceptedRoles[i] = role
		}
	}
	if o.baseURL == "" {
		o.baseURL = os.Getenv("CS_CTS_HOST")
	}
	return o, nil
}

// Strategy is a Rust stack-auth strategy retained inside the credential
// guest: the source of the bearer token encrypt.NewCredentials takes.
// Close drops its cached credential; closing the parent profile closes all
// its strategies. It is the caller's to close: an encrypt client that
// was given it asks it for tokens but never closes it, so it must stay open
// until the client is closed.
type Strategy struct {
	store         *ProfileStore
	handle        string
	providerID    uint32
	device        bool
	acceptedRoles []string
	mu            guest.Lock
	closed        bool
}

func (s *ProfileStore) newStrategy(ctx context.Context, config any, device bool, acceptedRoles []string) (*Strategy, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("auth: encode strategy: %w", err)
	}
	defer guest.Wipe(data)
	out, err := s.callArgs(ctx, func(i *instance) api.Function { return i.authNew }, guest.BufArg(data))
	if err != nil {
		return nil, err
	}
	if _, err := strconv.ParseUint(string(out), 10, 32); err != nil {
		return nil, fmt.Errorf("%w: invalid auth handle", ErrInternal)
	}
	return &Strategy{store: s, handle: string(out), device: device, acceptedRoles: acceptedRoles}, nil
}

// AccessKey consumes key, including on failure. The key stays in the guest
// after construction; it is not sent on each Token call.
func (s *ProfileStore) AccessKey(ctx context.Context, crn string, key *AccessKey, opts ...StrategyOption) (*Strategy, error) {
	defer key.Wipe()
	if crn == "" || key.IsZero() {
		return nil, ErrConfig
	}
	o, err := strategyConfig(opts)
	if err != nil {
		return nil, err
	}
	encoded := encodeAccessKey(guest.AccessKeyBytes(key))
	defer guest.Wipe(encoded)
	return s.newStrategy(ctx, struct {
		Kind    string          `json:"kind"`
		CRN     string          `json:"crn"`
		Key     json.RawMessage `json:"access_key"`
		BaseURL string          `json:"base_url,omitempty"`
	}{"access_key", crn, encoded, o.baseURL}, false, o.acceptedRoles)
}

// OIDC constructs stack-auth's federation strategy. provider is called on
// every Token call for the IdP JWT of the user that call is for; the
// strategy keeps one CTS token per distinct JWT and mints a new one only
// for a JWT that has no unexpired token. [WithCacheCapacity] sets how many
// JWTs that cache holds.
func (s *ProfileStore) OIDC(ctx context.Context, crn string, provider OIDCProvider, opts ...StrategyOption) (*Strategy, error) {
	if crn == "" || provider == nil {
		return nil, ErrConfig
	}
	o, err := strategyConfig(opts)
	if err != nil {
		return nil, err
	}
	id := s.root.inst.transport.register(provider)
	config := struct {
		Kind          string  `json:"kind"`
		CRN           string  `json:"crn"`
		Provider      uint32  `json:"provider"`
		BaseURL       string  `json:"base_url,omitempty"`
		CacheCapacity *uint32 `json:"cache_capacity,omitempty"`
	}{"oidc", crn, id, o.baseURL, o.cacheCapacity}
	strategy, err := s.newStrategy(ctx, config, false, o.acceptedRoles)
	if err != nil {
		s.root.inst.transport.unregister(id)
		return nil, err
	}
	strategy.providerID = id
	return strategy, nil
}

// DeviceSession uses this workspace store's auth.json. Fresh tokens are read
// without a lock. A refresh takes the same cross-process lock as the Rust
// CLI, then the guest re-reads and saves before the lock is released.
func (s *ProfileStore) DeviceSession(ctx context.Context, opts ...StrategyOption) (*Strategy, error) {
	if s.dir == guestRoot {
		return nil, ErrConfig
	}
	o, err := strategyConfig(opts)
	if err != nil {
		return nil, err
	}
	return s.newStrategy(ctx, struct {
		Kind    string `json:"kind"`
		Dir     string `json:"workspace_dir"`
		BaseURL string `json:"base_url,omitempty"`
	}{"device_session", s.dir, o.baseURL}, true, o.acceptedRoles)
}

// Auto follows stack-auth's detection order against the Go host's
// environment: access key first, then the current workspace's device token.
func (s *ProfileStore) Auto(ctx context.Context, opts ...StrategyOption) (*Strategy, error) {
	crn, crnSet := os.LookupEnv("CS_WORKSPACE_CRN")
	if crnSet {
		_, err := s.callArgs(ctx, func(i *instance) api.Function { return i.authValidateCRN }, guest.BufArg([]byte(crn)))
		if err != nil {
			return nil, err
		}
	}
	if key, keySet := os.LookupEnv("CS_CLIENT_ACCESS_KEY"); keySet {
		if !crnSet {
			return nil, ErrConfig
		}
		return s.AccessKey(ctx, crn, NewAccessKey([]byte(key)), opts...)
	}
	workspace, err := s.CurrentWorkspaceStore(ctx)
	if err != nil {
		if errors.Is(err, ErrNoCurrentWorkspace) || errors.Is(err, ErrNoProfile) {
			return nil, ErrNotAuthenticated
		}
		return nil, err
	}
	hasToken, err := workspace.hasToken(ctx)
	if err != nil {
		return nil, err
	}
	if !hasToken {
		return nil, ErrNotAuthenticated
	}
	return workspace.DeviceSession(ctx, opts...)
}

func (s *ProfileStore) hasToken(ctx context.Context) (bool, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.hasToken })
	if err != nil {
		return false, err
	}
	if len(out) != 1 || out[0] > 1 {
		return false, fmt.Errorf("%w: invalid has-token response", ErrInternal)
	}
	return out[0] == 1, nil
}

// Token gets the current CTS bearer credential. Device sessions read a fresh
// token without a file lock; only a refresh call takes the cross-process lock.
func (s *Strategy) Token(ctx context.Context) (ServiceToken, error) {
	// A request queued behind another's refresh leaves when its context
	// ends, as at the profile's own lock.
	if err := s.mu.Acquire(ctx); err != nil {
		return ServiceToken{}, err
	}
	if s.closed {
		s.mu.Unlock()
		return ServiceToken{}, ErrState
	}
	// The work runs on its own goroutine, which holds the lock until it is
	// done, so a caller that gives up returns at once. A device session's
	// refresh already sent finishes there, and the guest keeps what the
	// service sends (see refreshGrace): a rotated refresh token is never
	// lost. The token it brings is dropped; the next Token reads it. Any
	// other request ends with the caller.
	type result struct {
		token ServiceToken
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer s.mu.Unlock()
		ctx, status := withAuthHTTPStatus(ctx)
		token, err := s.token(ctx)
		if err == nil && s.acceptedRoles != nil {
			err = s.checkRoles(token.bearer)
			if err != nil {
				token = ServiceToken{}
			}
		}
		done <- result{token, status.wrap(err)}
	}()
	select {
	case r := <-done:
		return r.token, r.err
	case <-ctx.Done():
		// A call that finished as the context ended still answers.
		select {
		case r := <-done:
			return r.token, r.err
		default:
			return ServiceToken{}, ctx.Err()
		}
	}
}

// checkRoles reads only the role claims. It does not verify the JWT or duplicate
// the guest's workspace, endpoint, expiry or refresh handling.
func (s *Strategy) checkRoles(bearer string) error {
	invalid := fmt.Errorf("%w: invalid token role claims", ErrConfig)
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return invalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalid
	}
	defer guest.Wipe(payload)
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return invalid
	}
	var raw json.RawMessage
	for _, name := range []string{"role_set", "role", "roles"} {
		if value, ok := claims[name]; ok {
			if raw != nil {
				return invalid
			}
			raw = value
		}
	}
	var roles []string
	if raw != nil {
		if err := json.Unmarshal(raw, &roles); err != nil {
			var role string
			if err := json.Unmarshal(raw, &role); err != nil {
				return invalid
			}
			roles = []string{role}
		}
	}
	matched := false
	for _, role := range roles {
		// Match CTS's canonical spellings and its legacy aliases.
		switch role {
		case "admin", "Admin", "ADMIN", "control", "Control", "CONTROL", "member", "Member", "MEMBER":
			matched = matched || slices.Contains(s.acceptedRoles, strings.ToLower(role))
		default:
			return invalid
		}
	}
	if !matched {
		return fmt.Errorf("%w: token has no accepted role", ErrConfig)
	}
	return nil
}

// token is Token under the strategy's lock: a read, then a locked refresh
// for a device session that needs one.
func (s *Strategy) token(ctx context.Context) (ServiceToken, error) {
	call := func(ctx context.Context, export func(*instance) api.Function) (ServiceToken, error) {
		out, err := s.store.callArgs(ctx, export, guest.BufArg([]byte(s.handle)))
		if err != nil {
			return ServiceToken{}, err
		}
		defer guest.Wipe(out)
		// A caller that has left gets no copy: a string cannot be wiped,
		// and the next Token reads the guest's.
		if err := ctx.Err(); err != nil {
			return ServiceToken{}, err
		}
		return decodeServiceToken(out)
	}
	token, err := call(ctx, func(i *instance) api.Function { return i.authToken })
	if !s.device || !errors.Is(err, guest.ErrAuthRefreshRequired) {
		return token, err
	}
	path, err := s.store.LockPath(ctx, "auth.json")
	if err != nil {
		return ServiceToken{}, err
	}
	err = withRefreshLock(ctx, path, func() error {
		var err error
		// The one request that rotates a credential: it runs on after its
		// caller leaves (see refreshGrace).
		token, err = call(withRefresh(ctx), func(i *instance) api.Function { return i.authRefresh })
		return err
	})
	return token, err
}

// MemoryLockError is why the memory the strategy lives in is not locked in
// RAM: its ProfileStore's guest, where its token, its access key or refresh
// token, and any client key read through the same store are held. It is
// [ProfileStore.MemoryLockError] of that store, asked now rather than when
// the strategy was made: under best-effort locking the guest can commit
// unlocked memory later, on a growth for a token exchange or a refresh.
// Nil while the memory is locked. It can be asked after Close.
func (s *Strategy) MemoryLockError() error { return s.store.MemoryLockError() }

// Close drops the strategy's cached token and unregisters its provider.
// It waits for a call in flight, including a device session's refresh that
// a cancelled Token left running: that refresh finishes, for up to 10
// seconds, so the rotated refresh token it brings is saved rather than lost.
func (s *Strategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.providerID != 0 {
		s.store.root.inst.transport.unregister(s.providerID)
	}
	_, err := s.store.callArgs(context.Background(), func(i *instance) api.Function { return i.authFree }, guest.BufArg([]byte(s.handle)))
	if errors.Is(err, ErrState) {
		return nil
	}
	return err
}
