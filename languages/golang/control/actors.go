package control

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cipherstash/stack/languages/golang/auth"
)

// Actor is a machine identity. Its access-key identifier is a separate value.
type Actor struct {
	ID        string `json:"actorId"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt"`
}

// CreateActorOptions describes an app or agent and its access-key role.
// Empty Role and nil TokenExpiry select the service defaults.
type CreateActorOptions struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Role        string `json:"role,omitempty"`
	TokenExpiry *int64 `json:"tokenExpiry,omitempty"`
}

// CreatedActor includes the once-returned secret. TakeAccessKey or
// ExportAccessKey consumes it; copies of this result share that ownership.
type CreatedActor struct {
	Actor
	Role   string
	secret *creationSecret
}

// TakeAccessKey transfers the credential directly to an auth strategy's input.
func (a *CreatedActor) TakeAccessKey() (*auth.AccessKey, error) {
	b, err := a.ExportAccessKey()
	if err != nil {
		return nil, err
	}

	return auth.NewAccessKey(b), nil
}

// ExportAccessKey transfers encoded CSAK bytes for persistence. The caller
// owns and must wipe the returned bytes; subsequent extraction fails.
func (a *CreatedActor) ExportAccessKey() ([]byte, error) {
	if a == nil {
		return nil, ErrSecretConsumed
	}

	return a.secret.take()
}

// Wipe discards a creation secret that was not handed off or exported.
func (a *CreatedActor) Wipe() {
	if a != nil {
		a.secret.wipe()
	}
}
func (CreatedActor) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("CreatedActor(***)")) }

func (c *Client) CreateActor(ctx context.Context, opts CreateActorOptions) (*CreatedActor, error) {
	var out struct {
		Actor
		Role      string `json:"role"`
		AccessKey string `json:"accessKey"`
	}
	if err := c.request(ctx, "cts", http.MethodPost, "/api/actors", opts, &out); err != nil {
		return nil, err
	}

	if out.ID == "" || out.Name == "" || out.Kind == "" || out.Role == "" || out.AccessKey == "" {
		return nil, fmt.Errorf("%w: incomplete create-actor response", ErrResponse)
	}

	return &CreatedActor{Actor: out.Actor, Role: out.Role, secret: &creationSecret{bytes: []byte(out.AccessKey)}}, nil
}

type ListActorsOptions struct {
	Limit  int
	Cursor string
}

// ActorPage is one page, not an automatically accumulated workspace inventory.
type ActorPage struct {
	Items      []Actor `json:"items"`
	NextCursor string  `json:"nextCursor"`
}

func (c *Client) ListActors(ctx context.Context, opts ListActorsOptions) (ActorPage, error) {
	query := url.Values{}
	if opts.Limit != 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}

	if opts.Cursor != "" {
		query.Set("cursor", opts.Cursor)
	}

	path := "/api/actors"
	if len(query) != 0 {
		path += "?" + query.Encode()
	}

	var out ActorPage
	if err := c.request(ctx, "cts", http.MethodGet, path, nil, &out); err != nil {
		return ActorPage{}, err
	}

	if out.Items == nil {
		return ActorPage{}, fmt.Errorf("%w: missing actor list", ErrResponse)
	}

	for _, actor := range out.Items {
		if actor.ID == "" || actor.Name == "" {
			return ActorPage{}, fmt.Errorf("%w: missing actor identity", ErrResponse)
		}
	}

	return out, nil
}

// DeleteActor deletes the actor and its owned access key.
func (c *Client) DeleteActor(ctx context.Context, id string) error {
	return c.request(ctx, "cts", http.MethodDelete, "/api/actors/"+url.PathEscape(id), nil, nil)
}

// AccessKeyMetadata never contains the access key's secret material.
type AccessKeyMetadata struct {
	ID          string  `json:"keyId"`
	Name        string  `json:"keyName"`
	WorkspaceID string  `json:"workspaceId"`
	Role        string  `json:"role"`
	CreatedAt   string  `json:"createdAt"`
	LastUsedAt  *string `json:"lastUsedAt"`
}

func (c *Client) ListAccessKeys(ctx context.Context) ([]AccessKeyMetadata, error) {
	var out []AccessKeyMetadata
	if err := c.request(ctx, "cts", http.MethodGet, "/api/access-keys", nil, &out); err != nil {
		return nil, err
	}

	for _, key := range out {
		if key.ID == "" || key.Name == "" {
			return nil, fmt.Errorf("%w: missing access-key identity", ErrResponse)
		}
	}

	return out, nil
}
