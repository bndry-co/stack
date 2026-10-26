package control

import (
	"context"
	"fmt"
	"net/http"
)

// Keyset describes a ZeroKMS keyset without exposing key material.
type Keyset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsDisabled  bool   `json:"is_disabled"`
	IsDefault   bool   `json:"is_default"`
}

// CreateKeysetClientOptions requests a client alongside a new keyset.
// ClientType must be "device", the service's supported client type.
type CreateKeysetClientOptions struct {
	Name       string `json:"name"`
	ClientType string `json:"client_type"`
}

// CreateKeysetOptions describes a new keyset. A nil Client creates no client.
type CreateKeysetOptions struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Client      *CreateKeysetClientOptions `json:"client,omitempty"`
}

// CreatedKeyset includes an optional client with its once-returned encoded key.
// Extract or wipe that key through Client. Copies share the extraction right.
type CreatedKeyset struct {
	Keyset
	Client *CreatedClient
}

func (c *Client) CreateKeyset(ctx context.Context, opts CreateKeysetOptions) (*CreatedKeyset, error) {
	var out struct {
		Keyset
		Description *string `json:"description"`
		IsDisabled  *bool   `json:"is_disabled"`
		Client      *struct {
			ID        string `json:"id"`
			ClientKey string `json:"client_key"`
		} `json:"client"`
	}
	if err := c.request(ctx, "zerokms", http.MethodPost, "/create-keyset", opts, &out); err != nil {
		return nil, err
	}

	if out.ID == "" || out.Name == "" || out.Description == nil || out.IsDisabled == nil {
		return nil, fmt.Errorf("%w: incomplete create-keyset response", ErrResponse)
	}

	if (opts.Client != nil && out.Client == nil) || (out.Client != nil && (out.Client.ID == "" || out.Client.ClientKey == "")) {
		return nil, fmt.Errorf("%w: incomplete created keyset client", ErrResponse)
	}

	out.Keyset.Description = *out.Description
	out.Keyset.IsDisabled = *out.IsDisabled
	created := &CreatedKeyset{Keyset: out.Keyset}
	if out.Client != nil {
		// The response contains only the client's ID and key. Its name comes
		// from the request; no description is supplied by this endpoint.
		name := ""
		if opts.Client != nil {
			name = opts.Client.Name
		}

		created.Client = &CreatedClient{
			EncryptionClient: EncryptionClient{ID: out.Client.ID, Name: name, KeysetIDs: []string{out.ID}},
			KeysetID:         out.ID,
			secret:           &creationSecret{bytes: []byte(out.Client.ClientKey)},
		}
	}

	return created, nil
}

type ListKeysetsOptions struct {
	ShowDisabled bool `json:"show_disabled,omitempty"`
}

func (c *Client) ListKeysets(ctx context.Context, opts ListKeysetsOptions) ([]Keyset, error) {
	var out []struct {
		Keyset
		Description *string `json:"description"`
		IsDisabled  *bool   `json:"is_disabled"`
	}
	if err := c.request(ctx, "zerokms", http.MethodPost, "/list-keysets", opts, &out); err != nil {
		return nil, err
	}

	keysets := make([]Keyset, 0, len(out))
	for _, keyset := range out {
		if keyset.ID == "" || keyset.Name == "" || keyset.Description == nil || keyset.IsDisabled == nil {
			return nil, fmt.Errorf("%w: incomplete keyset", ErrResponse)
		}

		keyset.Keyset.Description = *keyset.Description
		keyset.Keyset.IsDisabled = *keyset.IsDisabled
		keysets = append(keysets, keyset.Keyset)
	}

	return keysets, nil
}

// ModifyKeysetOptions leaves nil fields unchanged. A non-nil pointer sends
// its value, including an empty string, for the service to validate.
type ModifyKeysetOptions struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// ModifyKeyset changes metadata for the keyset identified by its UUID.
func (c *Client) ModifyKeyset(ctx context.Context, id string, opts ModifyKeysetOptions) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/modify-keyset", struct {
		KeysetID string `json:"keyset_id"`
		ModifyKeysetOptions
	}{id, opts}, nil)
}

// EnableKeyset enables the keyset identified by its UUID.
func (c *Client) EnableKeyset(ctx context.Context, id string) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/enable-keyset", struct {
		KeysetID string `json:"keyset_id"`
	}{id}, nil)
}

// DisableKeyset disables the keyset identified by its UUID; it does not delete it.
func (c *Client) DisableKeyset(ctx context.Context, id string) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/disable-keyset", struct {
		KeysetID string `json:"keyset_id"`
	}{id}, nil)
}

// GrantKeyset grants a client access to a keyset. Both IDs are UUID strings.
func (c *Client) GrantKeyset(ctx context.Context, keysetID, clientID string) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/grant-keyset", struct {
		KeysetID string `json:"keyset_id"`
		ClientID string `json:"client_id"`
	}{keysetID, clientID}, nil)
}

// RevokeKeyset revokes a client's access to a keyset. Both IDs are UUID strings.
func (c *Client) RevokeKeyset(ctx context.Context, keysetID, clientID string) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/revoke-keyset", struct {
		KeysetID string `json:"keyset_id"`
		ClientID string `json:"client_id"`
	}{keysetID, clientID}, nil)
}
