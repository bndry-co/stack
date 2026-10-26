package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// EncryptionClient is a ZeroKMS client identity, not the SDK's administrative Client.
type EncryptionClient struct {
	ID          string
	Name        string
	Description string
	KeysetIDs   []string
}

// CreateClientOptions creates a client with an initial grant. KeysetID is a
// UUID; empty selects the workspace's default keyset.
type CreateClientOptions struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	KeysetID    string `json:"keyset_id,omitempty"`
}

// CreatedClient holds metadata and the once-returned encoded client key.
type CreatedClient struct {
	EncryptionClient
	KeysetID string
	secret   *creationSecret
}

// TakeClientKey transfers the encoded key to encryption credentials without
// exposing it. It consumes the same secret as ExportClientKey.
func (c *CreatedClient) TakeClientKey() (*auth.ClientKey, error) {
	b, err := c.ExportClientKey()
	if err != nil {
		return nil, err
	}
	return guest.NewClientKey(b), nil
}

// ExportClientKey transfers base64-encoded bytes for persistence. It does not
// decode or assume a fixed key length. The caller must wipe the bytes.
func (c *CreatedClient) ExportClientKey() ([]byte, error) {
	if c == nil {
		return nil, ErrSecretConsumed
	}
	return c.secret.take()
}

func (c *CreatedClient) Wipe() {
	if c != nil {
		c.secret.wipe()
	}
}
func (CreatedClient) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("CreatedClient(***)")) }

func (c *Client) CreateClient(ctx context.Context, opts CreateClientOptions) (*CreatedClient, error) {
	var out struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		Description *string `json:"description"`
		KeysetID    string  `json:"dataset_id"`
		ClientKey   string  `json:"client_key"`
	}
	if err := c.request(ctx, "zerokms", http.MethodPost, "/create-client", opts, &out); err != nil {
		return nil, err
	}
	if out.ID == "" || out.Name == "" || out.Description == nil || out.KeysetID == "" || out.ClientKey == "" {
		return nil, fmt.Errorf("%w: incomplete create-client response", ErrResponse)
	}
	return &CreatedClient{
		EncryptionClient: EncryptionClient{ID: out.ID, Name: out.Name, Description: *out.Description, KeysetIDs: []string{out.KeysetID}},
		KeysetID:         out.KeysetID, secret: &creationSecret{bytes: []byte(out.ClientKey)},
	}, nil
}

type ListClientsOptions struct{ KeysetID string }

func (c *Client) ListClients(ctx context.Context, opts ListClientsOptions) ([]EncryptionClient, error) {
	var input struct {
		KeysetID any `json:"keyset_id,omitempty"`
	}
	if opts.KeysetID != "" {
		input.KeysetID = struct {
			UUID string `json:"Uuid"`
		}{opts.KeysetID}
	}
	var out []struct {
		ID          string          `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		KeysetID    json.RawMessage `json:"keyset_id"`
	}
	if err := c.request(ctx, "zerokms", http.MethodPost, "/list-clients", input, &out); err != nil {
		return nil, err
	}
	clients := make([]EncryptionClient, 0, len(out))
	for _, item := range out {
		if item.ID == "" || len(item.KeysetID) == 0 || string(item.KeysetID) == "null" {
			return nil, fmt.Errorf("%w: missing client identity or keyset associations", ErrResponse)
		}
		var ids []string
		if err := json.Unmarshal(item.KeysetID, &ids); err != nil {
			var id string
			if err := json.Unmarshal(item.KeysetID, &id); err != nil {
				return nil, fmt.Errorf("%w: invalid client keyset associations", ErrResponse)
			}
			ids = []string{id}
		}
		for _, id := range ids {
			if id == "" {
				return nil, fmt.Errorf("%w: empty client keyset association", ErrResponse)
			}
		}
		clients = append(clients, EncryptionClient{ID: item.ID, Name: item.Name, Description: item.Description, KeysetIDs: ids})
	}
	return clients, nil
}

func (c *Client) DeleteClient(ctx context.Context, id string) error {
	return c.request(ctx, "zerokms", http.MethodPost, "/delete-client", struct {
		ClientID string `json:"client_id"`
	}{id}, nil)
}
