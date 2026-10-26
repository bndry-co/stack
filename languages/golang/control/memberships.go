package control

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Membership is a user's role in a workspace, as returned by listing memberships.
type Membership struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Role        string `json:"role"`
	Subject     string `json:"sub"`
}

// CreateMembershipOptions adds a user to the client's workspace.
// Empty Role selects the service default; supported roles are admin, control and member.
type CreateMembershipOptions struct {
	UserID string `json:"userId"`
	Role   string `json:"role,omitempty"`
}

// CreatedMembership contains the creation response. The service does not return
// a role here; use ListMemberships to read the assigned role.
type CreatedMembership struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspaceId"`
	Subject     string `json:"sub"`
}

func (c *Client) CreateMembership(ctx context.Context, opts CreateMembershipOptions) (CreatedMembership, error) {
	var out CreatedMembership
	if err := c.request(ctx, "cts", http.MethodPost, "/api/memberships", opts, &out); err != nil {
		return CreatedMembership{}, err
	}
	if out.ID == "" || out.WorkspaceID == "" || out.Subject == "" {
		return CreatedMembership{}, fmt.Errorf("%w: incomplete create-membership response", ErrResponse)
	}
	return out, nil
}

func (c *Client) ListMemberships(ctx context.Context) ([]Membership, error) {
	var out []Membership
	if err := c.request(ctx, "cts", http.MethodGet, "/api/memberships", nil, &out); err != nil {
		return nil, err
	}
	for _, member := range out {
		if member.ID == "" || member.WorkspaceID == "" || member.Subject == "" {
			return nil, fmt.Errorf("%w: missing membership identity", ErrResponse)
		}
	}
	return out, nil
}

func (c *Client) DeleteMembership(ctx context.Context, id string) error {
	return c.request(ctx, "cts", http.MethodDelete, "/api/memberships/"+url.PathEscape(id), nil, nil)
}
