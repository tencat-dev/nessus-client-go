package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionGetResponse struct {
	ID          int    `json:"id,omitempty"`
	Username    string `json:"username,omitempty"`
	Email       string `json:"email,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Permissions int    `json:"permissions,omitempty"`
	Lastlogin   int    `json:"lastlogin,omitempty"`
	Lockout     bool   `json:"lockout,omitempty"`
	ContainerID int    `json:"container_id,omitempty"`
	Groups      []any  `json:"groups,omitempty"`
}

func (c *Client) SessionGet() (*SessionGetResponse, error) {
	resp, err := c.Get(c.getAPIURL("/session"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrorResponse(body)
	}

	var data SessionGetResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
