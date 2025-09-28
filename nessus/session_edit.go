package nessus

import (
	"io"
	"net/http"

	"github.com/bytedance/sonic"
)

type SessionEditRequest struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type SessionEditResponse struct {
	Lockout      bool   `json:"lockout,omitempty"`
	ContainerID  int    `json:"container_id,omitempty"`
	Groups       any    `json:"groups,omitempty"`
	Pro7WhatsNew any    `json:"pro7_whats_new,omitempty"`
	Lastlogin    int    `json:"lastlogin,omitempty"`
	Permissions  int    `json:"permissions,omitempty"`
	Type         string `json:"type,omitempty"`
	Name         string `json:"name,omitempty"`
	Email        string `json:"email,omitempty"`
	Username     string `json:"username,omitempty"`
	ID           int    `json:"id,omitempty"`
}

func (c *Client) SessionEdit(req *SessionEditRequest) (*SessionEditResponse, error) {
	reqBody, err := sonic.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.Put(c.getAPIURL("/session"), "application/json", reqBody)
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

	var data SessionEditResponse
	if err = sonic.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
