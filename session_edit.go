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
	Lockout      bool   `json:"lockout"`
	ContainerID  int    `json:"container_id"`
	Groups       any    `json:"groups"`
	Pro7WhatsNew any    `json:"pro7_whats_new"`
	Lastlogin    int    `json:"lastlogin"`
	Permissions  int    `json:"permissions"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Username     string `json:"username"`
	ID           int    `json:"id"`
}

func (c *Client) SessionEdit(name string, email string) (*SessionEditResponse, error) {
	reqBody, err := sonic.Marshal(&SessionEditRequest{
		Name:  name,
		Email: email,
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.Put(c.apiURL+"/session", "application/json", reqBody)
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
